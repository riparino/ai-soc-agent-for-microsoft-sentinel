"""
Workspace / tenant registry for the AI SOC Agent.

The backend manages a *fleet* of Microsoft Sentinel workspaces that live in
delegated customer tenants (an Azure Lighthouse deployment) from one running
instance. This module is the single source of truth for that fleet:

  * It loads up to ~hundreds of workspace coordinates from config or a JSON store.
  * It assigns every workspace a stable ``id`` used to namespace incident IDs so a
    request can be routed back to the workspace the incident belongs to.
  * It records how Microsoft Graph must be handled per workspace, because Azure
    Lighthouse does **not** delegate Microsoft Graph (identity) access.

Workspace context is passed explicitly (as ``WorkspaceConfig`` objects) into the
Sentinel/KQL clients rather than mutated onto a global settings singleton.
"""

import json
import logging
import os
import re
import threading
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel

from app.config import settings

logger = logging.getLogger(__name__)

# Backend directory: relative WORKSPACES_CONFIG_PATH values resolve against it, so a
# fleet file next to .env is found even when an MCP client launches the server from
# an arbitrary working directory.
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def resolve_fleet_path(configured: Optional[str] = None, must_exist: bool = True) -> Optional[str]:
    """Resolve the fleet file path: absolute as-is; relative first against the
    current directory, then against the backend directory. Returns None when the
    path is unset (or, with must_exist, when no candidate exists)."""
    cfg = configured if configured is not None else settings.WORKSPACES_CONFIG_PATH
    if not cfg or not str(cfg).strip():
        return None
    cfg = str(cfg).strip()
    if os.path.isabs(cfg):
        candidates = [cfg]
    else:
        candidates = [os.path.abspath(cfg), os.path.join(BACKEND_DIR, cfg)]
    for cand in candidates:
        if os.path.exists(cand):
            return cand
    return None if must_exist else candidates[-1]


# Separator used to namespace incident IDs as "<workspace_id>::<raw_incident_id>".
# ':' is a valid URL path character (pchar), so refs survive REST/WebSocket paths.
WORKSPACE_REF_SEPARATOR = "::"


def slugify(value: str) -> str:
    """Produce a stable, URL-safe id fragment from a display/workspace name."""
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return s or "workspace"


class WorkspaceConfig(BaseModel):
    """Coordinates and policy for a single delegated Sentinel workspace."""

    id: str
    display_name: str
    tenant_id: Optional[str] = None
    subscription_id: Optional[str] = None
    resource_group: Optional[str] = None
    workspace_name: Optional[str] = None
    workspace_guid: Optional[str] = None  # Log Analytics customerId GUID

    # Optional per-customer Microsoft Graph app registration. Azure Lighthouse does
    # NOT cover Microsoft Graph, so reaching a customer tenant's directory requires
    # either an app registered + admin-consented in that customer tenant, or scoping
    # Graph features to the managing tenant. See graph_mode below.
    graph_tenant_id: Optional[str] = None
    graph_client_id: Optional[str] = None
    graph_client_secret: Optional[str] = None

    # True for the workspace that lives in the managing (home) tenant. The home
    # service principal's Graph token can see this tenant's directory directly.
    is_managing_tenant: bool = False

    def has_arm_coordinates(self) -> bool:
        return bool(self.subscription_id and self.resource_group and self.workspace_name)

    def has_delegated_graph_app(self) -> bool:
        return bool(self.graph_tenant_id and self.graph_client_id and self.graph_client_secret)

    @property
    def graph_mode(self) -> str:
        """
        How Microsoft Graph (identity) features behave for this workspace:

          * ``delegated-app``   - a per-customer app registration is configured, so
            we can read/act on this tenant's directory directly.
          * ``managing-tenant`` - this workspace is in the home tenant; the shared
            home SP Graph token sees it directly.
          * ``log-analytics-only`` - Lighthouse delegation covers ARM + Log
            Analytics but NOT Graph, so directory data can only be derived from the
            workspace's own SigninLogs/IdentityInfo telemetry and identity *write*
            remediation is unavailable from this instance.
        """
        if self.has_delegated_graph_app():
            return "delegated-app"
        if self.is_managing_tenant:
            return "managing-tenant"
        return "log-analytics-only"

    @property
    def graph_write_capable(self) -> bool:
        """Whether identity *write* actions (revoke sessions, disable account) can
        reach this workspace's tenant from this instance."""
        return self.graph_mode in ("delegated-app", "managing-tenant")

    def arm_base_url(self) -> str:
        """ARM SecurityInsights base URL for this workspace (Lighthouse-honored)."""
        return (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
        )

    def arm_workspace_url(self) -> str:
        """ARM URL of the workspace resource itself (used to resolve the GUID)."""
        return (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            f"?api-version=2022-10-01"
        )

    def public_dict(self) -> dict:
        """Secret-free representation safe to return from the API / show in the UI."""
        return {
            "id": self.id,
            "display_name": self.display_name,
            "tenant_id": self.tenant_id,
            "subscription_id": self.subscription_id,
            "resource_group": self.resource_group,
            "workspace_name": self.workspace_name,
            "workspace_guid": self.workspace_guid,
            "is_managing_tenant": self.is_managing_tenant,
            "graph_mode": self.graph_mode,
            "graph_write_capable": self.graph_write_capable,
        }


class WorkspaceRegistry:
    """Thread-safe, reloadable registry of the managed workspace fleet."""

    def __init__(self):
        self._lock = threading.RLock()
        self._workspaces: Dict[str, WorkspaceConfig] = {}
        self._order: List[str] = []
        self._default_id: Optional[str] = None
        self._source: str = "uninitialized"
        self.load()

    # ------------------------------------------------------------------ loading
    def load(self) -> None:
        with self._lock:
            workspaces, source = self._load_from_sources()
            # De-duplicate ids while preserving declared order.
            unique: Dict[str, WorkspaceConfig] = {}
            order: List[str] = []
            for w in workspaces:
                wid = w.id
                suffix = 2
                while wid in unique:
                    wid = f"{w.id}-{suffix}"
                    suffix += 1
                if wid != w.id:
                    w = w.model_copy(update={"id": wid})
                unique[wid] = w
                order.append(wid)
            self._workspaces = unique
            self._order = order
            self._default_id = order[0] if order else None
            self._source = source
            logger.info(
                "Workspace registry loaded %d workspace(s) from %s (default=%s)",
                len(order), source, self._default_id,
            )

    reload = load

    def _load_from_sources(self) -> Tuple[List[WorkspaceConfig], str]:
        # 1. Inline JSON array.
        if settings.WORKSPACES_JSON and settings.WORKSPACES_JSON.strip():
            try:
                raw = json.loads(settings.WORKSPACES_JSON)
                parsed = self._build_from_raw(raw)
                if parsed:
                    return parsed, "WORKSPACES_JSON"
            except Exception as e:
                logger.error("Failed to parse WORKSPACES_JSON: %s", e)

        # 2. JSON file path (relative paths resolve against cwd, then the backend dir).
        fleet_path = resolve_fleet_path()
        if fleet_path:
            try:
                with open(fleet_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                parsed = self._build_from_raw(raw)
                if parsed:
                    return parsed, f"file:{fleet_path}"
            except Exception as e:
                logger.error("Failed to load WORKSPACES_CONFIG_PATH (%s): %s", fleet_path, e)
        elif settings.WORKSPACES_CONFIG_PATH:
            logger.warning("WORKSPACES_CONFIG_PATH=%r does not exist; falling back.", settings.WORKSPACES_CONFIG_PATH)

        # 3. Legacy single-workspace AZURE_* configuration (managing tenant).
        if settings.AZURE_SUBSCRIPTION_ID and settings.AZURE_RESOURCE_GROUP_NAME and settings.AZURE_WORKSPACE_NAME:
            legacy = WorkspaceConfig(
                id=slugify(settings.AZURE_WORKSPACE_NAME),
                display_name=settings.AZURE_WORKSPACE_NAME,
                tenant_id=settings.AZURE_TENANT_ID,
                subscription_id=settings.AZURE_SUBSCRIPTION_ID,
                resource_group=settings.AZURE_RESOURCE_GROUP_NAME,
                workspace_name=settings.AZURE_WORKSPACE_NAME,
                workspace_guid=settings.AZURE_WORKSPACE_ID,
                is_managing_tenant=True,
            )
            return [legacy], "legacy-single-workspace"

        # 4. Demo seed - multiple workspaces so routing/aggregation is demonstrable
        #    even without any live Azure configuration.
        return self._demo_seed(), "demo-seed"

    def _build_from_raw(self, raw) -> List[WorkspaceConfig]:
        if isinstance(raw, dict):
            # Allow {"workspaces": [...]} wrapper.
            raw = raw.get("workspaces", [])
        if not isinstance(raw, list):
            return []
        home_tenant = (settings.AZURE_TENANT_ID or "").strip().lower()
        result: List[WorkspaceConfig] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            display = (
                entry.get("display_name")
                or entry.get("workspace_name")
                or entry.get("id")
                or "Workspace"
            )
            wid = entry.get("id") or slugify(display)
            tenant_id = entry.get("tenant_id")
            is_managing = bool(entry.get("is_managing_tenant"))
            if not is_managing and tenant_id and home_tenant and tenant_id.strip().lower() == home_tenant:
                is_managing = True
            result.append(
                WorkspaceConfig(
                    id=slugify(wid),
                    display_name=display,
                    tenant_id=tenant_id,
                    subscription_id=entry.get("subscription_id"),
                    resource_group=entry.get("resource_group") or entry.get("resource_group_name"),
                    workspace_name=entry.get("workspace_name"),
                    workspace_guid=entry.get("workspace_guid") or entry.get("workspace_id"),
                    graph_tenant_id=entry.get("graph_tenant_id"),
                    graph_client_id=entry.get("graph_client_id"),
                    graph_client_secret=entry.get("graph_client_secret"),
                    is_managing_tenant=is_managing,
                )
            )
        return result

    def _demo_seed(self) -> List[WorkspaceConfig]:
        return [
            WorkspaceConfig(
                id="contoso",
                display_name="Contoso Ltd (Managed)",
                tenant_id="11111111-1111-1111-1111-111111111111",
                subscription_id="demo-sub-contoso",
                resource_group="rg-sentinel-contoso",
                workspace_name="contoso-sentinel",
                workspace_guid="aaaaaaaa-1111-2222-3333-444444444444",
                is_managing_tenant=True,
            ),
            WorkspaceConfig(
                id="fabrikam",
                display_name="Fabrikam Inc (Managed / Lighthouse)",
                tenant_id="22222222-2222-2222-2222-222222222222",
                subscription_id="demo-sub-fabrikam",
                resource_group="rg-sentinel-fabrikam",
                workspace_name="fabrikam-sentinel",
                workspace_guid="bbbbbbbb-5555-6666-7777-888888888888",
                is_managing_tenant=False,
            ),
        ]

    # ------------------------------------------------------------------ queries
    def list_workspaces(self) -> List[WorkspaceConfig]:
        with self._lock:
            return [self._workspaces[wid] for wid in self._order]

    def get(self, workspace_id: Optional[str]) -> Optional[WorkspaceConfig]:
        if not workspace_id:
            return None
        with self._lock:
            return self._workspaces.get(slugify(workspace_id)) or self._workspaces.get(workspace_id)

    def default(self) -> Optional[WorkspaceConfig]:
        with self._lock:
            if self._default_id:
                return self._workspaces.get(self._default_id)
            return None

    def managing_workspace(self) -> Optional[WorkspaceConfig]:
        """The home-tenant workspace (for Graph features scoped to the managing tenant)."""
        with self._lock:
            for wid in self._order:
                w = self._workspaces[wid]
                if w.is_managing_tenant:
                    return w
        return self.default()

    def resolve_targets(self, workspace: Optional[str]) -> List[WorkspaceConfig]:
        """Resolve a selector into the list of workspaces to query.

        ``None``/``"all"`` -> the whole fleet. A comma-separated list or single id
        -> those workspaces (unknown ids ignored). Falls back to the default.
        """
        if workspace is None or str(workspace).strip().lower() in ("", "all", "*"):
            return self.list_workspaces()
        ids = [p.strip() for p in str(workspace).split(",") if p.strip()]
        resolved = [self.get(i) for i in ids]
        resolved = [w for w in resolved if w is not None]
        if resolved:
            return resolved
        default = self.default()
        return [default] if default else []

    # ------------------------------------------------------------------ ref helpers
    def make_ref(self, workspace_id: str, raw_incident_id: str) -> str:
        return f"{workspace_id}{WORKSPACE_REF_SEPARATOR}{raw_incident_id}"

    def parse_ref(self, incident_ref: str) -> Tuple[Optional[str], str]:
        """Split a namespaced incident ref into (workspace_id, raw_incident_id).

        A ref without the separator is returned as (None, ref) for backward
        compatibility with callers that still pass a bare incident id.
        """
        if incident_ref and WORKSPACE_REF_SEPARATOR in incident_ref:
            wid, raw = incident_ref.split(WORKSPACE_REF_SEPARATOR, 1)
            return wid, raw
        return None, incident_ref

    def resolve_ref(self, incident_ref: str) -> Tuple[WorkspaceConfig, str]:
        """Resolve a namespaced incident ref to its (WorkspaceConfig, raw_id).

        Falls back to the default workspace when the ref is not namespaced or the
        namespace is unknown.
        """
        wid, raw = self.parse_ref(incident_ref)
        workspace = self.get(wid) if wid else None
        if workspace is None:
            workspace = self.default()
        if workspace is None:
            # Should not happen; synthesize a placeholder so callers never crash.
            workspace = WorkspaceConfig(id=wid or "unknown", display_name=wid or "unknown")
        return workspace, raw


# Module-level singleton registry.
workspace_registry = WorkspaceRegistry()
