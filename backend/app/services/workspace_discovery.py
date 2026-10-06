"""
Discover the Sentinel workspace fleet with Azure Resource Graph.

Resource Graph queried at tenant scope (no subscription list) returns resources
from every subscription the caller can read, *including Azure Lighthouse
delegated subscriptions* — so an analyst signed in with ``az login`` can generate
the fleet file themselves with the same identity the MCP server runs as.

It is the programmatic twin of the portal's **Open query** button on the
Microsoft Sentinel / Log Analytics workspace list (Azure Resource Graph Explorer).

Only pure-Python assembly lives here (easy to test); the HTTP call is isolated in
``run_arg_query`` so tests can replace it.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import httpx

from app.config import settings
from app.services.workspace_registry import slugify

logger = logging.getLogger(__name__)

ARG_URL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"

# All Log Analytics workspaces the caller can read, with the customer tenant id.
QUERY_WORKSPACES = (
    "resources "
    "| where type =~ 'microsoft.operationalinsights/workspaces' "
    "| project id, name, resourceGroup, subscriptionId, tenantId, location, "
    "customerId = tostring(properties.customerId)"
)
# Workspaces onboarded to Microsoft Sentinel carry a SecurityInsights(<ws>) solution.
QUERY_SENTINEL_SOLUTIONS = (
    "resources "
    "| where type =~ 'microsoft.operationsmanagement/solutions' and name startswith 'SecurityInsights(' "
    "| project workspaceResourceId = tolower(tostring(properties.workspaceResourceId))"
)
QUERY_SUBSCRIPTIONS = (
    "resourcecontainers "
    "| where type =~ 'microsoft.resources/subscriptions' "
    "| project subscriptionId, subscriptionName = name, tenantId"
)

# Fields an operator may have hand-edited in an existing fleet file; preserved on merge.
PRESERVED_FIELDS = ("id", "display_name", "is_managing_tenant")


def run_arg_query(query: str, token: str, timeout: float = 30.0) -> list[dict[str, Any]]:
    """Run a Resource Graph query at tenant scope and return all rows (paginated)."""
    rows: list[dict[str, Any]] = []
    skip_token: Optional[str] = None
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    with httpx.Client(timeout=timeout) as client:
        while True:
            options: dict[str, Any] = {"resultFormat": "objectArray", "$top": 1000}
            if skip_token:
                options["$skipToken"] = skip_token
            resp = client.post(ARG_URL, headers=headers, json={"query": query, "options": options})
            resp.raise_for_status()
            body = resp.json()
            rows.extend(body.get("data") or [])
            skip_token = body.get("$skipToken")
            if not skip_token:
                return rows


def _key(subscription_id: str, resource_group: str, workspace_name: str) -> str:
    return f"{subscription_id}/{resource_group}/{workspace_name}".lower()


def build_entries(
    workspaces: list[dict[str, Any]],
    subscriptions: list[dict[str, Any]],
    sentinel_workspace_ids: set[str],
    include_all: bool = False,
) -> list[dict[str, Any]]:
    """Turn Resource Graph rows into fleet-file entries (sorted by display name)."""
    sub_names = {s.get("subscriptionId"): s.get("subscriptionName") for s in subscriptions}
    per_sub: dict[str, int] = {}
    for w in workspaces:
        per_sub[w.get("subscriptionId")] = per_sub.get(w.get("subscriptionId"), 0) + 1
    home_tenant = (settings.AZURE_TENANT_ID or "").lower()

    entries: list[dict[str, Any]] = []
    for w in workspaces:
        enabled = str(w.get("id", "")).lower() in sentinel_workspace_ids
        if not enabled and not include_all:
            continue
        sub_id = w.get("subscriptionId")
        sub_name = sub_names.get(sub_id) or sub_id
        # One workspace in the subscription -> the customer name alone reads best.
        display = sub_name if per_sub.get(sub_id, 0) == 1 else f"{sub_name} ({w.get('name')})"
        tenant_id = w.get("tenantId")
        entries.append({
            "id": slugify(w.get("name", "")),
            "display_name": display,
            "tenant_id": tenant_id,
            "subscription_id": sub_id,
            "resource_group": w.get("resourceGroup"),
            "workspace_name": w.get("name"),
            "workspace_guid": w.get("customerId") or None,
            "location": w.get("location"),
            "sentinel_enabled": enabled,
            "is_managing_tenant": bool(tenant_id and home_tenant and str(tenant_id).lower() == home_tenant),
        })
    entries.sort(key=lambda e: (e["display_name"] or "").lower())
    return entries


def merge_fleet(existing: list[dict[str, Any]], discovered: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Merge discovered entries into an existing fleet.

    Existing entries keep their order and any hand-edited fields (ids, display
    names, managing-tenant flag) while their
    coordinates/GUID/tenant are refreshed. Entries no longer found in Resource
    Graph are kept (the analyst may have lost access rather than the workspace
    being gone) and reported. New workspaces are appended.
    """
    by_key = {_key(d["subscription_id"], d["resource_group"], d["workspace_name"]): d for d in discovered}
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    summary = {"added": [], "updated": [], "missing": []}

    for old in existing:
        k = _key(old.get("subscription_id", ""), old.get("resource_group", ""), old.get("workspace_name", ""))
        new = by_key.get(k)
        if new is None:
            merged.append(old)
            summary["missing"].append(old.get("id") or old.get("workspace_name"))
            continue
        combined = dict(new)
        for f in PRESERVED_FIELDS:
            if old.get(f) not in (None, ""):
                combined[f] = old[f]
        merged.append(combined)
        seen.add(k)
        summary["updated"].append(combined["id"])

    for d in discovered:
        k = _key(d["subscription_id"], d["resource_group"], d["workspace_name"])
        if k not in seen:
            merged.append(d)
            summary["added"].append(d["id"])
    return merged, summary


def load_existing(path: str) -> list[dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return []
    if isinstance(raw, dict):
        raw = raw.get("workspaces", [])
    return [e for e in raw if isinstance(e, dict)]


def discover(
    token: str,
    include_all: bool = False,
    query_runner: Optional[Callable[[str, str], list[dict[str, Any]]]] = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Query Resource Graph and return (entries, stats).

    ``query_runner`` defaults to ``run_arg_query`` resolved at call time (not as a
    bound default), so it can be replaced in tests without touching the network.
    """
    query_runner = query_runner or run_arg_query
    workspaces = query_runner(QUERY_WORKSPACES, token)
    subscriptions = query_runner(QUERY_SUBSCRIPTIONS, token)
    sentinel_ids = {str(r.get("workspaceResourceId", "")).lower() for r in query_runner(QUERY_SENTINEL_SOLUTIONS, token)}
    entries = build_entries(workspaces, subscriptions, sentinel_ids, include_all=include_all)
    stats = {
        "log_analytics_workspaces": len(workspaces),
        "sentinel_workspaces": sum(1 for w in workspaces if str(w.get("id", "")).lower() in sentinel_ids),
        "subscriptions": len({w.get("subscriptionId") for w in workspaces}),
        "tenants": len({w.get("tenantId") for w in workspaces}),
        "included": len(entries),
    }
    return entries, stats


def render_fleet_file(entries: list[dict[str, Any]]) -> str:
    doc = {
        "generated_by": "python -m app.mcp_server --discover-workspaces (Azure Resource Graph)",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "workspaces": entries,
    }
    return json.dumps(doc, indent=2) + "\n"
