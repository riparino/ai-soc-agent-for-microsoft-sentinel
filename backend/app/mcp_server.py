"""
MCP server for the Microsoft Sentinel AI SOC Agent.

Exposes the agent's capabilities (fleet-wide incident listing, triage, KQL hunts,
threat intel, comments/status/assignment) as Model Context
Protocol tools so they can be used from Claude (Enterprise connectors, Claude
Desktop, Claude Code), GitHub Copilot (VS Code agent mode / coding agent), and
Microsoft Copilot Studio.

Two transports:

  * ``stdio``           - local, zero-network. Ideal for laptops and testing:
                          ``python -m app.mcp_server --transport stdio``
  * ``streamable-http`` - remote hosting (Copilot Studio, Claude Enterprise):
                          ``python -m app.mcp_server --transport streamable-http``

Authentication (HTTP transport only) is selected with ``MCP_AUTH_MODE``:
``none`` for local testing, or ``entra`` to require Microsoft Entra ID bearer
tokens issued for ``MCP_ENTRA_AUDIENCE`` (validated against the tenant's JWKS;
the server also publishes RFC 9728 protected-resource metadata so MCP clients
can discover the authorization server).

Workspace/tenant context travels inside the namespaced incident ref
(``<workspace_id>::<incident_guid>``) exactly as it does in the REST API, so every
tool routes to the correct delegated Sentinel workspace automatically.

Schema compatibility: tool parameters deliberately use plain, non-nullable types
with "empty means unset" defaults (``""``, ``0``, ``[]``, ``{}``) instead of
``Optional[...]``. Copilot Studio maps MCP schemas onto Power Platform connector
schemas and filters/truncates tools whose inputs use ``$ref``, ``type`` arrays or
nullable unions, so keeping schemas flat keeps every tool usable there.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from typing import Annotated, Any, Callable, Optional

import httpx
from pydantic import AnyHttpUrl, Field

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from app.config import settings
from app.services.workspace_registry import workspace_registry, WORKSPACE_REF_SEPARATOR

# Logging must go to stderr: on the stdio transport stdout is the protocol channel.
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel_mcp")

SERVER_NAME = "sentinel_soc_mcp"
SERVER_INSTRUCTIONS = (
    "Tools for triaging Microsoft Sentinel incidents across a fleet of delegated "
    "(Azure Lighthouse) workspaces. Incident IDs are namespaced refs of the form "
    f"'<workspace_id>{WORKSPACE_REF_SEPARATOR}<incident_guid>'; always obtain refs from "
    "sentinel_list_incidents or sentinel_get_incident rather than guessing them. "
    "Start with sentinel_list_workspaces to see the fleet. Use sentinel_extract_indicators "
    "to get an incident's IPs, hosts, accounts and hashes as flat lists for enrichment "
    "with other tools (threat intelligence, asset/cloud inventory), then record findings "
    "with sentinel_add_comment. sentinel_list_tables shows which Log Analytics tables a "
    "workspace ingests and sentinel_hunt_incident runs the catalog of entity-driven KQL "
    "hunts (Entra sign-in/audit/risk, Defender XDR Device*/Identity/Email/CloudApp, "
    "AzureActivity, AzureDiagnostics, SecurityEvent, Office, firewall, Syslog, alerts, TI) "
    "for an incident. Scope is Microsoft Sentinel only (incidents, comments, "
    "status, assignment, Log Analytics KQL): there are no Entra ID / Microsoft Graph or "
    "Defender XDR actions, because Azure Lighthouse does not delegate those. Optional "
    "parameters use empty values ('' / 0 / []) to mean 'not set'."
)

WORKSPACE_PUBLIC_FIELDS = (
    "id", "display_name", "tenant_id", "subscription_id", "resource_group",
    "workspace_name", "workspace_guid", "is_managing_tenant",
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
READ_ONLY_EXTERNAL = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)
WRITE_SAFE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
WRITE_DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)

INCIDENT_SUMMARY_FIELDS = (
    "id", "incidentNumber", "title", "severity", "status", "createdTimeUtc",
    "lastModifiedTimeUtc", "workspaceId", "workspaceName", "workspaceTenantId",
    "assignedTo", "tactics", "classification", "alertsCount", "labels",
)

REF_DESCRIPTION = f"Namespaced incident ref '<workspace_id>{WORKSPACE_REF_SEPARATOR}<incident_guid>' from sentinel_list_incidents."


# --------------------------------------------------------------------------- auth
class EntraTokenVerifier:
    """Validate Microsoft Entra ID bearer tokens against the tenant's JWKS.

    Accepts v2.0 (``login.microsoftonline.com/<tenant>/v2.0``) and v1.0
    (``sts.windows.net/<tenant>/``) issuers, checks the audience against the
    configured app ID (both bare and ``api://`` forms), and maps the ``scp`` /
    ``roles`` claims onto MCP scopes.
    """

    JWKS_TTL_SECONDS = 3600

    def __init__(self, tenant_id: str, audiences: list[str], required_scopes: Optional[list[str]] = None):
        self.tenant_id = tenant_id
        self.audiences = audiences
        self.required_scopes = required_scopes or []
        self.jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        self.issuers = {
            f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            f"https://sts.windows.net/{tenant_id}/",
        }
        self._jwks: dict[str, Any] = {}
        self._jwks_fetched_at: float = 0.0

    async def _get_jwks(self, force: bool = False) -> dict[str, Any]:
        stale = (time.time() - self._jwks_fetched_at) > self.JWKS_TTL_SECONDS
        if force or stale or not self._jwks:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(self.jwks_url)
                resp.raise_for_status()
                self._jwks = resp.json()
                self._jwks_fetched_at = time.time()
        return self._jwks

    async def _find_key(self, kid: str) -> Optional[dict[str, Any]]:
        jwks = await self._get_jwks()
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if key is None:
            # Key rotation: refresh once on an unknown kid.
            jwks = await self._get_jwks(force=True)
            key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        return key

    async def verify_token(self, token: str) -> AccessToken | None:
        from jose import jwt as jose_jwt
        from jose.exceptions import JWTError

        try:
            header = jose_jwt.get_unverified_header(token)
            key = await self._find_key(header.get("kid", ""))
            if key is None:
                logger.warning("MCP auth: token signed with unknown key id")
                return None
            unverified = jose_jwt.get_unverified_claims(token)
            issuer = unverified.get("iss")
            if issuer not in self.issuers:
                logger.warning("MCP auth: unexpected issuer %s", issuer)
                return None
            # python-jose only accepts a single audience string, so verify the
            # signature/issuer/expiry here and check `aud` against our accepted
            # list (bare app id and api:// form) ourselves below.
            claims = jose_jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=issuer,
                options={"verify_aud": False},
            )
        except JWTError as e:
            logger.warning("MCP auth: token rejected (%s)", e)
            return None
        except httpx.HTTPError as e:
            logger.error("MCP auth: could not fetch JWKS (%s)", e)
            return None

        aud_claim = claims.get("aud")
        token_audiences = aud_claim if isinstance(aud_claim, list) else [aud_claim]
        if not any(a in self.audiences for a in token_audiences):
            logger.warning("MCP auth: token audience %s not accepted", aud_claim)
            return None

        scopes: list[str] = []
        if claims.get("scp"):
            scopes.extend(str(claims["scp"]).split())
        if isinstance(claims.get("roles"), list):
            scopes.extend(claims["roles"])
        missing = [s for s in self.required_scopes if s not in scopes]
        if missing:
            logger.warning("MCP auth: token missing required scopes %s", missing)
            return None

        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("appid") or claims.get("aud")),
            scopes=scopes,
            expires_at=claims.get("exp"),
            subject=claims.get("oid") or claims.get("sub"),
            claims=claims,
        )


def _split_csv(value: Optional[str]) -> list[str]:
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def _build_auth(auth_mode: str) -> tuple[Optional[EntraTokenVerifier], Optional[AuthSettings]]:
    """Build the token verifier + AuthSettings for the HTTP transport."""
    if auth_mode != "entra":
        return None, None
    tenant = settings.MCP_ENTRA_TENANT_ID or settings.AZURE_TENANT_ID
    audiences = _split_csv(settings.MCP_ENTRA_AUDIENCE)
    if not tenant or not audiences:
        raise SystemExit(
            "MCP_AUTH_MODE=entra requires MCP_ENTRA_TENANT_ID (or AZURE_TENANT_ID) and MCP_ENTRA_AUDIENCE."
        )
    # Accept both the bare app ID and the api:// identifier URI for each audience.
    expanded: list[str] = []
    for aud in audiences:
        expanded.append(aud)
        if not aud.startswith("api://"):
            expanded.append(f"api://{aud}")
    required = _split_csv(settings.MCP_REQUIRED_SCOPES)
    verifier = EntraTokenVerifier(tenant, expanded, required)
    resource_url = settings.MCP_PUBLIC_URL or f"http://{settings.MCP_HOST}:{settings.MCP_PORT}/mcp"
    auth = AuthSettings(
        issuer_url=AnyHttpUrl(f"https://login.microsoftonline.com/{tenant}/v2.0"),
        resource_server_url=AnyHttpUrl(resource_url),
        required_scopes=required or None,
    )
    return verifier, auth


# ------------------------------------------------------------------- server
def create_server(auth_mode: Optional[str] = None, host: Optional[str] = None, port: Optional[int] = None) -> FastMCP:
    """Create the FastMCP server with all (non-disabled) tools registered.

    ``auth_mode`` overrides ``settings.MCP_AUTH_MODE`` (``none`` | ``entra``).
    Tools named in ``settings.MCP_DISABLED_TOOLS`` are not registered.
    """
    mode = (auth_mode or settings.MCP_AUTH_MODE or "none").lower()
    verifier, auth = _build_auth(mode)

    mcp = FastMCP(
        SERVER_NAME,
        instructions=SERVER_INSTRUCTIONS,
        host=host or settings.MCP_HOST,
        port=port or settings.MCP_PORT,
        token_verifier=verifier,
        auth=auth,
        stateless_http=True,
        json_response=True,
    )
    disabled = set(_split_csv(settings.MCP_DISABLED_TOOLS))
    if disabled:
        logger.info("MCP: not registering disabled tools: %s", ", ".join(sorted(disabled)))
    _register_tools(mcp, disabled)
    return mcp


def _summarize(incident: dict[str, Any]) -> dict[str, Any]:
    """Compact incident summary for list responses (keeps agent context small)."""
    summary = {k: incident.get(k) for k in INCIDENT_SUMMARY_FIELDS if k in incident}
    summary["entityCount"] = len(incident.get("entities") or [])
    return summary


def _not_found(incident_ref: str) -> dict[str, Any]:
    return {
        "error": "INCIDENT_NOT_FOUND",
        "incident_ref": incident_ref,
        "hint": (
            "Use sentinel_list_incidents to obtain a valid namespaced ref "
            f"('<workspace_id>{WORKSPACE_REF_SEPARATOR}<incident_guid>'). "
            "A bare GUID is routed to the default workspace, which may not be where the incident lives."
        ),
    }


def _opt(value: str) -> Optional[str]:
    """Flat-schema optional: '' means not set."""
    value = (value or "").strip()
    return value or None


def _actor(label: str) -> str:
    """Actor recorded in Sentinel audit comments.

    An explicit label wins; otherwise the signed-in analyst when the server runs
    with AZURE_AUTH_MODE=user (local per-analyst mode), else a generic agent label.
    """
    explicit = _opt(label)
    if explicit:
        return explicit
    from app.services.azure_credentials import actor_label
    from app.services.sentinel_client import sentinel_client
    return actor_label(sentinel_client.credential, fallback="AI SOC Agent (MCP)")


from app.services.indicators import extract_indicators  # noqa: E402  (shared with hunting / triage)


def _register_tools(mcp: FastMCP, disabled: set[str]) -> None:
    # Imported here so creating the server module doesn't eagerly construct every
    # service at import time (keeps `--help` fast and stdio startup quiet).
    from app.services.sentinel_client import sentinel_client
    from app.services.kql_runner import kql_runner
    from app.services.threat_intel import threat_intel_service
    # Shared with the REST/WebSocket API. Deliberately NOT imported from app.api.*
    # so this server never pulls in the HTTP/auth layer (whose import prints the
    # first-run credential banner — fatal on the stdio transport where stdout is
    # the protocol channel).
    from app.services.triage_store import TRIAGE_REPORTS_CACHE

    def tool(name: str, **kwargs: Any) -> Callable[[Callable], Callable]:
        """Register with FastMCP unless the tool is disabled by configuration."""
        if name in disabled:
            return lambda fn: fn
        return mcp.tool(name=name, **kwargs)

    # ---------------------------------------------------------------- fleet
    @tool("sentinel_list_workspaces", title="List Sentinel workspaces", annotations=READ_ONLY)
    async def sentinel_list_workspaces() -> dict[str, Any]:
        """List the managed Microsoft Sentinel workspace fleet (one entry per customer tenant).

        Returns each workspace's ``id`` (use it as the ``workspace`` selector in other
        tools), display name, and tenant/subscription/resource-group coordinates.
        Call this first to discover valid workspace ids.
        """
        workspaces = [
            {k: v for k, v in w.public_dict().items() if k in WORKSPACE_PUBLIC_FIELDS}
            for w in workspace_registry.list_workspaces()
        ]
        return {"count": len(workspaces), "workspaces": workspaces}

    # ------------------------------------------------------------ incidents
    @tool("sentinel_list_incidents", title="List Sentinel incidents", annotations=READ_ONLY)
    async def sentinel_list_incidents(
        workspace: Annotated[str, Field(description="Workspace id from sentinel_list_workspaces, a comma-separated list of ids, or 'all' to aggregate the whole fleet.")] = "all",
        status: Annotated[str, Field(description="Filter by status: New, Active, or Closed. Empty = any status.")] = "",
        severity: Annotated[str, Field(description="Filter by severity: High, Medium, Low, or Informational. Empty = any severity.")] = "",
        days: Annotated[int, Field(description="Only incidents created in the last N days. 0 = no time filter.", ge=0, le=365)] = 0,
        limit: Annotated[int, Field(description="Maximum incidents to return (newest first).", ge=1, le=200)] = 25,
    ) -> dict[str, Any]:
        """List incidents across one, several, or all managed Sentinel workspaces.

        Returns compact summaries sorted newest first. Each summary carries a namespaced
        ``id`` ('<workspace_id>::<incident_guid>') plus ``workspaceId``/``workspaceName``;
        pass that ``id`` as ``incident_ref`` to the other incident tools. Use
        sentinel_get_incident for the full entity graph, alerts, and comments.
        """
        incidents = await sentinel_client.list_incidents(
            filter_status=_opt(status), severity=_opt(severity), time_range_days=days or None, workspace=workspace
        )
        page = incidents[:limit]
        per_workspace: dict[str, int] = {}
        for inc in incidents:
            wid = inc.get("workspaceId", "unknown")
            per_workspace[wid] = per_workspace.get(wid, 0) + 1
        return {
            "total": len(incidents),
            "count": len(page),
            "truncated": len(incidents) > len(page),
            "workspace_selector": workspace,
            "per_workspace": per_workspace,
            "incidents": [_summarize(i) for i in page],
        }

    @tool("sentinel_get_incident", title="Get Sentinel incident", annotations=READ_ONLY)
    async def sentinel_get_incident(
        incident_ref: Annotated[str, Field(description=REF_DESCRIPTION, min_length=1)],
    ) -> dict[str, Any]:
        """Get one incident with its full entity graph (accounts, IPs, hosts, processes,
        hashes), correlated alerts, comments, labels, and classification.

        The ref's namespace routes the request to the correct delegated workspace.
        """
        incident = await sentinel_client.get_incident(incident_ref)
        return incident or _not_found(incident_ref)

    @tool("sentinel_extract_indicators", title="Extract incident indicators", annotations=READ_ONLY)
    async def sentinel_extract_indicators(
        incident_ref: Annotated[str, Field(description=REF_DESCRIPTION, min_length=1)],
    ) -> dict[str, Any]:
        """Return an incident's indicators as flat, deduplicated lists: ``ips``,
        ``accounts``, ``hosts``, ``file_hashes``, ``urls``, ``azure_resources``,
        ``processes``, ``cloud_apps``, ``mailboxes`` (plus ``counts``).

        Use this to hand indicators to other tools — e.g. enrich ``ips``/``file_hashes``/
        ``urls`` with a threat-intelligence service, or look up ``hosts``/``azure_resources``
        in an asset or cloud-security inventory — then record findings on the incident
        with sentinel_add_comment.
        """
        incident = await sentinel_client.get_incident(incident_ref)
        if not incident:
            return _not_found(incident_ref)
        return extract_indicators(incident)

    # --------------------------------------------------------------- triage
    @tool("sentinel_triage_incident", title="Run AI triage on an incident", annotations=WRITE_SAFE)
    async def sentinel_triage_incident(
        incident_ref: Annotated[str, Field(description=REF_DESCRIPTION, min_length=1)],
        claim: Annotated[bool, Field(description="Claim the incident first: assign it to you if unassigned, and refuse if another analyst owns it. Prevents two analysts triaging the same incident.")] = True,
        force: Annotated[bool, Field(description="Triage even if another analyst owns it or it was triaged within the last TRIAGE_DEDUPE_MINUTES. Never changes ownership.")] = False,
    ) -> dict[str, Any]:
        """Run the autonomous triage investigation on an incident and return the report.

        Coordination (so analysts don't collide): with ``claim`` (default) the incident is
        first assigned to you if nobody owns it, using an ETag-conditional write — if
        another analyst owns it, or claimed it a moment earlier, you get
        ``ALREADY_ASSIGNED`` with the owner instead of a duplicate investigation. If an AI
        triage comment was posted within the dedupe window you get ``RECENTLY_TRIAGED``
        pointing at the existing findings. Pass ``force=true`` to run anyway.

        The agent extracts entities, checks threat intelligence, runs KQL hunts against the
        incident's own workspace, and produces a verdict (TRUE_POSITIVE / FALSE_POSITIVE /
        SUSPICIOUS_ESCALATE) with confidence, MITRE ATT&CK mapping, evidence, recommended
        actions, and a root-cause analysis. When AUTO_POST_COMMENTS_TO_SENTINEL is enabled
        the summary is also posted back to the incident as a comment in its tenant.
        Can take 10-60 seconds. Use sentinel_get_triage_report to fetch an existing report.
        """
        from app.services.azure_credentials import get_signed_in_identity
        from app.services.triage_coordinator import run_coordinated_triage

        actor = get_signed_in_identity(sentinel_client.credential) if sentinel_client.credential else None
        result = await run_coordinated_triage(
            incident_ref,
            actor=actor,
            claim=claim and settings.TRIAGE_CLAIM_ON_RUN,
            dedupe=True,
            force=force,
        )
        if result.get("status") == "NOT_FOUND":
            return _not_found(incident_ref)
        return result

    @tool("sentinel_get_triage_report", title="Get existing triage report", annotations=READ_ONLY)
    async def sentinel_get_triage_report(
        incident_ref: Annotated[str, Field(description=REF_DESCRIPTION, min_length=1)],
    ) -> dict[str, Any]:
        """Return a previously generated triage report for an incident, if one exists.

        Returns ``{"status": "NOT_TRIAGED"}`` when no report has been generated yet; call
        sentinel_triage_incident to produce one.
        """
        workspace, raw_id = workspace_registry.resolve_ref(incident_ref)
        canonical = workspace_registry.make_ref(workspace.id, raw_id)
        report = TRIAGE_REPORTS_CACHE.get(canonical) or TRIAGE_REPORTS_CACHE.get(incident_ref)
        if report:
            return report
        return {"status": "NOT_TRIAGED", "incident_ref": canonical, "hint": "Run sentinel_triage_incident to generate a report."}

    # ------------------------------------------------------------ hunting/TI
    @tool("sentinel_run_kql", title="Run KQL query", annotations=READ_ONLY_EXTERNAL)
    async def sentinel_run_kql(
        query: Annotated[str, Field(description="Kusto Query Language query, e.g. \"SigninLogs | where ResultType != 0 | take 20\".", min_length=1)],
        workspace: Annotated[str, Field(description="Workspace id to query. Empty = the default workspace. Use the incident's workspaceId when hunting for a specific incident.")] = "",
        timespan_hours: Annotated[int, Field(description="Lookback window in hours.", ge=1, le=24 * 90)] = 24,
    ) -> dict[str, Any]:
        """Execute an ad-hoc KQL query against a workspace's Log Analytics data.

        Any ingested table works: Entra ID (SigninLogs, AADNonInteractiveUserSignInLogs,
        AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs, AuditLogs, AADRiskyUsers,
        AADUserRiskEvents, AADRiskyServicePrincipals, AADServicePrincipalRiskEvents), Defender
        XDR advanced-hunting tables (DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents,
        DeviceFileEvents, DeviceEvents, DeviceInfo, DeviceRegistryEvents, IdentityLogonEvents,
        EmailEvents, CloudAppEvents…), AzureActivity, AzureDiagnostics, SecurityEvent,
        OfficeActivity, CommonSecurityLog, Syslog, SecurityAlert, SecurityIncident, TI tables.
        Check sentinel_list_tables first to see what this workspace actually ingests; prefer
        sentinel_hunt_incident for the standard entity pivots.

        Works across delegated tenants via Azure Lighthouse with your own Sentinel role.
        Returns tables with columns, rows, row counts, latency and the data source, or
        status ERROR with error_type (TABLE_NOT_FOUND, QUERY_INVALID, FORBIDDEN…) — never
        simulated rows outside demo mode.
        """
        ws_id = _opt(workspace)
        ws = workspace_registry.get(ws_id) if ws_id else None
        if ws_id and ws is None:
            return {"error": "WORKSPACE_NOT_FOUND", "workspace": ws_id, "hint": "Use sentinel_list_workspaces for valid ids."}
        return await kql_runner.execute_kql(query, timespan_hours=timespan_hours, workspace=ws)

    @tool("sentinel_list_tables", title="List ingested tables", annotations=READ_ONLY_EXTERNAL)
    async def sentinel_list_tables(
        workspace: Annotated[str, Field(description="Workspace id (from sentinel_list_workspaces). Empty = the default workspace.")] = "",
        days: Annotated[int, Field(description="Only tables that received data within the last N days.", ge=1, le=90)] = 7,
    ) -> dict[str, Any]:
        """Which Log Analytics tables this workspace actually ingests (from its Usage
        table), with last-record time and volume. Use it to know what you can hunt in
        before writing KQL: e.g. whether Device* (Defender XDR), AADNonInteractiveUserSignInLogs,
        AzureDiagnostics or OfficeActivity exist here. Also reports which catalog hunts the
        data supports."""
        from app.services.hunting_catalog import HUNTS

        ws_id = _opt(workspace)
        ws = workspace_registry.get(ws_id) if ws_id else None
        if ws_id and ws is None:
            return {"error": "WORKSPACE_NOT_FOUND", "workspace": ws_id, "hint": "Use sentinel_list_workspaces for valid ids."}
        target = ws or workspace_registry.default()
        tables = await kql_runner.list_tables(ws, days=days)
        if tables is None:
            return {"status": "UNKNOWN", "workspace_id": target.id if target else None,
                    "message": "Could not read the workspace's Usage table (no access or query failed); hunts will run blind and report missing tables."}
        names = {t["table"].lower() for t in tables}
        supported = [h.id for h in HUNTS if all(t.lower() in names for t in h.tables)]
        return {
            "status": "SUCCESS",
            "workspace_id": target.id if target else None,
            "lookback_days": days,
            "count": len(tables),
            "tables": tables,
            "hunts_supported": supported,
            "hunts_unsupported": [{"id": h.id, "missing": [t for t in h.tables if t.lower() not in names]} for h in HUNTS if h.id not in supported],
        }

    @tool("sentinel_hunt_incident", title="Run catalog hunts for an incident", annotations=READ_ONLY_EXTERNAL)
    async def sentinel_hunt_incident(
        incident_ref: Annotated[str, Field(description=REF_DESCRIPTION, min_length=1)],
        hunts: Annotated[str, Field(description="Comma-separated hunt ids to run (see dry_run output). Empty = every applicable hunt.")] = "",
        families: Annotated[str, Field(description="Comma-separated families to restrict to: entra-id, defender-xdr, azure, security-logs, alerts, threat-intel. Empty = all.")] = "",
        max_hunts: Annotated[int, Field(description="Cap on hunts per call. 0 = server default (HUNT_MAX_QUERIES).", ge=0, le=40)] = 0,
        max_rows: Annotated[int, Field(description="Rows returned per hunt. 0 = server default (HUNT_MAX_ROWS).", ge=0, le=200)] = 0,
        dry_run: Annotated[bool, Field(description="Plan only: return the rendered KQL for each applicable hunt without executing it.")] = False,
    ) -> dict[str, Any]:
        """Run the entity-driven KQL hunt catalog for an incident in its own workspace:
        sign-in baselines and token sign-ins, risk detections, directory audit, endpoint
        logons / processes / network / files / inventory / registry (Defender XDR Device*),
        identity logons, email, cloud-app activity, Azure control-plane and resource logs,
        Windows / Linux / Office / firewall logs, related alerts and TI matches.

        Hunts are selected from the incident's accounts, IPs, hosts, hashes, URLs, apps and
        resources, and from the tables the workspace ingests; skipped hunts say why. Each
        result carries the exact KQL so the analyst can re-run or refine it with
        sentinel_run_kql. Read-only; nothing is written to the incident."""
        from app.services.hunting import hunt_incident

        incident = await sentinel_client.get_incident(incident_ref)
        if not incident:
            return _not_found(incident_ref)
        return await hunt_incident(
            incident,
            hunt_ids=_opt(hunts),
            families=_opt(families),
            max_hunts=max_hunts or None,
            max_rows=max_rows or None,
            dry_run=dry_run,
        )

    @tool("sentinel_check_ip_reputation", title="Check IP reputation", annotations=READ_ONLY_EXTERNAL)
    async def sentinel_check_ip_reputation(
        ip_address: Annotated[str, Field(description="IPv4 or IPv6 address to look up.", min_length=3)],
    ) -> dict[str, Any]:
        """Look up an IP address against threat-intelligence feeds (AbuseIPDB and global
        feeds). Returns an abuse confidence score, verdict (MALICIOUS / SUSPICIOUS /
        BENIGN_INTERNAL / …), and context such as ISP and country. If a dedicated
        threat-intelligence tool is available to you, prefer it and use this as a fallback."""
        return await threat_intel_service.lookup_ip_reputation(ip_address)

    @tool("sentinel_check_file_hash", title="Check file hash", annotations=READ_ONLY_EXTERNAL)
    async def sentinel_check_file_hash(
        file_hash: Annotated[str, Field(description="SHA256, SHA1, or MD5 hash.", min_length=32)],
    ) -> dict[str, Any]:
        """Look up a file hash against VirusTotal-style threat databases and return
        detection counts and a verdict. If a dedicated threat-intelligence tool is
        available to you, prefer it and use this as a fallback."""
        return await threat_intel_service.lookup_file_hash(file_hash)

    # ---------------------------------------------------------------- actions
    @tool("sentinel_add_comment", title="Add incident comment", annotations=WRITE_SAFE)
    async def sentinel_add_comment(
        incident_ref: Annotated[str, Field(description=REF_DESCRIPTION, min_length=1)],
        message: Annotated[str, Field(description="Markdown comment to post on the incident.", min_length=1, max_length=20000)],
        author: Annotated[str, Field(description="Author label recorded with the comment. Empty = the signed-in analyst (local user mode) or 'AI SOC Agent (MCP)'.")] = "",
    ) -> dict[str, Any]:
        """Post an investigation note / comment to the incident in its own Sentinel
        workspace — e.g. enrichment results from other tools. Non-destructive; the
        comment is appended to the incident's timeline."""
        result = await sentinel_client.add_comment(incident_ref, message, author=_actor(author))
        return result if result.get("status") != "NOT_FOUND" else _not_found(incident_ref)

    @tool("sentinel_update_incident_status", title="Update incident status / classification", annotations=WRITE_DESTRUCTIVE)
    async def sentinel_update_incident_status(
        incident_ref: Annotated[str, Field(description=REF_DESCRIPTION, min_length=1)],
        status: Annotated[str, Field(description="New status: New, Active, or Closed.", pattern="^(New|Active|Closed)$")],
        severity: Annotated[str, Field(description="Optionally adjust severity: High, Medium, Low, Informational. Empty = unchanged.")] = "",
        classification: Annotated[str, Field(description="Required when closing: TruePositive, FalsePositive, BenignPositive, or Undetermined. Empty = unchanged.")] = "",
        classification_reason: Annotated[str, Field(description="Sentinel classification reason, e.g. SuspiciousActivity, InaccurateData, SuspiciousButExpected. Empty = default for the classification.")] = "",
        classification_comment: Annotated[str, Field(description="Closing notes recorded on the incident. Empty = default note.")] = "",
        labels: Annotated[list[str], Field(description="Labels/tags to apply to the incident. Empty list = unchanged.")] = [],
        updated_by: Annotated[str, Field(description="Analyst / agent name recorded in the audit comment. Empty = the signed-in analyst (local user mode) or 'AI SOC Agent (MCP)'.")] = "",
        expected_etag: Annotated[str, Field(description="Optional etag from sentinel_get_incident; the write fails with CONFLICT if the incident changed since. Empty = skip this check (the write is still ETag-protected against concurrent edits).")] = "",
    ) -> dict[str, Any]:
        """Change an incident's status, severity, classification, or labels in its Sentinel
        workspace. Closing an incident is a significant action: confirm with the analyst
        first and always supply a ``classification`` (and ideally a reason/comment). An
        audit comment is posted automatically. Writes are ETag-conditional: if another
        analyst changed the incident concurrently you get CONFLICT — re-read and retry."""
        if status == "Closed" and not _opt(classification):
            return {
                "error": "CLASSIFICATION_REQUIRED",
                "hint": "Closing requires classification: TruePositive, FalsePositive, BenignPositive, or Undetermined.",
            }
        result = await sentinel_client.update_status(
            incident_ref,
            status=status,
            severity=_opt(severity),
            classification=_opt(classification),
            classification_reason=_opt(classification_reason),
            classification_comment=_opt(classification_comment),
            labels=list(labels) or None,
            updated_by=_actor(updated_by),
            expected_etag=_opt(expected_etag),
        )
        return result if result.get("status") != "NOT_FOUND" else _not_found(incident_ref)

    @tool("sentinel_assign_incident", title="Assign incident", annotations=WRITE_SAFE)
    async def sentinel_assign_incident(
        incident_ref: Annotated[str, Field(description=REF_DESCRIPTION, min_length=1)],
        user_upn: Annotated[str, Field(description="UPN/email of the assignee (their Entra sign-in name). Leave all user fields empty to unassign.")] = "",
        user_name: Annotated[str, Field(description="Display name of the assignee.")] = "",
        user_id: Annotated[str, Field(description="Entra object id of the assignee, if known.")] = "",
        assigned_by: Annotated[str, Field(description="Who performed the assignment (audit comment). Empty = the signed-in analyst (local user mode) or 'AI SOC Agent (MCP)'.")] = "",
        only_if_unassigned: Annotated[bool, Field(description="Claim semantics: succeed only if nobody else owns the incident (returns ALREADY_ASSIGNED otherwise). Use this to take an incident safely.")] = False,
        expected_etag: Annotated[str, Field(description="Optional etag from sentinel_get_incident; the write fails with CONFLICT if the incident changed since. Empty = skip this check (the write is still ETag-protected against concurrent edits).")] = "",
    ) -> dict[str, Any]:
        """Assign an incident to a SOC engineer in its tenant, or unassign it when all user
        fields are empty. Posts an audit comment on the incident. Writes are
        ETag-conditional, so concurrent assignments return CONFLICT rather than
        overwriting each other."""
        result = await sentinel_client.assign_incident(
            incident_ref,
            user_id=_opt(user_id),
            user_name=_opt(user_name),
            user_email=_opt(user_upn),
            user_upn=_opt(user_upn),
            assigned_by=_actor(assigned_by),
            only_if_unassigned=only_if_unassigned,
            expected_etag=_opt(expected_etag),
        )
        return result if result.get("status") != "NOT_FOUND" else _not_found(incident_ref)



# ------------------------------------------------------------ local tooling
BACKEND_DIR = str(__import__("pathlib").Path(__file__).resolve().parent.parent)
CLIENT_CONFIG_TARGETS = ("claude-desktop", "claude-code", "vscode")


def client_config(target: str) -> str:
    """Render the MCP client configuration for running this server locally over
    stdio with the current interpreter. PYTHONPATH makes `app.*` importable from
    any working directory; settings load the backend's own .env regardless of cwd.
    """
    import json

    python = sys.executable
    args = ["-m", "app.mcp_server", "--transport", "stdio"]
    env = {"PYTHONPATH": BACKEND_DIR}
    if target == "claude-desktop":
        return json.dumps({"mcpServers": {"sentinel-soc": {"command": python, "args": args, "env": env}}}, indent=2)
    if target == "vscode":
        return json.dumps({"servers": {"sentinel-soc": {"type": "stdio", "command": python, "args": args, "env": env}}}, indent=2)
    if target == "claude-code":
        return f"claude mcp add sentinel-soc -e PYTHONPATH={BACKEND_DIR} -- {python} {' '.join(args)}"
    raise ValueError(f"unknown client config target {target!r}; choose from {', '.join(CLIENT_CONFIG_TARGETS)}")


def run_discover(out_path: Optional[str], include_all: bool, dry_run: bool) -> int:
    """Generate / refresh the fleet file from Azure Resource Graph using the
    current identity (the analyst's az login in user mode). Returns an exit code."""
    from app.services import workspace_discovery as disc
    from app.services.sentinel_client import sentinel_client
    from app.services.workspace_registry import BACKEND_DIR as _BD, resolve_fleet_path

    if settings.DEMO_MODE or not sentinel_client.is_live:
        print("Discovery needs live Azure credentials: set DEMO_MODE=False and AZURE_AUTH_MODE=user, then `az login --tenant <managing-tenant-id>`.")
        return 1
    token = sentinel_client._get_arm_token()
    if not token:
        print("Could not obtain an Azure token. Run `az login --tenant <managing-tenant-id>` and retry.")
        return 1

    target = out_path or resolve_fleet_path(must_exist=False) or __import__("os").path.join(_BD, "workspaces.json")
    try:
        entries, stats = disc.discover(token, include_all=include_all)
    except Exception as e:  # noqa: BLE001
        print(f"Resource Graph query failed: {type(e).__name__}: {e}")
        return 1
    existing = disc.load_existing(target)
    merged, summary = disc.merge_fleet(existing, entries) if existing else (entries, {"added": [e["id"] for e in entries], "updated": [], "missing": []})

    print("Azure Resource Graph discovery (tenant scope, includes Lighthouse-delegated subscriptions)")
    print(f"  Log Analytics workspaces visible : {stats['log_analytics_workspaces']} across {stats['subscriptions']} subscription(s) in {stats['tenants']} tenant(s)")
    print(f"  Microsoft Sentinel enabled       : {stats['sentinel_workspaces']}" + ("" if include_all else "  (only these are written; add --include-all-workspaces to keep the rest)"))
    print(f"  Fleet file                       : {target}{' (dry run - not written)' if dry_run else ''}")
    print(f"  Added {len(summary['added'])} · refreshed {len(summary['updated'])} · kept-but-not-found {len(summary['missing'])}")
    for wid in summary["missing"]:
        print(f"    ! {wid}: not visible in Resource Graph - lost access, or the workspace is gone")
    if dry_run:
        print(disc.render_fleet_file(merged))
        return 0
    with open(target, "w", encoding="utf-8") as f:
        f.write(disc.render_fleet_file(merged))
    print(f"  Wrote {len(merged)} workspace(s). Next: python -m app.mcp_server --check")
    return 0


def run_check(check_workspaces: bool = True) -> int:
    """Self-diagnosis for a local (per-analyst) install. Prints a report to stdout
    and returns a process exit code (0 = ready)."""
    import asyncio

    from app.services.azure_credentials import get_signed_in_identity, resolve_auth_mode
    from app.services.sentinel_client import sentinel_client

    ok = True
    out: list[str] = []
    mode = resolve_auth_mode()
    out.append("Sentinel AI SOC Agent MCP server - local check")
    out.append(f"  Backend dir   : {BACKEND_DIR}")
    out.append(f"  Python        : {sys.executable}")
    out.append(f"  DEMO_MODE     : {settings.DEMO_MODE}")
    out.append(f"  Auth mode     : {mode}")

    if settings.DEMO_MODE:
        out.append("  Azure         : not contacted (DEMO_MODE=True). Set DEMO_MODE=False for live Sentinel.")
    elif not sentinel_client.is_live:
        ok = False
        out.append("  Azure         : NOT LIVE - no usable credentials. For a local analyst install set AZURE_AUTH_MODE=user and run `az login --tenant <managing-tenant-id>`.")
    else:
        identity = get_signed_in_identity(sentinel_client.credential)
        if identity:
            out.append(f"  Signed in as  : {identity.get('name')} <{identity.get('upn') or '-'}> ({identity.get('kind')}, tenant {identity.get('tenant_id')})")
        else:
            ok = False
            out.append("  Signed in as  : FAILED to obtain an ARM token. Run `az login --tenant <managing-tenant-id>` (or check AZURE_AUTH_MODE / service-principal settings).")

    fleet = workspace_registry.list_workspaces()
    source = workspace_registry._source
    out.append(f"  Workspaces    : {len(fleet)} loaded (source: {source})")
    if not settings.DEMO_MODE and source in ("demo-seed", "legacy-single-workspace"):
        ok = False
        if settings.WORKSPACES_CONFIG_PATH:
            out.append(f"    ! fleet file not found: WORKSPACES_CONFIG_PATH={settings.WORKSPACES_CONFIG_PATH!r}. Generate it with `python -m app.mcp_server --discover-workspaces`.")
        else:
            out.append("    ! no fleet configured (running on built-in sample workspaces). Set WORKSPACES_CONFIG_PATH and run `python -m app.mcp_server --discover-workspaces`.")
    for w in fleet:
        out.append(f"    - {w.id:<24} {w.display_name}  [{'managing tenant' if w.is_managing_tenant else 'delegated'}]")
    if not fleet:
        ok = False
        out.append("    (none) - set WORKSPACES_CONFIG_PATH to the fleet file you were given.")

    if check_workspaces and sentinel_client.is_live and fleet:
        token = sentinel_client._get_arm_token()
        if token:
            async def probe(ws):
                if not ws.has_arm_coordinates():
                    return ws.id, "SKIP (no ARM coordinates)"
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        r = await client.get(ws.arm_workspace_url(), headers={"Authorization": f"Bearer {token}"})
                    if r.status_code == 200:
                        return ws.id, "OK"
                    if r.status_code == 403:
                        return ws.id, "403 - no delegated role on this workspace (check Lighthouse authorization)"
                    if r.status_code == 404:
                        return ws.id, "404 - subscription/resource group/workspace name not found"
                    return ws.id, f"HTTP {r.status_code}"
                except Exception as e:  # noqa: BLE001
                    return ws.id, f"ERROR {type(e).__name__}"

            async def probe_all():
                sem = asyncio.Semaphore(10)
                async def one(ws):
                    async with sem:
                        return await probe(ws)
                return await asyncio.gather(*[one(ws) for ws in fleet])

            results = asyncio.run(probe_all())
            out.append("  Reachability  :")
            for wid, status in results:
                if status != "OK" and not status.startswith("SKIP"):
                    ok = False
                out.append(f"    - {wid:<24} {status}")

    server = create_server(auth_mode="none")
    tool_names = sorted(t.name for t in asyncio.run(server.list_tools()))
    disabled = _split_csv(settings.MCP_DISABLED_TOOLS)
    out.append(f"  Tools         : {len(tool_names)} registered" + (f" ({len(disabled)} disabled via MCP_DISABLED_TOOLS)" if disabled else ""))
    llm = bool((settings.LLM_PROVIDER == "azure_openai" and settings.AZURE_OPENAI_ENDPOINT and settings.AZURE_OPENAI_API_KEY) or settings.OPENAI_API_KEY)
    out.append(f"  Server LLM    : {'configured' if llm else 'not configured - fine for MCP use: your MCP client is the reasoning engine; sentinel_triage_incident uses the built-in deterministic engine'}")
    out.append("")
    out.append("READY" if ok else "NOT READY - fix the items above and re-run --check")
    out.append("Next: python -m app.mcp_server --print-config claude-desktop   (or vscode / claude-code)")
    print("\n".join(out))
    return 0 if ok else 1


# ------------------------------------------------------------------------ CLI
def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m app.mcp_server",
        description="Run the Microsoft Sentinel AI SOC Agent MCP server.",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="stdio for local clients (Claude Desktop/Code, VS Code); streamable-http for remote hosting (default: stdio).",
    )
    parser.add_argument("--host", default=None, help=f"HTTP bind host (default: MCP_HOST={settings.MCP_HOST}).")
    parser.add_argument("--port", type=int, default=None, help=f"HTTP bind port (default: MCP_PORT={settings.MCP_PORT}).")
    parser.add_argument(
        "--auth",
        choices=["none", "entra"],
        default=None,
        help=f"Bearer auth for the HTTP transport (default: MCP_AUTH_MODE={settings.MCP_AUTH_MODE}).",
    )
    parser.add_argument("--check", action="store_true", help="Self-diagnose a local install (auth, identity, fleet, workspace reachability, tools) and exit.")
    parser.add_argument("--no-workspace-probe", action="store_true", help="With --check: skip probing each workspace over ARM.")
    parser.add_argument("--print-config", choices=list(CLIENT_CONFIG_TARGETS), default=None, help="Print the MCP client configuration for this install and exit.")
    parser.add_argument("--discover-workspaces", action="store_true", help="Generate/refresh the fleet file (workspaces.json) from Azure Resource Graph using your signed-in identity, then exit.")
    parser.add_argument("--fleet-out", default=None, help="With --discover-workspaces: where to write the fleet file (default: WORKSPACES_CONFIG_PATH, else backend/workspaces.json).")
    parser.add_argument("--include-all-workspaces", action="store_true", help="With --discover-workspaces: include Log Analytics workspaces that are not Sentinel-enabled.")
    parser.add_argument("--dry-run", action="store_true", help="With --discover-workspaces: print the fleet file instead of writing it.")
    args = parser.parse_args(argv)

    if args.discover_workspaces:
        sys.exit(run_discover(args.fleet_out, args.include_all_workspaces, args.dry_run))

    if args.print_config:
        print(client_config(args.print_config))
        return
    if args.check:
        sys.exit(run_check(check_workspaces=not args.no_workspace_probe))

    auth_mode = args.auth or settings.MCP_AUTH_MODE
    if args.transport == "stdio":
        # stdio is a local, single-user channel; bearer auth does not apply.
        auth_mode = "none"

    server = create_server(auth_mode=auth_mode, host=args.host, port=args.port)
    if args.transport == "streamable-http":
        logger.info(
            "Sentinel MCP server listening on http://%s:%s/mcp (auth=%s, demo_mode=%s)",
            server.settings.host, server.settings.port, auth_mode, settings.DEMO_MODE,
        )
        if auth_mode == "none" and server.settings.host not in ("127.0.0.1", "localhost"):
            logger.warning("MCP HTTP transport is bound to %s with NO authentication - use MCP_AUTH_MODE=entra for anything beyond local testing.", server.settings.host)
    else:
        logger.info("Sentinel MCP server running on stdio (demo_mode=%s)", settings.DEMO_MODE)
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
