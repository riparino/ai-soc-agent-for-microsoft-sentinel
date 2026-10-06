"""
MCP server for the Microsoft Sentinel AI SOC Agent.

Exposes the agent's capabilities (fleet-wide incident listing, triage, KQL hunts,
threat intel, comments/status/assignment, guarded remediation) as Model Context
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
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from typing import Annotated, Any, Optional

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
    "Start with sentinel_list_workspaces to see the fleet. Identity actions (revoke "
    "sessions / disable account) are refused for delegated tenants without a per-customer "
    "Microsoft Graph app because Azure Lighthouse does not delegate Microsoft Graph."
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
    """Create the FastMCP server with all tools registered.

    ``auth_mode`` overrides ``settings.MCP_AUTH_MODE`` (``none`` | ``entra``).
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
    _register_tools(mcp)
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


def _register_tools(mcp: FastMCP) -> None:
    # Imported here so creating the server module doesn't eagerly construct every
    # service at import time (keeps `--help` fast and stdio startup quiet).
    from app.services.sentinel_client import sentinel_client
    from app.services.kql_runner import kql_runner
    from app.services.threat_intel import threat_intel_service
    from app.services.remediation_service import remediation_service
    from app.agent.triage_agent import triage_agent
    # Shared with the REST/WebSocket API. Deliberately NOT imported from app.api.*
    # so this server never pulls in the HTTP/auth layer (whose import prints the
    # first-run credential banner — fatal on the stdio transport where stdout is
    # the protocol channel).
    from app.services.triage_store import TRIAGE_REPORTS_CACHE

    # ---------------------------------------------------------------- fleet
    @mcp.tool(name="sentinel_list_workspaces", title="List Sentinel workspaces", annotations=READ_ONLY)
    async def sentinel_list_workspaces() -> dict[str, Any]:
        """List the managed Microsoft Sentinel workspace fleet (one entry per customer tenant).

        Returns each workspace's ``id`` (use it as the ``workspace`` selector in other
        tools), display name, tenant/subscription coordinates, and ``graph_mode``:
        ``managing-tenant`` / ``delegated-app`` allow identity actions; ``log-analytics-only``
        means Microsoft Graph is not reachable for that tenant (Azure Lighthouse limitation).
        Call this first to discover valid workspace ids.
        """
        workspaces = [w.public_dict() for w in workspace_registry.list_workspaces()]
        return {"count": len(workspaces), "workspaces": workspaces}

    # ------------------------------------------------------------ incidents
    @mcp.tool(name="sentinel_list_incidents", title="List Sentinel incidents", annotations=READ_ONLY)
    async def sentinel_list_incidents(
        workspace: Annotated[str, Field(description="Workspace id from sentinel_list_workspaces, a comma-separated list of ids, or 'all' to aggregate the whole fleet.")] = "all",
        status: Annotated[Optional[str], Field(description="Filter by status: New, Active, or Closed.")] = None,
        severity: Annotated[Optional[str], Field(description="Filter by severity: High, Medium, Low, or Informational.")] = None,
        days: Annotated[Optional[int], Field(description="Only incidents created in the last N days.", ge=1, le=365)] = None,
        limit: Annotated[int, Field(description="Maximum incidents to return (newest first).", ge=1, le=200)] = 25,
    ) -> dict[str, Any]:
        """List incidents across one, several, or all managed Sentinel workspaces.

        Returns compact summaries sorted newest first. Each summary carries a namespaced
        ``id`` ('<workspace_id>::<incident_guid>') plus ``workspaceId``/``workspaceName``;
        pass that ``id`` as ``incident_ref`` to the other incident tools. Use
        sentinel_get_incident for the full entity graph, alerts, and comments.
        """
        incidents = await sentinel_client.list_incidents(
            filter_status=status, severity=severity, time_range_days=days, workspace=workspace
        )
        page = incidents[:limit]
        per_workspace: dict[str, int] = {}
        for inc in incidents:
            per_workspace[inc.get("workspaceId", "unknown")] = per_workspace.get(inc.get("workspaceId", "unknown"), 0) + 1
        return {
            "total": len(incidents),
            "count": len(page),
            "truncated": len(incidents) > len(page),
            "workspace_selector": workspace,
            "per_workspace": per_workspace,
            "incidents": [_summarize(i) for i in page],
        }

    @mcp.tool(name="sentinel_get_incident", title="Get Sentinel incident", annotations=READ_ONLY)
    async def sentinel_get_incident(
        incident_ref: Annotated[str, Field(description="Namespaced incident ref '<workspace_id>::<incident_guid>' from sentinel_list_incidents.", min_length=1)],
    ) -> dict[str, Any]:
        """Get one incident with its full entity graph (accounts, IPs, hosts, processes,
        hashes), correlated alerts, comments, labels, and classification.

        The ref's namespace routes the request to the correct delegated workspace.
        """
        incident = await sentinel_client.get_incident(incident_ref)
        return incident or _not_found(incident_ref)

    @mcp.tool(name="sentinel_list_tenant_users", title="List tenant users for assignment", annotations=READ_ONLY)
    async def sentinel_list_tenant_users(
        workspace: Annotated[Optional[str], Field(description="Workspace id whose tenant directory to list. Defaults to the managing tenant.")] = None,
    ) -> dict[str, Any]:
        """List SOC engineers / users for a workspace's tenant, for use with
        sentinel_assign_incident.

        Source depends on the workspace's ``graph_mode``: Microsoft Graph for the managing
        tenant or a per-customer app; otherwise the workspace's own SigninLogs telemetry
        (Azure Lighthouse does not delegate Microsoft Graph).
        """
        ws = workspace_registry.get(workspace) if workspace else None
        users = await sentinel_client.get_entra_users(workspace=ws)
        resolved = ws or workspace_registry.managing_workspace() or workspace_registry.default()
        return {
            "workspace_id": resolved.id if resolved else None,
            "graph_mode": resolved.graph_mode if resolved else None,
            "count": len(users),
            "users": users,
        }

    # --------------------------------------------------------------- triage
    @mcp.tool(name="sentinel_triage_incident", title="Run AI triage on an incident", annotations=WRITE_SAFE)
    async def sentinel_triage_incident(
        incident_ref: Annotated[str, Field(description="Namespaced incident ref '<workspace_id>::<incident_guid>'.", min_length=1)],
    ) -> dict[str, Any]:
        """Run the autonomous triage investigation on an incident and return the report.

        The agent extracts entities, checks threat intelligence, runs KQL hunts against the
        incident's own workspace, and produces a verdict (TRUE_POSITIVE / FALSE_POSITIVE /
        SUSPICIOUS_ESCALATE) with confidence, MITRE ATT&CK mapping, evidence, recommended
        actions, and a root-cause analysis. When AUTO_POST_COMMENTS_TO_SENTINEL is enabled
        the summary is also posted back to the incident as a comment in its tenant.
        Can take 10-60 seconds. Use sentinel_get_triage_report to fetch an existing report.
        """
        incident = await sentinel_client.get_incident(incident_ref)
        if not incident:
            return _not_found(incident_ref)
        report = await triage_agent.triage_incident(incident)
        TRIAGE_REPORTS_CACHE[incident["id"]] = report
        return report

    @mcp.tool(name="sentinel_get_triage_report", title="Get existing triage report", annotations=READ_ONLY)
    async def sentinel_get_triage_report(
        incident_ref: Annotated[str, Field(description="Namespaced incident ref '<workspace_id>::<incident_guid>'.", min_length=1)],
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
    @mcp.tool(name="sentinel_run_kql", title="Run KQL query", annotations=READ_ONLY_EXTERNAL)
    async def sentinel_run_kql(
        query: Annotated[str, Field(description="Kusto Query Language query, e.g. \"SigninLogs | where ResultType != 0 | take 20\".", min_length=1)],
        workspace: Annotated[Optional[str], Field(description="Workspace id to query. Defaults to the default workspace. Use the incident's workspaceId when hunting for a specific incident.")] = None,
        timespan_hours: Annotated[int, Field(description="Lookback window in hours.", ge=1, le=24 * 90)] = 24,
    ) -> dict[str, Any]:
        """Execute a KQL query against a workspace's Log Analytics data (SigninLogs,
        DeviceProcessEvents, DeviceNetworkEvents, SecurityEvent, CommonSecurityLog…).

        Works across delegated tenants via Azure Lighthouse. Returns tables with columns,
        rows, row counts, latency, and the data source (live vs. simulated in demo mode).
        """
        ws = workspace_registry.get(workspace) if workspace else None
        if workspace and ws is None:
            return {"error": "WORKSPACE_NOT_FOUND", "workspace": workspace, "hint": "Use sentinel_list_workspaces for valid ids."}
        return await kql_runner.execute_kql(query, timespan_hours=timespan_hours, workspace=ws)

    @mcp.tool(name="sentinel_check_ip_reputation", title="Check IP reputation", annotations=READ_ONLY_EXTERNAL)
    async def sentinel_check_ip_reputation(
        ip_address: Annotated[str, Field(description="IPv4 or IPv6 address to look up.", min_length=3)],
    ) -> dict[str, Any]:
        """Look up an IP address against threat-intelligence feeds (AbuseIPDB and global
        feeds). Returns an abuse confidence score, verdict (MALICIOUS / SUSPICIOUS /
        BENIGN_INTERNAL / …), and context such as ISP and country."""
        return await threat_intel_service.lookup_ip_reputation(ip_address)

    @mcp.tool(name="sentinel_check_file_hash", title="Check file hash", annotations=READ_ONLY_EXTERNAL)
    async def sentinel_check_file_hash(
        file_hash: Annotated[str, Field(description="SHA256, SHA1, or MD5 hash.", min_length=32)],
    ) -> dict[str, Any]:
        """Look up a file hash against VirusTotal-style threat databases and return
        detection counts and a verdict."""
        return await threat_intel_service.lookup_file_hash(file_hash)

    # ---------------------------------------------------------------- actions
    @mcp.tool(name="sentinel_add_comment", title="Add incident comment", annotations=WRITE_SAFE)
    async def sentinel_add_comment(
        incident_ref: Annotated[str, Field(description="Namespaced incident ref '<workspace_id>::<incident_guid>'.", min_length=1)],
        message: Annotated[str, Field(description="Markdown comment to post on the incident.", min_length=1, max_length=20000)],
        author: Annotated[str, Field(description="Author label recorded with the comment.")] = "AI SOC Agent (MCP)",
    ) -> dict[str, Any]:
        """Post an investigation note / comment to the incident in its own Sentinel
        workspace. Non-destructive; the comment is appended to the incident's timeline."""
        result = await sentinel_client.add_comment(incident_ref, message, author=author)
        return result if result.get("status") != "NOT_FOUND" else _not_found(incident_ref)

    @mcp.tool(name="sentinel_update_incident_status", title="Update incident status / classification", annotations=WRITE_DESTRUCTIVE)
    async def sentinel_update_incident_status(
        incident_ref: Annotated[str, Field(description="Namespaced incident ref '<workspace_id>::<incident_guid>'.", min_length=1)],
        status: Annotated[str, Field(description="New status: New, Active, or Closed.", pattern="^(New|Active|Closed)$")],
        severity: Annotated[Optional[str], Field(description="Optionally adjust severity: High, Medium, Low, Informational.")] = None,
        classification: Annotated[Optional[str], Field(description="Required when closing: TruePositive, FalsePositive, BenignPositive, or Undetermined.")] = None,
        classification_reason: Annotated[Optional[str], Field(description="Sentinel classification reason, e.g. SuspiciousActivity, InaccurateData, SuspiciousButExpected.")] = None,
        classification_comment: Annotated[Optional[str], Field(description="Closing notes recorded on the incident.")] = None,
        labels: Annotated[Optional[list[str]], Field(description="Labels/tags to apply to the incident.")] = None,
        updated_by: Annotated[str, Field(description="Analyst / agent name recorded in the audit comment.")] = "AI SOC Agent (MCP)",
    ) -> dict[str, Any]:
        """Change an incident's status, severity, classification, or labels in its Sentinel
        workspace. Closing an incident is a significant action: confirm with the analyst
        first and always supply a ``classification`` (and ideally a reason/comment). An
        audit comment is posted automatically."""
        if status == "Closed" and not classification:
            return {
                "error": "CLASSIFICATION_REQUIRED",
                "hint": "Closing requires classification: TruePositive, FalsePositive, BenignPositive, or Undetermined.",
            }
        result = await sentinel_client.update_status(
            incident_ref,
            status=status,
            severity=severity,
            classification=classification,
            classification_reason=classification_reason,
            classification_comment=classification_comment,
            labels=labels,
            updated_by=updated_by,
        )
        return result if result.get("status") != "NOT_FOUND" else _not_found(incident_ref)

    @mcp.tool(name="sentinel_assign_incident", title="Assign incident", annotations=WRITE_SAFE)
    async def sentinel_assign_incident(
        incident_ref: Annotated[str, Field(description="Namespaced incident ref '<workspace_id>::<incident_guid>'.", min_length=1)],
        user_upn: Annotated[Optional[str], Field(description="UPN/email of the assignee (from sentinel_list_tenant_users). Omit all user fields to unassign.")] = None,
        user_name: Annotated[Optional[str], Field(description="Display name of the assignee.")] = None,
        user_id: Annotated[Optional[str], Field(description="Entra object id of the assignee, if known.")] = None,
        assigned_by: Annotated[str, Field(description="Who performed the assignment (audit comment).")] = "AI SOC Agent (MCP)",
    ) -> dict[str, Any]:
        """Assign an incident to a SOC engineer in its tenant, or unassign it when no user
        fields are given. Posts an audit comment on the incident."""
        result = await sentinel_client.assign_incident(
            incident_ref,
            user_id=user_id,
            user_name=user_name,
            user_email=user_upn,
            user_upn=user_upn,
            assigned_by=assigned_by,
        )
        return result if result.get("status") != "NOT_FOUND" else _not_found(incident_ref)

    @mcp.tool(name="sentinel_remediate_incident", title="Execute remediation action", annotations=WRITE_DESTRUCTIVE)
    async def sentinel_remediate_incident(
        incident_ref: Annotated[str, Field(description="Namespaced incident ref '<workspace_id>::<incident_guid>'.", min_length=1)],
        action_type: Annotated[str, Field(
            description="One of: isolate_endpoint, block_ip, trigger_playbook, close_false_positive, revoke_sessions, disable_account.",
            pattern="^(isolate_endpoint|block_ip|trigger_playbook|close_false_positive|revoke_sessions|disable_account)$",
        )],
        entity: Annotated[str, Field(description="Target entity: device name, IP address, or user UPN depending on the action.", min_length=1)],
        parameters: Annotated[Optional[dict[str, Any]], Field(description="Action parameters, e.g. {\"playbook_name\": \"...\"} or {\"reason\": \"...\"}.")] = None,
        analyst_name: Annotated[str, Field(description="Analyst / agent executing the action (audit trail).")] = "AI SOC Agent (MCP)",
    ) -> dict[str, Any]:
        """Execute a containment / remediation action for an incident and record an audit
        comment on it. DESTRUCTIVE: confirm with the analyst before calling.

        isolate_endpoint, block_ip, trigger_playbook and close_false_positive work across
        all delegated tenants (ARM / Defender). revoke_sessions and disable_account need
        Microsoft Graph access to the incident's tenant: for 'log-analytics-only' workspaces
        they return status BLOCKED_GRAPH_SCOPE with guidance instead of pretending success.
        """
        incident = await sentinel_client.get_incident(incident_ref)
        if not incident:
            return _not_found(incident_ref)
        return await remediation_service.execute_remediation(
            incident_id=incident["id"],
            action_type=action_type,
            entity=entity,
            analyst_name=analyst_name,
            parameters=parameters,
        )


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
    args = parser.parse_args(argv)

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
