"""One error contract for everything the analyst sees.

Every failure that reaches an MCP tool result is a ``SocError`` rendered as::

    {"error": "<CODE>", "message": "...", "what_to_check": [...], "tell_admin": "...",
     "workspace": "...", "incident_ref": "...", "http_status": 403, "detail": "..."}

``message`` says what happened in plain words, ``what_to_check`` is what the analyst
can do themselves, and ``tell_admin`` is the exact sentence to send the SOC admin
when it is not something the analyst can fix. Nothing in here ever substitutes
sample data for a failed call.
"""
from __future__ import annotations

from typing import Any, Optional

AZ_LOGIN = "az login --tenant <managing-tenant-id>   (then re-run: ./run-mcp.sh --check)"


class SocError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        what_to_check: Optional[list[str]] = None,
        tell_admin: Optional[str] = None,
        workspace: Optional[str] = None,
        incident_ref: Optional[str] = None,
        http_status: Optional[int] = None,
        detail: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.what_to_check = what_to_check or []
        self.tell_admin = tell_admin
        self.workspace = workspace
        self.incident_ref = incident_ref
        self.http_status = http_status
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"error": self.code, "message": self.message}
        if self.what_to_check:
            out["what_to_check"] = self.what_to_check
        if self.tell_admin:
            out["tell_admin"] = self.tell_admin
        if self.workspace:
            out["workspace"] = self.workspace
        if self.incident_ref:
            out["incident_ref"] = self.incident_ref
        if self.http_status is not None:
            out["http_status"] = self.http_status
        if self.detail:
            out["detail"] = str(self.detail)[:1500]
        return out


def _who(actor: Optional[dict[str, Any]]) -> str:
    if actor and (actor.get("upn") or actor.get("name")):
        return str(actor.get("upn") or actor.get("name"))
    return "my account"


def auth_error(detail: Optional[str] = None) -> SocError:
    return SocError(
        "NOT_AUTHENTICATED",
        "No usable Azure sign-in: the server could not obtain a token for Azure Resource Manager.",
        what_to_check=[
            f"Sign in to the managing tenant: {AZ_LOGIN}",
            "Check `az account show` reports the managing tenant and your own account.",
            "Confirm backend/.env has DEMO_MODE=False and AZURE_AUTH_MODE=user.",
        ],
        detail=detail,
    )


def fleet_not_configured() -> SocError:
    return SocError(
        "FLEET_NOT_CONFIGURED",
        "No customer workspaces are configured (workspaces.json missing or empty).",
        what_to_check=[
            "Generate it: ./run-mcp.sh --discover-workspaces   (Windows: .\\run-mcp.ps1 --discover-workspaces)",
            "Confirm WORKSPACES_CONFIG_PATH in backend/.env points at that file (default ./workspaces.json).",
        ],
    )


def workspace_unknown(workspace_id: Optional[str]) -> SocError:
    return SocError(
        "WORKSPACE_UNKNOWN",
        f"'{workspace_id}' is not a workspace id in your fleet file.",
        what_to_check=[
            "Use sentinel_list_workspaces for the valid ids.",
            "If the customer is new, re-run ./run-mcp.sh --discover-workspaces.",
        ],
        workspace=workspace_id,
    )


def classify_http(
    status: int,
    text: str = "",
    *,
    workspace: Optional[Any] = None,
    incident_ref: Optional[str] = None,
    actor: Optional[dict[str, Any]] = None,
    resource: str = "incident",
) -> SocError:
    """Map an Azure Resource Manager response into an analyst-facing error."""
    ws_id = getattr(workspace, "id", None) or (workspace if isinstance(workspace, str) else None)
    ws_desc = ""
    if workspace is not None and hasattr(workspace, "subscription_id"):
        ws_desc = (
            f" (subscription {workspace.subscription_id}, resource group {workspace.resource_group}, "
            f"workspace {workspace.workspace_name})"
        )
    who = _who(actor)
    snippet = (text or "")[:600]

    if status == 401:
        return SocError(
            "NOT_AUTHENTICATED", "Azure rejected the token (401): your sign-in has expired or is for the wrong tenant.",
            what_to_check=[f"Sign in again: {AZ_LOGIN}", "Tools keep failing with 401 until you re-run az login."],
            workspace=ws_id, incident_ref=incident_ref, http_status=401, detail=snippet,
        )
    if status == 403:
        return SocError(
            "FORBIDDEN",
            f"Azure refused the call (403): {who} has no Microsoft Sentinel Responder access on workspace '{ws_id}'.",
            what_to_check=[
                "Confirm `az account show` is the managing tenant, not a customer tenant.",
                "Check you are still a member of the Lighthouse analyst group.",
                "If other workspaces work and only this one fails, it is the customer's delegation, not your setup.",
            ],
            tell_admin=(
                f"Workspace '{ws_id}'{ws_desc} returns 403 for {who}. The Lighthouse delegation for this customer "
                "does not authorize our analyst group with Microsoft Sentinel Responder (or the role assignment was removed)."
            ),
            workspace=ws_id, incident_ref=incident_ref, http_status=403, detail=snippet,
        )
    if status == 404:
        if resource == "incident":
            return SocError(
                "INCIDENT_NOT_FOUND", f"Incident {incident_ref or ''} does not exist in workspace '{ws_id}' (404).",
                what_to_check=["Use the exact ref from sentinel_list_incidents; it may have been deleted or merged."],
                workspace=ws_id, incident_ref=incident_ref, http_status=404, detail=snippet,
            )
        return SocError(
            "WORKSPACE_NOT_FOUND",
            f"Workspace '{ws_id}' was not found in Azure (404): the subscription, resource group or workspace name in your fleet file is stale.",
            what_to_check=["Re-run ./run-mcp.sh --discover-workspaces to refresh workspaces.json, then --check."],
            tell_admin=f"Workspace '{ws_id}'{ws_desc} returns 404 after re-discovery: it may have been renamed, moved or offboarded.",
            workspace=ws_id, incident_ref=incident_ref, http_status=404, detail=snippet,
        )
    if status in (409, 412):
        return SocError(
            "CONFLICT", "Someone changed this incident a moment ago; the write was not applied.",
            what_to_check=["Re-read the incident (sentinel_get_incident) and retry if still appropriate."],
            workspace=ws_id, incident_ref=incident_ref, http_status=status, detail=snippet,
        )
    if status == 429:
        return SocError(
            "THROTTLED", "Azure is rate-limiting requests (429). Wait a minute and retry.",
            what_to_check=["Narrow the request (one workspace instead of 'all', fewer incidents)."],
            workspace=ws_id, incident_ref=incident_ref, http_status=429, detail=snippet,
        )
    if status >= 500:
        return SocError(
            "AZURE_UNAVAILABLE", f"Azure returned HTTP {status}; the service is having trouble, not your setup.",
            what_to_check=["Retry in a few minutes.", "Check https://status.azure.com for Microsoft Sentinel / Azure Resource Manager."],
            workspace=ws_id, incident_ref=incident_ref, http_status=status, detail=snippet,
        )
    return SocError(
        "AZURE_ERROR", f"Azure returned HTTP {status} for workspace '{ws_id}'.",
        what_to_check=["Read `detail` below; if it is unclear, send the whole error block to the SOC admin."],
        tell_admin=f"Unexpected HTTP {status} from ARM on workspace '{ws_id}'{ws_desc}: {snippet[:200]}",
        workspace=ws_id, incident_ref=incident_ref, http_status=status, detail=snippet,
    )


def from_exception(exc: BaseException, *, workspace: Optional[Any] = None, incident_ref: Optional[str] = None) -> SocError:
    """Turn an unexpected exception into the error contract (network, auth, bugs)."""
    if isinstance(exc, SocError):
        return exc
    ws_id = getattr(workspace, "id", None) or (workspace if isinstance(workspace, str) else None)
    name = type(exc).__name__
    text = f"{name}: {exc}"
    low = text.lower()
    try:
        import httpx

        if isinstance(exc, httpx.TimeoutException):
            return SocError(
                "NETWORK_TIMEOUT", "Azure did not answer in time.",
                what_to_check=["Retry once.", "If you are on VPN / a proxy, check it allows management.azure.com and api.loganalytics.io."],
                workspace=ws_id, incident_ref=incident_ref, detail=text,
            )
        if isinstance(exc, (httpx.ConnectError, httpx.NetworkError)):
            return SocError(
                "NETWORK", "Could not reach Azure (connection failed).",
                what_to_check=["Check internet / VPN / proxy; the server needs HTTPS to management.azure.com, login.microsoftonline.com and api.loganalytics.io."],
                workspace=ws_id, incident_ref=incident_ref, detail=text,
            )
    except Exception:  # noqa: BLE001 - httpx import is best effort
        pass
    if "clientauthenticationerror" in low or "credentialunavailable" in low or "az login" in low or "aadsts" in low:
        return auth_error(text)
    return SocError(
        "UNEXPECTED", f"The server hit an unexpected error ({name}). This is a bug or an environment problem, not something you did.",
        what_to_check=["Re-run ./run-mcp.sh --check and send its output plus this error block to the SOC admin."],
        tell_admin=f"Unexpected {name} in the MCP server" + (f" on workspace '{ws_id}'" if ws_id else "") + f": {str(exc)[:300]}",
        workspace=ws_id, incident_ref=incident_ref, detail=text,
    )
