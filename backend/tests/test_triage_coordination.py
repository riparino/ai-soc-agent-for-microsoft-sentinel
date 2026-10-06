"""
Race-condition protection between analysts: claim-on-triage, dedupe of recent
AI triage, and ETag-conditional writes (CONFLICT instead of last-writer-wins).
Runs on the mock path, which emulates ARM etags.
"""

import pytest

from app.config import settings
from app.services import triage_coordinator as coord
from app.services.sentinel_client import MOCK_INCIDENTS, sentinel_client
from app.services.workspace_registry import workspace_registry

ANA = {"kind": "user", "name": "Ana Lyst", "upn": "ana@mssp.example", "email": "ana@mssp.example", "object_id": "11111111-aaaa-4bbb-8ccc-dddddddddddd"}
BOB = {"kind": "user", "name": "Bob Blue", "upn": "bob@mssp.example", "email": "bob@mssp.example", "object_id": "22222222-aaaa-4bbb-8ccc-dddddddddddd"}


@pytest.fixture(autouse=True)
def _fresh_incident():
    """Use the Fabrikam incident (not touched by other suites' triage), reset ownership
    and strip prior AI triage comments so each test starts unassigned and untriaged."""
    settings.WORKSPACES_JSON = None
    settings.WORKSPACES_CONFIG_PATH = None
    workspace_registry.reload()
    inc = next(m for m in MOCK_INCIDENTS if m["incidentNumber"] == 9044)
    inc["assignedTo"] = None
    inc["owner"] = {}
    inc["comments"] = [c for c in inc.get("comments", []) if not str(c.get("message", "")).startswith(coord.AI_TRIAGE_COMMENT_MARKER)]
    yield "fabrikam::inc-2026-9044"
    inc["assignedTo"] = None
    inc["owner"] = {}
    inc["comments"] = [c for c in inc.get("comments", []) if not str(c.get("message", "")).startswith(coord.AI_TRIAGE_COMMENT_MARKER)]


def _mock(ref):
    return next(m for m in MOCK_INCIDENTS if m["id"] == ref.split("::", 1)[1])


# ------------------------------------------------------------- claim
@pytest.mark.asyncio
async def test_triage_claims_unassigned_incident_for_the_analyst(_fresh_incident):
    ref = _fresh_incident
    report = await coord.run_coordinated_triage(ref, actor=ANA, claim=True)
    assert "verdict" in report
    assert report["coordination"]["claimed"] is True
    inc = await sentinel_client.get_incident(ref)
    assert inc["owner"]["userPrincipalName"] == "ana@mssp.example"
    assert inc["owner"]["objectId"] == ANA["object_id"]
    assert inc["assignedTo"] == "Ana Lyst"


@pytest.mark.asyncio
async def test_second_analyst_is_refused_not_duplicated(_fresh_incident):
    ref = _fresh_incident
    await coord.run_coordinated_triage(ref, actor=ANA, claim=True)
    comments_before = len(_mock(ref)["comments"])

    res = await coord.run_coordinated_triage(ref, actor=BOB, claim=True)
    assert res["status"] == "ALREADY_ASSIGNED"
    assert res["owner"]["userPrincipalName"] == "ana@mssp.example"
    assert len(_mock(ref)["comments"]) == comments_before        # no second report posted
    assert _mock(ref)["assignedTo"] == "Ana Lyst"               # ownership untouched


@pytest.mark.asyncio
async def test_owner_rerun_is_deduped_then_forced(_fresh_incident):
    ref = _fresh_incident
    await coord.run_coordinated_triage(ref, actor=ANA, claim=True)
    again = await coord.run_coordinated_triage(ref, actor=ANA, claim=True)
    assert again["status"] == "RECENTLY_TRIAGED"
    assert again["triaged_at"]
    forced = await coord.run_coordinated_triage(ref, actor=ANA, claim=True, force=True)
    assert "verdict" in forced
    assert forced["coordination"]["owner"]["userPrincipalName"] == "ana@mssp.example"


@pytest.mark.asyncio
async def test_force_never_steals_ownership(_fresh_incident):
    ref = _fresh_incident
    await coord.run_coordinated_triage(ref, actor=ANA, claim=True)
    forced = await coord.run_coordinated_triage(ref, actor=BOB, claim=True, force=True)
    assert "verdict" in forced
    assert forced["coordination"]["claimed"] is False
    assert _mock(ref)["assignedTo"] == "Ana Lyst"


@pytest.mark.asyncio
async def test_no_identity_cannot_claim_but_still_dedupes(_fresh_incident):
    ref = _fresh_incident
    first = await coord.run_coordinated_triage(ref, actor=None, claim=True)
    assert "verdict" in first and first["coordination"]["claimed"] is False
    assert "claim_skipped" in first["coordination"]
    assert _mock(ref)["assignedTo"] is None
    second = await coord.run_coordinated_triage(ref, actor=None, claim=True)
    assert second["status"] == "RECENTLY_TRIAGED"


@pytest.mark.asyncio
async def test_dedupe_window_can_be_disabled(_fresh_incident):
    ref = _fresh_incident
    await coord.run_coordinated_triage(ref, actor=None, claim=False, dedupe=False)
    again = await coord.run_coordinated_triage(ref, actor=None, claim=False, dedupe=False)
    assert "verdict" in again


# ------------------------------------------------------ conditional writes
@pytest.mark.asyncio
async def test_claim_assign_refuses_when_owned_by_someone_else(_fresh_incident):
    ref = _fresh_incident
    first = await sentinel_client.assign_incident(ref, user_name="Ana Lyst", user_upn="ana@mssp.example", only_if_unassigned=True)
    assert first["status"] == "SUCCESS"
    second = await sentinel_client.assign_incident(ref, user_name="Bob Blue", user_upn="bob@mssp.example", only_if_unassigned=True)
    assert second["status"] == "ALREADY_ASSIGNED"
    assert second["owner"]["assignedTo"] == "Ana Lyst"
    # Re-claiming your own incident is fine (idempotent for the owner).
    again = await sentinel_client.assign_incident(ref, user_name="Ana Lyst", user_upn="ana@mssp.example", only_if_unassigned=True)
    assert again["status"] == "SUCCESS"
    # Taking over deliberately (no only_if_unassigned) still works.
    takeover = await sentinel_client.assign_incident(ref, user_name="Bob Blue", user_upn="bob@mssp.example")
    assert takeover["status"] == "SUCCESS" and _mock(ref)["assignedTo"] == "Bob Blue"


@pytest.mark.asyncio
async def test_stale_etag_yields_conflict_not_overwrite(_fresh_incident):
    ref = _fresh_incident
    inc = await sentinel_client.get_incident(ref)
    stale = inc["etag"]
    # Someone else changes the incident (etag moves on).
    bump = await sentinel_client.update_status(ref, status="Active", updated_by="Bob Blue")
    assert bump["status"] == "SUCCESS"
    assert (await sentinel_client.get_incident(ref))["etag"] != stale

    res = await sentinel_client.update_status(ref, status="Closed", classification="FalsePositive", expected_etag=stale)
    assert res["status"] == "CONFLICT" and "current_etag" in res
    assert _mock(ref)["status"] == "Active"                     # the stale write did not land

    res2 = await sentinel_client.assign_incident(ref, user_name="Ana Lyst", user_upn="ana@mssp.example", expected_etag=stale)
    assert res2["status"] == "CONFLICT"
    assert _mock(ref)["assignedTo"] is None

    fresh = (await sentinel_client.get_incident(ref))["etag"]
    ok = await sentinel_client.update_status(ref, status="New", expected_etag=fresh)
    assert ok["status"] == "SUCCESS"


# --------------------------------------------------------------- over MCP
@pytest.mark.asyncio
async def test_mcp_triage_reports_already_assigned(monkeypatch, _fresh_incident):
    import json
    from mcp.shared.memory import create_connected_server_and_client_session
    from app.mcp_server import create_server
    from app.services import azure_credentials as creds

    ref = _fresh_incident
    # Bob owns it already (set directly, as if from the portal).
    await sentinel_client.assign_incident(ref, user_name="Bob Blue", user_upn="bob@mssp.example")
    # The MCP server runs as Ana.
    monkeypatch.setattr(sentinel_client, "credential", object())
    monkeypatch.setattr(creds, "get_signed_in_identity", lambda cred, refresh=False: ANA)

    server = create_server(auth_mode="none")
    async with create_connected_server_and_client_session(server) as session:
        res = await session.call_tool("sentinel_triage_incident", {"incident_ref": ref})
        data = res.structuredContent or json.loads(res.content[0].text)
        assert data["status"] == "ALREADY_ASSIGNED"
        assert data["owner"]["userPrincipalName"] == "bob@mssp.example"

        tools = {t.name: t for t in (await session.list_tools()).tools}
        props = tools["sentinel_triage_incident"].inputSchema["properties"]
        assert props["claim"]["type"] == "boolean" and props["force"]["type"] == "boolean"
        assert "expected_etag" in tools["sentinel_update_incident_status"].inputSchema["properties"]
        assert "only_if_unassigned" in tools["sentinel_assign_incident"].inputSchema["properties"]
