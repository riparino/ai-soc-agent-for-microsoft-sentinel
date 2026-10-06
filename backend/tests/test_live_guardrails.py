"""Live mode (DEMO_MODE=False) must never serve sample data: every failure is a
structured, analyst-readable error, and triage without a server LLM returns an
evidence pack rather than an invented verdict."""
import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from app.config import settings
from app.mcp_server import create_server
from app.services import sentinel_client as sc_mod
from app.services.errors import SocError, classify_http, from_exception
from app.services.sentinel_client import MOCK_INCIDENTS, sentinel_client
from app.services.threat_intel import threat_intel_service
from app.services.workspace_registry import workspace_registry
from tests.test_mcp_server import _call  # noqa: F401


async def _async(v):
    return v


@pytest.fixture
def live(monkeypatch):
    """Live mode, nothing configured."""
    monkeypatch.setattr(settings, "DEMO_MODE", False)
    monkeypatch.setattr(settings, "WORKSPACES_JSON", None)
    monkeypatch.setattr(settings, "WORKSPACES_CONFIG_PATH", None)
    workspace_registry.reload()
    yield
    monkeypatch.setattr(settings, "DEMO_MODE", True)
    workspace_registry.reload()


@pytest.fixture
def live_with_fleet(live, monkeypatch):
    monkeypatch.setattr(settings, "WORKSPACES_JSON", '[{"id":"acme","display_name":"Acme","tenant_id":"t","subscription_id":"s","resource_group":"rg","workspace_name":"acme-sentinel"}]')
    workspace_registry.reload()
    yield


# ------------------------------------------------------------ error contract
def test_classify_http_messages_are_actionable():
    class WS:
        id, subscription_id, resource_group, workspace_name = "acme", "sub-1", "rg-1", "acme-sentinel"
    e403 = classify_http(403, "AuthorizationFailed", workspace=WS(), actor={"upn": "ana@mssp.example"})
    assert e403.code == "FORBIDDEN" and "ana@mssp.example" in e403.tell_admin and "sub-1" in e403.tell_admin
    assert classify_http(401, "").code == "NOT_AUTHENTICATED"
    assert classify_http(404, "", workspace=WS(), resource="workspace").code == "WORKSPACE_NOT_FOUND"
    assert classify_http(404, "", workspace=WS(), incident_ref="acme::x").code == "INCIDENT_NOT_FOUND"
    assert classify_http(429, "").code == "THROTTLED" and classify_http(503, "").code == "AZURE_UNAVAILABLE"
    assert {"error", "message", "what_to_check", "tell_admin", "workspace", "http_status"} <= set(e403.to_dict())


def test_from_exception_maps_network_and_auth():
    assert from_exception(httpx.ConnectError("boom")).code == "NETWORK"
    assert from_exception(httpx.ReadTimeout("slow")).code == "NETWORK_TIMEOUT"
    assert from_exception(RuntimeError("Please run 'az login' to set up account")).code == "NOT_AUTHENTICATED"
    assert from_exception(ValueError("x")).code == "UNEXPECTED"


# --------------------------------------------------------- no fleet / no auth
@pytest.mark.asyncio
async def test_live_without_fleet_is_fleet_not_configured(live):
    assert workspace_registry.list_workspaces() == []
    with pytest.raises(SocError) as ei:
        await sentinel_client.list_incidents()
    assert ei.value.code == "FLEET_NOT_CONFIGURED"
    with pytest.raises(SocError) as ei:
        await sentinel_client.get_incident("acme::inc-1")
    assert ei.value.code == "FLEET_NOT_CONFIGURED"


@pytest.mark.asyncio
async def test_live_without_credentials_never_returns_mock(live_with_fleet, monkeypatch):
    monkeypatch.setattr(sentinel_client, "is_live", False)
    monkeypatch.setattr(sentinel_client, "credential", None)
    monkeypatch.setattr(sentinel_client, "_init_client", lambda: None)
    for coro in (
        sentinel_client.list_incidents(),
        sentinel_client.get_incident("acme::inc-2026-9041"),
        sentinel_client.add_comment("acme::inc-2026-9041", "x"),
        sentinel_client.update_status("acme::inc-2026-9041", "Active"),
        sentinel_client.assign_incident("acme::inc-2026-9041", user_upn="a@b.c"),
    ):
        with pytest.raises(SocError) as ei:
            await coro
        assert ei.value.code == "NOT_AUTHENTICATED", ei.value.to_dict()
        assert any("az login" in w for w in ei.value.what_to_check)
    assert all(not any(c.get("message") == "x" for c in m.get("comments", [])) for m in MOCK_INCIDENTS)


# ------------------------------------------------- per-workspace 403 reporting
class _Resp:
    def __init__(self, status, payload=None, text=""):
        self.status_code, self._payload, self.text = status, payload, text or ""

    def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_list_reports_forbidden_workspace_and_keeps_others(live, monkeypatch):
    monkeypatch.setattr(settings, "WORKSPACES_JSON", '[{"id":"good","display_name":"Good","subscription_id":"s","resource_group":"rg","workspace_name":"g"},'
                                                     '{"id":"bad","display_name":"Bad","subscription_id":"s","resource_group":"rg","workspace_name":"b"}]')
    workspace_registry.reload()
    monkeypatch.setattr(sentinel_client, "is_live", True)
    monkeypatch.setattr(sentinel_client, "_get_arm_token", lambda: "tok")

    async def fake_get(self, url, headers=None, **kw):
        if "/workspaces/b/" in url:
            return _Resp(403, text='{"error":{"code":"AuthorizationFailed"}}')
        return _Resp(200, {"value": [{"name": "i1", "properties": {"incidentNumber": 1, "title": "T", "severity": "High", "status": "New",
                                                                   "createdTimeUtc": "2026-10-01T00:00:00Z", "owner": {}}}]})

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(sc_mod.SentinelClient, "_fetch_incident_entities_and_comments", lambda *a, **k: _async(([], [], [])))
    res = await sentinel_client.list_incidents_detailed()
    assert [i["workspaceId"] for i in res["incidents"]] == ["good"]
    assert res["incidents"][0]["alerts"] == []
    assert len(res["errors"]) == 1 and res["errors"][0]["error"] == "FORBIDDEN" and res["errors"][0]["workspace"] == "bad"
    assert "tell_admin" in res["errors"][0]


# ------------------------------------------------------------- threat intel
@pytest.mark.asyncio
async def test_threat_intel_live_without_keys_is_not_configured(live, monkeypatch):
    monkeypatch.setattr(threat_intel_service, "abuseipdb_key", None)
    monkeypatch.setattr(threat_intel_service, "virustotal_key", None)
    ip = await threat_intel_service.lookup_ip_reputation("185.220.101.5")
    assert ip["status"] == "NOT_CONFIGURED" and ip["verdict"] == "UNKNOWN" and "abuse_confidence_score" not in ip
    h = await threat_intel_service.lookup_file_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert h["status"] == "NOT_CONFIGURED" and h["verdict"] == "UNKNOWN"
    assert (await threat_intel_service.lookup_ip_reputation("10.1.2.3"))["verdict"] == "BENIGN_INTERNAL"


# -------------------------------------------------- triage: evidence, no verdict
@pytest.mark.asyncio
async def test_triage_without_llm_returns_evidence_pack(live_with_fleet, monkeypatch):
    from app.agent.triage_agent import triage_agent
    from app.services.kql_runner import kql_runner

    monkeypatch.setattr(triage_agent, "openai_client", None)
    monkeypatch.setattr(threat_intel_service, "abuseipdb_key", None)
    posted = []

    async def fake_comment(*a, **k):
        posted.append(a)
        return {"status": "SUCCESS"}

    async def fake_tables(ws=None, days=7, force_refresh=False):
        return [{"table": "SigninLogs"}]

    async def fake_kql(query, timespan_hours=24, workspace=None):
        return {"status": "ERROR", "error_type": "FORBIDDEN", "error": "no query permission", "tables": [], "row_count": 0}

    monkeypatch.setattr(sentinel_client, "add_comment", fake_comment)
    monkeypatch.setattr(kql_runner, "list_tables", fake_tables)
    monkeypatch.setattr(kql_runner, "execute_kql", fake_kql)
    incident = {**MOCK_INCIDENTS[0], "id": "acme::inc-x", "workspaceId": "acme", "workspaceName": "Acme"}
    report = await triage_agent.triage_incident(incident)
    assert report["status"] == "EVIDENCE_COLLECTED" and report["verdict"] is None
    assert report["kql_findings"] and all(f["status"] == "ERROR" and f["error_type"] == "FORBIDDEN" for f in report["kql_findings"])
    assert report["kql_queries_used"] == []
    assert all(t.get("status") in ("NOT_CONFIGURED", "SUCCESS") for t in report["threat_intel"].values())
    assert posted == []


# --------------------------------------------------------------- MCP guard
@pytest.mark.asyncio
async def test_mcp_tool_returns_structured_error_instead_of_raising(monkeypatch):
    monkeypatch.setattr(settings, "DEMO_MODE", True)
    workspace_registry.reload()

    async def boom(ref):
        raise classify_http(403, "AuthorizationFailed", workspace=workspace_registry.get("fabrikam"), incident_ref=ref)

    monkeypatch.setattr(sentinel_client, "get_incident", boom)
    server = create_server(auth_mode="none")
    async with create_connected_server_and_client_session(server) as session:
        res = await _call(session, "sentinel_get_incident", incident_ref="fabrikam::inc-2026-9044")
        res2 = await _call(session, "sentinel_extract_indicators", incident_ref="fabrikam::inc-2026-9044")
    assert res["error"] == "FORBIDDEN" and res["workspace"] == "fabrikam" and res["tell_admin"]
    assert res2["error"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_mcp_unexpected_exception_is_wrapped(monkeypatch):
    monkeypatch.setattr(settings, "DEMO_MODE", True)
    workspace_registry.reload()

    async def boom(ref):
        raise ValueError("kaboom")

    monkeypatch.setattr(sentinel_client, "get_incident", boom)
    server = create_server(auth_mode="none")
    async with create_connected_server_and_client_session(server) as session:
        res = await _call(session, "sentinel_get_incident", incident_ref="contoso::inc-2026-9041")
    assert res["error"] == "UNEXPECTED" and "kaboom" in res["detail"] and res["tell_admin"]
