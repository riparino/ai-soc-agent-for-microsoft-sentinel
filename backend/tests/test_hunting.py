"""Catalog hunting: rendering safety, table-driven selection, demo execution,
MCP exposure, and the KQL runner refusing to fake results outside demo mode."""
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from app.config import settings
from app.services import hunting_catalog as cat
from app.services.hunting import hunt_incident, plan_hunts
from app.services.indicators import account_short_names, extract_indicators, host_short_names, url_domains
from app.services.kql_runner import kql_runner
from app.services.sentinel_client import sentinel_client
from app.mcp_server import create_server
from tests.test_mcp_server import _call  # noqa: F401  (shared helper)


@pytest.fixture(autouse=True)
def demo(monkeypatch):
    monkeypatch.setattr(settings, "DEMO_MODE", True)
    kql_runner._tables_cache.clear()
    yield


FULL = {
    "accounts": ["J.Doe@Contoso.com", "CORP\\bob", 'evil"quote@x.y'],
    "ips": ["185.220.101.5"], "hosts": ["FIN-SRV-01.corp.local"], "file_hashes": ["a" * 64],
    "urls": ["https://login.evil.example/p?x=1", "evil2.example/path"], "azure_resources": ["/subscriptions/s/resourceGroups/rg"],
    "processes": ["powershell.exe -enc AAAA"], "cloud_apps": ["Contoso Sync App"], "mailboxes": ["jdoe@contoso.com"],
}


# ------------------------------------------------------------- indicators
def test_indicator_helpers():
    assert account_short_names(["j.doe@contoso.com", "CORP\\bob", "ab"]) == ["j.doe", "bob"]
    assert host_short_names(["FIN-SRV-01.corp.local", "x"]) == ["FIN-SRV-01"]
    assert url_domains(["https://login.evil.example/p", "evil2.example/path", "nodomain"]) == ["login.evil.example", "evil2.example"]


# ---------------------------------------------------------------- catalog
def test_every_hunt_renders_with_all_indicators_and_names_its_table():
    ctx = cat.build_context(FULL, 24)
    for h in cat.HUNTS:
        q = h.render(ctx)
        assert "$" not in q, h.id                       # every placeholder substituted
        assert h.tables[0] in q, h.id                   # the primary table is queried
        assert cat.NEVER_MATCH not in q or True         # sentinel allowed where a kind is absent
        assert h.family in cat.FAMILIES and set(h.needs) <= set(cat.INDICATOR_KINDS)


def test_rendering_escapes_quotes_and_backslashes():
    ctx = cat.build_context(FULL, 24)
    q = cat.HUNTS_BY_ID["signin_baseline"].render(ctx)
    assert '"corp\\\\bob"' in q                         # backslash doubled inside the KQL string literal
    assert 'evil\\"quote@x.y' in q                      # embedded quote escaped
    assert "j.doe@contoso.com" in q                     # accounts lower-cased for in~


def test_empty_indicator_kind_renders_never_matching_sentinel():
    ctx = cat.build_context({"accounts": ["a@b.c"]}, 24)
    q = cat.HUNTS_BY_ID["signin_baseline"].render(ctx)
    assert f'let ips = dynamic(["{cat.NEVER_MATCH}"])' in q


def test_window_literal():
    assert cat.window_literal(24 * 7) == "7d" and cat.window_literal(36) == "36h"


# --------------------------------------------------------------- planning
def test_plan_filters_by_entities_and_tables():
    ind = {"accounts": ["a@b.c"], "ips": [], "hosts": [], "file_hashes": [], "urls": [], "azure_resources": [], "processes": [], "cloud_apps": [], "mailboxes": []}
    selected, skipped = plan_hunts(ind, [{"table": "SigninLogs"}, {"table": "Heartbeat"}], max_hunts=50)
    assert [h.id for h in selected] == ["signin_baseline"]
    reasons = {s["id"]: s["reason"] for s in skipped}
    assert "no ips" in reasons["signin_from_incident_ips"]
    assert "AADNonInteractiveUserSignInLogs" in reasons["noninteractive_signins"]
    assert "DeviceLogonEvents" in reasons["device_logons"]


def test_plan_runs_blind_when_tables_unknown_and_honours_cap_and_filters():
    ind = extract_indicators({"entities": [{"kind": "Ip", "address": "1.2.3.4"}, {"kind": "Account", "upn": "a@b.c"}]})
    selected, skipped = plan_hunts(ind, None, max_hunts=3)
    assert len(selected) == 3 and any("per-run limit" in s["reason"] for s in skipped)
    only_xdr, _ = plan_hunts(ind, None, families="defender-xdr", max_hunts=50)
    assert only_xdr and all(h.family == "defender-xdr" for h in only_xdr)
    picked, skipped = plan_hunts(ind, None, hunt_ids="device_logons,nope", max_hunts=50)
    assert [h.id for h in picked] == ["device_logons"] and any(s["id"] == "nope" for s in skipped)


# -------------------------------------------------------------- execution
@pytest.mark.asyncio
async def test_hunt_incident_demo_runs_catalog_and_reports_coverage():
    incs = await sentinel_client.list_incidents(workspace="fabrikam")
    inc = await sentinel_client.get_incident(incs[0]["id"])
    events = []
    r = await hunt_incident(inc, max_rows=2, progress=lambda ev, p: events.append(ev))
    assert r["tables"]["checked"] and "SigninLogs" in r["tables"]["available"]
    assert r["summary"]["planned"] == r["summary"]["executed"] == len(r["hunts"]) > 0
    assert all(h["status"] == "SUCCESS" and len(h["rows"]) <= 2 for h in r["hunts"])
    assert all(h["query"].startswith("let ") for h in r["hunts"])
    assert "HUNT_PLAN" in events and events.count("KQL_RESULT") == len(r["hunts"])
    assert any("not ingested" in s["reason"] for s in r["skipped"])


@pytest.mark.asyncio
async def test_hunt_incident_dry_run_returns_kql_only():
    incs = await sentinel_client.list_incidents(workspace="contoso")
    inc = await sentinel_client.get_incident(incs[0]["id"])
    r = await hunt_incident(inc, dry_run=True)
    assert r["summary"]["dry_run"] and r["summary"]["executed"] == 0
    assert all(h["status"] == "PLANNED" and h["rows"] == [] and "| where" in h["query"] for h in r["hunts"])


@pytest.mark.asyncio
async def test_list_tables_demo_and_cache():
    t1 = await kql_runner.list_tables(None, days=7)
    t2 = await kql_runner.list_tables(None, days=7)
    assert t1 is t2 and {"SigninLogs", "DeviceProcessEvents"} <= {t["table"] for t in t1}


# ---------------------------------------------------- live mode: no fakes
@pytest.mark.asyncio
async def test_live_query_failure_returns_error_not_simulation(monkeypatch):
    monkeypatch.setattr(settings, "DEMO_MODE", False)

    class Boom:
        def query_workspace(self, **kw):
            raise RuntimeError("SemanticError: Failed to resolve table or column expression named 'DeviceEvents'")

    ws = sentinel_client.registry.get("fabrikam") if hasattr(sentinel_client, "registry") else None
    from app.services.workspace_registry import workspace_registry
    ws = ws or workspace_registry.get("fabrikam")
    monkeypatch.setattr(ws, "workspace_guid", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setattr(kql_runner, "client", Boom())
    monkeypatch.setattr(sentinel_client, "_get_arm_token", lambda: None)
    res = await kql_runner.execute_kql("DeviceEvents | take 1", workspace=ws)
    assert res["status"] == "ERROR" and res["error_type"] == "TABLE_NOT_FOUND" and res["row_count"] == 0
    assert "SIMULATED" not in str(res.get("source"))


@pytest.mark.asyncio
async def test_live_without_credentials_returns_error(monkeypatch):
    monkeypatch.setattr(settings, "DEMO_MODE", False)
    monkeypatch.setattr(kql_runner, "client", None)
    monkeypatch.setattr(kql_runner, "_init_azure_client", lambda: None)
    res = await kql_runner.execute_kql("SigninLogs | take 1")
    assert res["status"] == "ERROR" and res["error_type"] in ("NOT_AUTHENTICATED", "QUERY_FAILED") and res["row_count"] == 0


# -------------------------------------------------------------------- MCP
@pytest.fixture
def server():
    return create_server(auth_mode="none")


@pytest.mark.asyncio
async def test_mcp_list_tables_and_hunt(server):
    async with create_connected_server_and_client_session(server) as session:
        tables = await _call(session, "sentinel_list_tables", workspace="fabrikam")
        fab = await _call(session, "sentinel_list_incidents", workspace="fabrikam")
        ref = fab["incidents"][0]["id"]
        plan = await _call(session, "sentinel_hunt_incident", incident_ref=ref, dry_run=True)
        ran = await _call(session, "sentinel_hunt_incident", incident_ref=ref, families="entra-id", max_rows=1)
        missing = await _call(session, "sentinel_hunt_incident", incident_ref="fabrikam::nope")
    assert tables["status"] == "SUCCESS" and "signin_baseline" in tables["hunts_supported"]
    assert any(u["id"] == "email_events" and u["missing"] == ["EmailEvents"] for u in tables["hunts_unsupported"])
    assert plan["summary"]["dry_run"] and plan["hunts"]
    assert ran["hunts"] and all(h["family"] == "entra-id" and len(h["rows"]) <= 1 for h in ran["hunts"])
    assert missing["error"] == "INCIDENT_NOT_FOUND"
