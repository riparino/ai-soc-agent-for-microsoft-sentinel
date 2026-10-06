"""Fleet discovery via Azure Resource Graph, fleet-path resolution, and the
--discover-workspaces / --check behaviour around a missing fleet file.
Resource Graph is never called: the query runner is replaced with canned rows."""

import json
import os

import pytest

from app.config import settings
from app.services import workspace_discovery as disc
from app.services import workspace_registry as reg
from app.services.sentinel_client import sentinel_client

WS_A = {"id": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.OperationalInsights/workspaces/contoso-sentinel",
        "name": "contoso-sentinel", "resourceGroup": "rg-a", "subscriptionId": "sub-a", "tenantId": "tenant-a",
        "location": "eastus", "customerId": "aaaaaaaa-1111-2222-3333-444444444444"}
WS_B = {"id": "/subscriptions/sub-b/resourceGroups/rg-b/providers/Microsoft.OperationalInsights/workspaces/fab-sentinel",
        "name": "fab-sentinel", "resourceGroup": "rg-b", "subscriptionId": "sub-b", "tenantId": "tenant-b",
        "location": "westeurope", "customerId": "bbbbbbbb-1111-2222-3333-444444444444"}
WS_B2 = {"id": "/subscriptions/sub-b/resourceGroups/rg-b/providers/Microsoft.OperationalInsights/workspaces/fab-ops-logs",
         "name": "fab-ops-logs", "resourceGroup": "rg-b", "subscriptionId": "sub-b", "tenantId": "tenant-b",
         "location": "westeurope", "customerId": "cccccccc-1111-2222-3333-444444444444"}
SUBS = [{"subscriptionId": "sub-a", "subscriptionName": "Contoso Production", "tenantId": "tenant-a"},
        {"subscriptionId": "sub-b", "subscriptionName": "Fabrikam Security", "tenantId": "tenant-b"}]
SENTINEL = [{"workspaceResourceId": WS_A["id"].lower()}, {"workspaceResourceId": WS_B["id"].lower()}]


def fake_runner(query: str, token: str):
    if query == disc.QUERY_WORKSPACES:
        return [WS_A, WS_B, WS_B2]
    if query == disc.QUERY_SUBSCRIPTIONS:
        return SUBS
    if query == disc.QUERY_SENTINEL_SOLUTIONS:
        return SENTINEL
    raise AssertionError(f"unexpected query {query!r}")


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(settings, "AZURE_TENANT_ID", "tenant-a")
    yield
    reg.workspace_registry.reload()


def test_discover_builds_sentinel_only_entries_with_customer_tenants():
    entries, stats = disc.discover("tok", query_runner=fake_runner)
    assert stats == {"log_analytics_workspaces": 3, "sentinel_workspaces": 2, "subscriptions": 2, "tenants": 2, "included": 2}
    by_name = {e["workspace_name"]: e for e in entries}
    assert set(by_name) == {"contoso-sentinel", "fab-sentinel"}          # fab-ops-logs is not Sentinel-enabled
    assert by_name["fab-sentinel"]["tenant_id"] == "tenant-b"              # the customer tenant, from Resource Graph
    assert by_name["fab-sentinel"]["workspace_guid"].startswith("bbbbbbbb")
    assert by_name["contoso-sentinel"]["is_managing_tenant"] is True       # matches AZURE_TENANT_ID
    assert by_name["contoso-sentinel"]["display_name"] == "Contoso Production"          # sole workspace in its subscription
    assert by_name["fab-sentinel"]["display_name"] == "Fabrikam Security (fab-sentinel)"  # one of several


def test_include_all_keeps_non_sentinel_workspaces():
    entries, _ = disc.discover("tok", include_all=True, query_runner=fake_runner)
    flags = {e["workspace_name"]: e["sentinel_enabled"] for e in entries}
    assert flags == {"contoso-sentinel": True, "fab-sentinel": True, "fab-ops-logs": False}


def test_merge_preserves_hand_edits_and_reports_missing():
    discovered, _ = disc.discover("tok", query_runner=fake_runner)
    existing = [
        {"id": "fabrikam", "display_name": "Fabrikam Inc", "subscription_id": "sub-b", "resource_group": "rg-b",
         "workspace_name": "fab-sentinel", "graph_tenant_id": "tenant-b", "graph_client_id": "app", "graph_client_secret": "s3cret"},
        {"id": "gone", "display_name": "Decommissioned Co", "subscription_id": "sub-z", "resource_group": "rg-z", "workspace_name": "zeta"},
    ]
    merged, summary = disc.merge_fleet(existing, discovered)
    ids = [e["id"] for e in merged]
    assert ids == ["fabrikam", "gone", "contoso-sentinel"]            # existing order first, new appended
    fab = merged[0]
    assert fab["display_name"] == "Fabrikam Inc" and fab["graph_client_secret"] == "s3cret"   # hand edits kept
    assert fab["workspace_guid"].startswith("bbbbbbbb") and fab["tenant_id"] == "tenant-b"    # coordinates refreshed
    assert summary == {"added": ["contoso-sentinel"], "updated": ["fabrikam"], "missing": ["gone"]}


def test_rendered_fleet_file_loads_in_registry(tmp_path, monkeypatch):
    entries, _ = disc.discover("tok", query_runner=fake_runner)
    path = tmp_path / "workspaces.json"
    path.write_text(disc.render_fleet_file(entries))
    monkeypatch.setattr(settings, "WORKSPACES_JSON", None)
    monkeypatch.setattr(settings, "WORKSPACES_CONFIG_PATH", str(path))
    reg.workspace_registry.reload()
    assert {w.id for w in reg.workspace_registry.list_workspaces()} == {"contoso-sentinel", "fab-sentinel"}
    assert reg.workspace_registry.get("fab-sentinel").graph_mode == "log-analytics-only"
    assert reg.workspace_registry.get("contoso-sentinel").graph_mode == "managing-tenant"


def test_relative_fleet_path_resolves_against_backend_dir(tmp_path, monkeypatch):
    """Claude Desktop launches the server from an arbitrary cwd; './workspaces.json'
    must still be found next to .env in the backend directory."""
    backend = tmp_path / "backend"; backend.mkdir()
    (backend / "workspaces.json").write_text(json.dumps([
        {"id": "only", "display_name": "Only Co", "subscription_id": "s", "resource_group": "r", "workspace_name": "w"}]))
    elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setattr(reg, "BACKEND_DIR", str(backend))
    monkeypatch.setattr(settings, "WORKSPACES_JSON", None)
    monkeypatch.setattr(settings, "WORKSPACES_CONFIG_PATH", "./workspaces.json")
    assert reg.resolve_fleet_path() == os.path.join(str(backend), "./workspaces.json")
    reg.workspace_registry.reload()
    assert [w.id for w in reg.workspace_registry.list_workspaces()] == ["only"]
    assert reg.workspace_registry._source.startswith("file:")


def test_cli_discover_dry_run_prints_fleet(monkeypatch, capsys):
    from app import mcp_server
    monkeypatch.setattr(settings, "DEMO_MODE", False)
    monkeypatch.setattr(sentinel_client, "is_live", True)
    monkeypatch.setattr(sentinel_client, "_get_arm_token", lambda: "tok")
    monkeypatch.setattr(disc, "run_arg_query", fake_runner)
    try:
        with pytest.raises(SystemExit) as exc:
            mcp_server.main(["--discover-workspaces", "--dry-run", "--fleet-out", "/nonexistent/dir/workspaces.json"])
    finally:
        monkeypatch.setattr(settings, "DEMO_MODE", True)
        sentinel_client._init_client()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "Microsoft Sentinel enabled       : 2" in out and "dry run" in out
    doc = json.loads(out[out.index("{"):])
    assert {w["workspace_name"] for w in doc["workspaces"]} == {"contoso-sentinel", "fab-sentinel"}


def test_cli_discover_requires_live_credentials(capsys):
    from app import mcp_server
    with pytest.raises(SystemExit) as exc:
        mcp_server.main(["--discover-workspaces", "--dry-run"])
    assert exc.value.code == 1
    assert "az login" in capsys.readouterr().out


def test_check_flags_missing_fleet_file_when_live(monkeypatch, capsys):
    from app import mcp_server
    monkeypatch.setattr(settings, "WORKSPACES_JSON", None)
    monkeypatch.setattr(settings, "WORKSPACES_CONFIG_PATH", "/nonexistent/workspaces.json")
    monkeypatch.setattr(settings, "DEMO_MODE", False)
    monkeypatch.setattr(settings, "AZURE_AUTH_MODE", "user")
    reg.workspace_registry.reload()
    sentinel_client._init_client()
    try:
        with pytest.raises(SystemExit) as exc:
            mcp_server.main(["--check", "--no-workspace-probe"])
    finally:
        monkeypatch.setattr(settings, "DEMO_MODE", True)
        monkeypatch.setattr(settings, "AZURE_AUTH_MODE", "auto")
        monkeypatch.setattr(settings, "WORKSPACES_CONFIG_PATH", None)
        reg.workspace_registry.reload()
        sentinel_client._init_client()
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "fleet file not found" in out and "--discover-workspaces" in out and "NOT READY" in out
