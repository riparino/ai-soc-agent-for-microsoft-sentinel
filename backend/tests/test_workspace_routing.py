"""
Tests for multi-workspace / multi-tenant (Azure Lighthouse fleet) routing.

These exercise the existing in-memory mock path in ``services/sentinel_client.py``
(DEMO_MODE), which seeds two demo workspaces so incident namespacing, per-request
workspace selection and aggregation can all be verified without live Azure.
"""


import pytest

from app.config import settings
from app.services.workspace_registry import (
    WORKSPACE_REF_SEPARATOR,
    workspace_registry,
)
from app.services.sentinel_client import sentinel_client, MOCK_INCIDENTS


@pytest.fixture(autouse=True)
def _restore_registry():
    """Ensure every test starts and ends on the default (demo-seed) fleet."""
    workspace_registry.reload()
    yield
    settings.WORKSPACES_JSON = None
    settings.WORKSPACES_CONFIG_PATH = None
    workspace_registry.reload()


# --------------------------------------------------------------------- registry
def test_demo_seed_loads_multiple_workspaces():
    workspaces = workspace_registry.list_workspaces()
    ids = [w.id for w in workspaces]
    assert len(workspaces) >= 2
    assert "contoso" in ids and "fabrikam" in ids


def test_managing_tenant_flag_and_no_graph_fields():
    assert workspace_registry.get("contoso").is_managing_tenant is True
    assert workspace_registry.get("fabrikam").is_managing_tenant is False
    assert not any(k.startswith("graph") for k in workspace_registry.get("fabrikam").public_dict())


def test_ref_roundtrip():
    ref = workspace_registry.make_ref("fabrikam", "inc-123")
    assert ref == f"fabrikam{WORKSPACE_REF_SEPARATOR}inc-123"
    wid, raw = workspace_registry.parse_ref(ref)
    assert wid == "fabrikam" and raw == "inc-123"
    ws, raw2 = workspace_registry.resolve_ref(ref)
    assert ws.id == "fabrikam" and raw2 == "inc-123"


def test_resolve_ref_bare_id_falls_back_to_default():
    ws, raw = workspace_registry.resolve_ref("inc-999")
    assert ws.id == workspace_registry.default().id
    assert raw == "inc-999"


def test_resolve_targets_selector():
    assert len(workspace_registry.resolve_targets(None)) == len(workspace_registry.list_workspaces())
    assert len(workspace_registry.resolve_targets("all")) == len(workspace_registry.list_workspaces())
    assert [w.id for w in workspace_registry.resolve_targets("contoso")] == ["contoso"]
    assert {w.id for w in workspace_registry.resolve_targets("contoso,fabrikam")} == {"contoso", "fabrikam"}
    # Unknown selector falls back to the default workspace.
    assert len(workspace_registry.resolve_targets("does-not-exist")) == 1


# ------------------------------------------------------------------- listing
@pytest.mark.asyncio
async def test_list_aggregates_all_workspaces_with_namespaced_ids():
    incidents = await sentinel_client.list_incidents()
    assert len(incidents) == len(MOCK_INCIDENTS)
    for inc in incidents:
        assert WORKSPACE_REF_SEPARATOR in inc["id"]
        wid, raw = workspace_registry.parse_ref(inc["id"])
        assert inc["workspaceId"] == wid
        assert inc["workspaceName"]
        # The namespace must match the stamped workspace.
        assert inc["id"].startswith(f"{inc['workspaceId']}{WORKSPACE_REF_SEPARATOR}")


@pytest.mark.asyncio
async def test_selection_routes_to_single_workspace():
    contoso = await sentinel_client.list_incidents(workspace="contoso")
    fabrikam = await sentinel_client.list_incidents(workspace="fabrikam")

    assert len(contoso) > 0 and len(fabrikam) > 0
    assert all(i["workspaceId"] == "contoso" for i in contoso)
    assert all(i["workspaceId"] == "fabrikam" for i in fabrikam)

    # The two workspaces partition the fleet (disjoint union == aggregate).
    contoso_nums = {i["incidentNumber"] for i in contoso}
    fabrikam_nums = {i["incidentNumber"] for i in fabrikam}
    assert contoso_nums.isdisjoint(fabrikam_nums)
    assert len(contoso) + len(fabrikam) == len(MOCK_INCIDENTS)


@pytest.mark.asyncio
async def test_selection_is_stable():
    first = await sentinel_client.list_incidents(workspace="contoso")
    second = await sentinel_client.list_incidents(workspace="contoso")
    assert {i["id"] for i in first} == {i["id"] for i in second}


# ------------------------------------------------------------------- get/route
@pytest.mark.asyncio
async def test_get_incident_routes_by_ref():
    fabrikam = await sentinel_client.list_incidents(workspace="fabrikam")
    ref = fabrikam[0]["id"]
    fetched = await sentinel_client.get_incident(ref)
    assert fetched is not None
    assert fetched["id"] == ref
    assert fetched["workspaceId"] == "fabrikam"


@pytest.mark.asyncio
async def test_comment_routes_to_correct_workspace_incident():
    contoso = await sentinel_client.list_incidents(workspace="contoso")
    ref = contoso[0]["id"]
    _, raw_id = workspace_registry.parse_ref(ref)

    before = len(next(m for m in MOCK_INCIDENTS if m["id"] == raw_id).get("comments", []))
    res = await sentinel_client.add_comment(ref, "routing test note", author="pytest")
    assert res["status"] == "SUCCESS"
    after = len(next(m for m in MOCK_INCIDENTS if m["id"] == raw_id).get("comments", []))
    assert after == before + 1
