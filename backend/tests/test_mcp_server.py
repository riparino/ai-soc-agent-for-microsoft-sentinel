"""
Tests for the MCP server (``app.mcp_server``).

Protocol-level tests use the SDK's in-memory client/server session, so they
exercise real MCP ``tools/list`` and ``tools/call`` round-trips over the existing
DEMO_MODE mock path — no live Azure, no network.

Auth tests sign real RS256 JWTs with a throwaway RSA key and feed the matching JWKS
to the Entra verifier, so signature / audience / issuer / scope checks are real.
"""

import json
import time

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from app.config import settings
from app.mcp_server import EntraTokenVerifier, _build_auth, create_server
from app.services.workspace_registry import WORKSPACE_REF_SEPARATOR, workspace_registry

EXPECTED_TOOLS = {
    "sentinel_list_workspaces",
    "sentinel_list_incidents",
    "sentinel_get_incident",
    "sentinel_extract_indicators",
    "sentinel_triage_incident",
    "sentinel_get_triage_report",
    "sentinel_run_kql",
    "sentinel_check_ip_reputation",
    "sentinel_check_file_hash",
    "sentinel_add_comment",
    "sentinel_update_incident_status",
    "sentinel_assign_incident",
}


@pytest.fixture(autouse=True)
def _demo_registry():
    settings.WORKSPACES_JSON = None
    settings.WORKSPACES_CONFIG_PATH = None
    settings.MCP_DISABLED_TOOLS = None
    workspace_registry.reload()
    yield
    settings.MCP_DISABLED_TOOLS = None


# ------------------------------------------------------ Copilot Studio compat
def _walk(node, found):
    """Collect JSON-schema constructs Copilot Studio can't consume."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("$ref", "$defs", "anyOf", "oneOf", "exclusiveMinimum", "exclusiveMaximum"):
                found.append(k)
            if k == "type" and isinstance(v, list):
                found.append("type-array")
            _walk(v, found)
    elif isinstance(node, list):
        for v in node:
            _walk(v, found)


@pytest.mark.asyncio
async def test_schemas_are_flat_for_copilot_studio(server):
    """Copilot Studio filters tools with $ref inputs and truncates schemas with type
    arrays / nullable unions; every tool must stay flat so none get dropped there."""
    async with create_connected_server_and_client_session(server) as session:
        tools = (await session.list_tools()).tools
    offenders = {}
    for t in tools:
        found = []
        _walk(t.inputSchema, found)
        if found:
            offenders[t.name] = found
    assert offenders == {}, f"non-flat input schemas: {offenders}"


def test_disabled_tools_are_not_registered(monkeypatch):
    """MCP_DISABLED_TOOLS trims the tool set (e.g. when another MCP server in the
    agent already provides threat intel)."""
    import asyncio

    monkeypatch.setattr(settings, "MCP_DISABLED_TOOLS", "sentinel_check_ip_reputation, sentinel_check_file_hash")
    names = {t.name for t in asyncio.run(create_server(auth_mode="none").list_tools())}
    assert names == EXPECTED_TOOLS - {"sentinel_check_ip_reputation", "sentinel_check_file_hash"}


@pytest.mark.asyncio
async def test_extract_indicators_flattens_entities(server):
    async with create_connected_server_and_client_session(server) as session:
        contoso = await _call(session, "sentinel_list_incidents", workspace="contoso")
        ref = contoso["incidents"][0]["id"]
        inc = await _call(session, "sentinel_get_incident", incident_ref=ref)
        ind = await _call(session, "sentinel_extract_indicators", incident_ref=ref)
        missing = await _call(session, "sentinel_extract_indicators", incident_ref="contoso::nope")
    assert ind["incident_ref"] == ref and ind["workspace_id"] == "contoso"
    expected_ips = {e["address"] for e in inc["entities"] if e.get("kind") == "Ip"}
    assert set(ind["ips"]) == expected_ips
    assert all(isinstance(v, str) for v in ind["ips"] + ind["accounts"] + ind["hosts"])
    assert ind["counts"]["ips"] == len(ind["ips"])
    assert missing["error"] == "INCIDENT_NOT_FOUND"


@pytest.mark.asyncio
async def test_empty_optionals_mean_unset(server):
    """Flat-schema convention: '' / 0 behave exactly like omitted parameters."""
    async with create_connected_server_and_client_session(server) as session:
        implicit = await _call(session, "sentinel_list_incidents", workspace="all")
        explicit = await _call(session, "sentinel_list_incidents", workspace="all", status="", severity="", days=0)
        filtered = await _call(session, "sentinel_list_incidents", workspace="all", severity="High")
    assert {i["id"] for i in implicit["incidents"]} == {i["id"] for i in explicit["incidents"]}
    assert 0 < filtered["total"] <= implicit["total"]
    assert all(i["severity"] == "High" for i in filtered["incidents"])


@pytest.fixture
def server():
    return create_server(auth_mode="none")


def _payload(result):
    """Extract the tool's structured payload from a CallToolResult.

    FastMCP returns dict results as structuredContent (sometimes wrapped as
    {"result": ...}); fall back to parsing the text block.
    """
    assert not result.isError, f"tool call errored: {result.content}"
    data = result.structuredContent
    if isinstance(data, dict) and set(data) == {"result"}:
        data = data["result"]
    if data is None:
        data = json.loads(result.content[0].text)
    return data


async def _call(session, name, **args):
    return _payload(await session.call_tool(name, args))


# ----------------------------------------------------------------- discovery
@pytest.mark.asyncio
async def test_tools_are_registered_with_annotations(server):
    async with create_connected_server_and_client_session(server) as session:
        tools = {t.name: t for t in (await session.list_tools()).tools}
    assert set(tools) == EXPECTED_TOOLS
    # Reads are flagged read-only; destructive actions are flagged destructive.
    assert tools["sentinel_list_incidents"].annotations.readOnlyHint is True
    assert tools["sentinel_get_incident"].annotations.readOnlyHint is True
    assert tools["sentinel_update_incident_status"].annotations.destructiveHint is True
    assert tools["sentinel_add_comment"].annotations.destructiveHint is False
    # Required params surface in the schema so clients prompt for them.
    assert "incident_ref" in tools["sentinel_get_incident"].inputSchema["required"]
    assert "query" in tools["sentinel_run_kql"].inputSchema["required"]


# -------------------------------------------------------------- fleet / list
@pytest.mark.asyncio
async def test_list_workspaces(server):
    async with create_connected_server_and_client_session(server) as session:
        data = await _call(session, "sentinel_list_workspaces")
    ids = {w["id"] for w in data["workspaces"]}
    assert {"contoso", "fabrikam"} <= ids
    # Sentinel-only surface: no Microsoft Graph fields leak into the analyst tools.
    for w in data["workspaces"]:
        assert not any(k.startswith("graph") for k in w), w
    assert {"tenant_id", "subscription_id", "resource_group", "workspace_name"} <= set(data["workspaces"][0])


@pytest.mark.asyncio
async def test_list_incidents_routes_by_workspace(server):
    async with create_connected_server_and_client_session(server) as session:
        all_data = await _call(session, "sentinel_list_incidents")
        fab = await _call(session, "sentinel_list_incidents", workspace="fabrikam")
    assert all_data["total"] >= fab["total"] > 0
    assert all(i["workspaceId"] == "fabrikam" for i in fab["incidents"])
    assert all(WORKSPACE_REF_SEPARATOR in i["id"] for i in all_data["incidents"])
    # Summaries are compact: full entity graphs are not shipped in list responses.
    assert "entities" not in fab["incidents"][0]
    assert "entityCount" in fab["incidents"][0]


@pytest.mark.asyncio
async def test_list_incidents_limit_and_truncation(server):
    async with create_connected_server_and_client_session(server) as session:
        data = await _call(session, "sentinel_list_incidents", limit=1)
    assert data["count"] == 1
    assert data["truncated"] is True


# ------------------------------------------------------------- get / errors
@pytest.mark.asyncio
async def test_get_incident_by_ref(server):
    async with create_connected_server_and_client_session(server) as session:
        fab = await _call(session, "sentinel_list_incidents", workspace="fabrikam")
        ref = fab["incidents"][0]["id"]
        inc = await _call(session, "sentinel_get_incident", incident_ref=ref)
    assert inc["id"] == ref
    assert inc["workspaceId"] == "fabrikam"
    assert "entities" in inc and "alerts" in inc


@pytest.mark.asyncio
async def test_get_incident_not_found_is_actionable(server):
    async with create_connected_server_and_client_session(server) as session:
        data = await _call(session, "sentinel_get_incident", incident_ref="contoso::does-not-exist")
    assert data["error"] == "INCIDENT_NOT_FOUND"
    assert "sentinel_list_incidents" in data["hint"]


# ---------------------------------------------------------------- hunting
@pytest.mark.asyncio
async def test_run_kql_against_workspace(server):
    async with create_connected_server_and_client_session(server) as session:
        data = await _call(session, "sentinel_run_kql", query="SigninLogs | take 1", workspace="contoso")
        bad = await _call(session, "sentinel_run_kql", query="SigninLogs | take 1", workspace="nope")
    assert data["status"] == "SUCCESS"
    assert data["row_count"] >= 1
    assert bad["error"] == "WORKSPACE_NOT_FOUND"


@pytest.mark.asyncio
async def test_threat_intel_tools(server):
    async with create_connected_server_and_client_session(server) as session:
        ip = await _call(session, "sentinel_check_ip_reputation", ip_address="185.220.101.5")
    assert ip["verdict"] == "MALICIOUS"


# ----------------------------------------------------------------- triage
@pytest.mark.asyncio
async def test_triage_then_fetch_report(server):
    async with create_connected_server_and_client_session(server) as session:
        contoso = await _call(session, "sentinel_list_incidents", workspace="contoso")
        ref = contoso["incidents"][0]["id"]
        before = await _call(session, "sentinel_get_triage_report", incident_ref=ref)
        # Other tests may already have triaged this seeded incident (mock state is
        # process-global), so force past the claim/dedupe guard for the first run...
        report = await _call(session, "sentinel_triage_incident", incident_ref=ref, force=True)
        after = await _call(session, "sentinel_get_triage_report", incident_ref=ref)
        # ...and the very next plain run must be deduplicated, not repeated.
        rerun = await _call(session, "sentinel_triage_incident", incident_ref=ref)
    assert before.get("status") == "NOT_TRIAGED" or "verdict" in before
    assert report["verdict"] in {"TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS_ESCALATE"}
    assert report["coordination"]["claim_requested"] is True
    assert after["verdict"] == report["verdict"]
    assert rerun["status"] == "RECENTLY_TRIAGED"
    assert rerun["incident_ref"] == ref


# ---------------------------------------------------------------- actions
@pytest.mark.asyncio
async def test_close_requires_classification(server):
    async with create_connected_server_and_client_session(server) as session:
        contoso = await _call(session, "sentinel_list_incidents", workspace="contoso")
        ref = contoso["incidents"][0]["id"]
        data = await _call(session, "sentinel_update_incident_status", incident_ref=ref, status="Closed")
    assert data["error"] == "CLASSIFICATION_REQUIRED"


@pytest.mark.asyncio
async def test_add_comment_routes_to_incident(server):
    async with create_connected_server_and_client_session(server) as session:
        fab = await _call(session, "sentinel_list_incidents", workspace="fabrikam")
        ref = fab["incidents"][0]["id"]
        res = await _call(session, "sentinel_add_comment", incident_ref=ref, message="mcp test note")
        inc = await _call(session, "sentinel_get_incident", incident_ref=ref)
    assert res["status"] == "SUCCESS"
    assert any(c.get("message") == "mcp test note" for c in inc["comments"])



# ------------------------------------------------------------------- auth
def _rsa_jwks_and_signer():
    """Generate a throwaway RSA key; return (jwks dict, sign(claims) -> token)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jose import jwk, jwt

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    kid = "test-kid-1"
    public_jwk = jwk.construct(pem, algorithm="RS256").public_key().to_dict()
    public_jwk.update({"kid": kid, "use": "sig"})
    jwks = {"keys": [public_jwk]}

    def sign(claims):
        return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": kid})

    return jwks, sign


def test_build_auth_none_disables_bearer():
    assert _build_auth("none") == (None, None)


def _entra_settings(monkeypatch, public_url="http://testserver/mcp"):
    monkeypatch.setattr(settings, "MCP_ENTRA_TENANT_ID", "11111111-1111-1111-1111-111111111111")
    monkeypatch.setattr(settings, "MCP_ENTRA_AUDIENCE", "aaaaaaaa-0000-0000-0000-000000000001")
    monkeypatch.setattr(settings, "MCP_PUBLIC_URL", public_url)
    monkeypatch.setattr(settings, "MCP_REQUIRED_SCOPES", None)


def test_http_transport_enforces_entra_auth(monkeypatch):
    """Over the real Streamable HTTP app: no/garbage token -> 401 with discovery
    header; RFC 9728 metadata is served at the path-based well-known URL."""
    from starlette.testclient import TestClient

    _entra_settings(monkeypatch)
    app = create_server(auth_mode="entra").streamable_http_app()
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

    with TestClient(app) as client:
        missing = client.post("/mcp", json=body, headers=headers)
        assert missing.status_code == 401
        assert "resource_metadata=" in missing.headers.get("www-authenticate", "")

        garbage = client.post("/mcp", json=body, headers={**headers, "Authorization": "Bearer not.a.jwt"})
        assert garbage.status_code == 401

        meta = client.get("/.well-known/oauth-protected-resource/mcp")
        assert meta.status_code == 200
        data = meta.json()
        assert data["resource"].rstrip("/") == "http://testserver/mcp"
        assert any("login.microsoftonline.com/11111111" in a for a in data["authorization_servers"])


def test_http_transport_without_auth_serves_tools():
    """auth_mode=none: the HTTP transport answers tools/list with the full tool set."""
    from starlette.testclient import TestClient

    server = create_server(auth_mode="none")
    app = server.streamable_http_app()
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    # Bound to loopback, the SDK enables DNS-rebinding protection and only accepts
    # Host headers matching the bind address, so the client must present it.
    base_url = f"http://{server.settings.host}:{server.settings.port}"
    with TestClient(app, base_url=base_url) as client:
        resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, headers=headers)
    assert resp.status_code == 200
    assert {t["name"] for t in resp.json()["result"]["tools"]} == EXPECTED_TOOLS


def test_build_auth_entra_requires_config(monkeypatch):
    monkeypatch.setattr(settings, "MCP_ENTRA_TENANT_ID", None)
    monkeypatch.setattr(settings, "AZURE_TENANT_ID", None)
    monkeypatch.setattr(settings, "MCP_ENTRA_AUDIENCE", None)
    with pytest.raises(SystemExit):
        _build_auth("entra")


def test_build_auth_entra_publishes_resource_metadata(monkeypatch):
    monkeypatch.setattr(settings, "MCP_ENTRA_TENANT_ID", "11111111-1111-1111-1111-111111111111")
    monkeypatch.setattr(settings, "MCP_ENTRA_AUDIENCE", "aaaaaaaa-0000-0000-0000-000000000001")
    monkeypatch.setattr(settings, "MCP_PUBLIC_URL", "https://soc-mcp.example.com/mcp")
    monkeypatch.setattr(settings, "MCP_REQUIRED_SCOPES", "Sentinel.Triage")
    verifier, auth = _build_auth("entra")
    assert isinstance(verifier, EntraTokenVerifier)
    # Both the bare app id and api:// forms are accepted audiences.
    assert "aaaaaaaa-0000-0000-0000-000000000001" in verifier.audiences
    assert "api://aaaaaaaa-0000-0000-0000-000000000001" in verifier.audiences
    assert str(auth.issuer_url).startswith("https://login.microsoftonline.com/11111111")
    assert str(auth.resource_server_url) == "https://soc-mcp.example.com/mcp"
    assert auth.required_scopes == ["Sentinel.Triage"]


@pytest.mark.asyncio
async def test_entra_verifier_accepts_valid_token_and_rejects_bad_ones(monkeypatch):
    tenant = "11111111-1111-1111-1111-111111111111"
    app_id = "aaaaaaaa-0000-0000-0000-000000000001"
    jwks, sign = _rsa_jwks_and_signer()

    verifier = EntraTokenVerifier(tenant, [app_id, f"api://{app_id}"], required_scopes=["Sentinel.Triage"])

    async def fake_jwks(force=False):
        return jwks

    monkeypatch.setattr(verifier, "_get_jwks", fake_jwks)

    now = int(time.time())
    base = {
        "iss": f"https://login.microsoftonline.com/{tenant}/v2.0",
        "aud": app_id,
        "iat": now,
        "exp": now + 600,
        "oid": "user-oid-1",
        "azp": "client-app-1",
        "scp": "Sentinel.Triage Sentinel.Read",
    }

    ok = await verifier.verify_token(sign(base))
    assert ok is not None
    assert ok.subject == "user-oid-1"
    assert "Sentinel.Triage" in ok.scopes

    # v1.0 issuer with app roles is also accepted.
    v1 = dict(base, iss=f"https://sts.windows.net/{tenant}/", roles=["Sentinel.Triage"])
    v1.pop("scp")
    assert await verifier.verify_token(sign(v1)) is not None

    assert await verifier.verify_token(sign(dict(base, aud="someone-else"))) is None
    assert await verifier.verify_token(sign(dict(base, iss="https://login.microsoftonline.com/other-tenant/v2.0"))) is None
    assert await verifier.verify_token(sign(dict(base, exp=now - 10))) is None
    assert await verifier.verify_token(sign(dict(base, scp="Sentinel.Read"))) is None  # missing required scope

    # Token signed by a different key must be rejected even with valid claims.
    _, other_sign = _rsa_jwks_and_signer()
    assert await verifier.verify_token(other_sign(base)) is None
