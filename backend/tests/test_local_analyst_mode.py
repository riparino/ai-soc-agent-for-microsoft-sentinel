"""
Tests for the local per-analyst mode: user credentials (az login), analyst
attribution in audit comments, and the --check / --print-config tooling.
No Azure is contacted: credentials are built but never asked for real tokens,
and identity decoding uses a locally minted (unsigned-trust) JWT.
"""

import json

import pytest

from app.config import settings
from app.services import azure_credentials as creds
from app.services.sentinel_client import sentinel_client
from app.services.workspace_registry import workspace_registry


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
        monkeypatch.setattr(settings, k, None)
    monkeypatch.setattr(settings, "USE_MANAGED_IDENTITY", False)
    monkeypatch.setattr(settings, "AZURE_AUTH_MODE", "auto")
    monkeypatch.setattr(settings, "AZURE_INTERACTIVE_LOGIN", False)
    monkeypatch.setattr(settings, "MCP_DISABLED_TOOLS", None)
    creds._identity_cache.clear()
    workspace_registry.reload()
    yield
    creds._identity_cache.clear()


# ------------------------------------------------------------- auth modes
def test_auth_mode_auto_without_credentials_is_none():
    assert creds.resolve_auth_mode() == "none"
    assert creds.has_live_credentials() is False


def test_auth_mode_auto_prefers_managed_identity_then_sp(monkeypatch):
    monkeypatch.setattr(settings, "AZURE_TENANT_ID", "t")
    monkeypatch.setattr(settings, "AZURE_CLIENT_ID", "c")
    monkeypatch.setattr(settings, "AZURE_CLIENT_SECRET", "s")
    assert creds.resolve_auth_mode() == "service_principal"
    monkeypatch.setattr(settings, "USE_MANAGED_IDENTITY", True)
    assert creds.resolve_auth_mode() == "managed_identity"


def test_user_mode_builds_cli_credential_chain(monkeypatch):
    azure_identity = pytest.importorskip("azure.identity")
    monkeypatch.setattr(settings, "AZURE_AUTH_MODE", "user")
    assert creds.resolve_auth_mode() == "user"
    assert creds.has_live_credentials() is True
    credential = creds.build_credential()
    assert isinstance(credential, azure_identity.ChainedTokenCredential)


def test_user_mode_makes_clients_live_without_a_secret(monkeypatch):
    """The whole point of local mode: live Sentinel without any SP secret on the box."""
    pytest.importorskip("azure.identity")
    monkeypatch.setattr(settings, "AZURE_AUTH_MODE", "user")
    monkeypatch.setattr(settings, "DEMO_MODE", False)
    sentinel_client._init_client()
    try:
        assert sentinel_client.is_live is True
        assert sentinel_client.auth_mode == "user"
        assert sentinel_client.credential is not None
    finally:
        monkeypatch.setattr(settings, "DEMO_MODE", True)
        monkeypatch.setattr(settings, "AZURE_AUTH_MODE", "auto")
        sentinel_client._init_client()
        assert sentinel_client.is_live is False


# -------------------------------------------------------------- identity
class _FakeToken:
    def __init__(self, token):
        self.token = token


class _FakeCredential:
    def __init__(self, claims):
        from jose import jwt

        self._token = jwt.encode(claims, "not-verified-here", algorithm="HS256")
        self.calls = 0

    def get_token(self, *scopes, **kwargs):
        self.calls += 1
        return _FakeToken(self._token)


def test_signed_in_identity_from_user_token():
    cred = _FakeCredential({"preferred_username": "ana.lyst@mssp.example", "name": "Ana Lyst", "oid": "oid-1", "tid": "tenant-1"})
    ident = creds.get_signed_in_identity(cred)
    assert ident == {"kind": "user", "upn": "ana.lyst@mssp.example", "name": "Ana Lyst", "object_id": "oid-1", "tenant_id": "tenant-1"}
    # Cached per credential: a second lookup doesn't re-mint a token.
    creds.get_signed_in_identity(cred)
    assert cred.calls == 1
    assert creds.actor_label(cred) == "Ana Lyst (ana.lyst@mssp.example) via AI SOC Agent"


def test_signed_in_identity_from_app_token_keeps_generic_actor():
    cred = _FakeCredential({"appid": "app-123", "oid": "sp-oid", "tid": "tenant-1"})
    ident = creds.get_signed_in_identity(cred)
    assert ident["kind"] == "app" and ident["name"] == "app-123"
    assert creds.actor_label(cred, fallback="AI SOC Agent (MCP)") == "AI SOC Agent (MCP)"


# ----------------------------------------------------- MCP attribution
@pytest.mark.asyncio
async def test_mcp_comments_are_attributed_to_the_analyst(monkeypatch):
    from mcp.shared.memory import create_connected_server_and_client_session
    from app.mcp_server import create_server

    cred = _FakeCredential({"preferred_username": "ana.lyst@mssp.example", "name": "Ana Lyst", "oid": "o", "tid": "t"})
    monkeypatch.setattr(sentinel_client, "credential", cred)

    server = create_server(auth_mode="none")
    async with create_connected_server_and_client_session(server) as session:
        listed = await session.call_tool("sentinel_list_incidents", {"workspace": "contoso"})
        ref = (listed.structuredContent or {}).get("incidents", [{}])[0].get("id") or json.loads(listed.content[0].text)["incidents"][0]["id"]
        res = await session.call_tool("sentinel_add_comment", {"incident_ref": ref, "message": "attribution test"})
        explicit = await session.call_tool("sentinel_add_comment", {"incident_ref": ref, "message": "explicit author", "author": "Playbook X"})
    data = res.structuredContent or json.loads(res.content[0].text)
    assert data["comment"]["author"] == "Ana Lyst (ana.lyst@mssp.example) via AI SOC Agent (MCP)"
    data2 = explicit.structuredContent or json.loads(explicit.content[0].text)
    assert data2["comment"]["author"] == "Playbook X"


# ------------------------------------------------------------ local tooling
def test_print_config_targets(capsys):
    from app.mcp_server import BACKEND_DIR, main

    main(["--print-config", "claude-desktop"])
    cfg = json.loads(capsys.readouterr().out)
    server = cfg["mcpServers"]["sentinel-soc"]
    assert server["args"] == ["-m", "app.mcp_server", "--transport", "stdio"]
    assert server["env"]["PYTHONPATH"] == BACKEND_DIR

    main(["--print-config", "vscode"])
    cfg = json.loads(capsys.readouterr().out)
    assert cfg["servers"]["sentinel-soc"]["type"] == "stdio"

    main(["--print-config", "claude-code"])
    line = capsys.readouterr().out
    assert line.startswith("claude mcp add sentinel-soc") and "app.mcp_server" in line


def test_check_reports_ready_in_demo_mode(capsys):
    from app.mcp_server import main

    with pytest.raises(SystemExit) as exc:
        main(["--check"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "DEMO_MODE     : True" in out
    assert "Workspaces    : 2 loaded" in out
    assert "READY" in out and "NOT READY" not in out


def test_check_flags_missing_credentials_when_live(capsys, monkeypatch):
    from app.mcp_server import main

    monkeypatch.setattr(settings, "DEMO_MODE", False)
    sentinel_client._init_client()
    try:
        with pytest.raises(SystemExit) as exc:
            main(["--check", "--no-workspace-probe"])
    finally:
        monkeypatch.setattr(settings, "DEMO_MODE", True)
        sentinel_client._init_client()
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "NOT LIVE" in out and "AZURE_AUTH_MODE=user" in out and "NOT READY" in out
