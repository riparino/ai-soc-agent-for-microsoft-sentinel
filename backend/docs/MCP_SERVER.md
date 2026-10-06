# MCP Server — Sentinel as tools for Claude, GitHub Copilot & Copilot Studio

`app/mcp_server.py` exposes Microsoft Sentinel — across the Lighthouse-delegated
workspace fleet — as **Model Context Protocol (MCP)** tools. On the `analyst-local`
branch it is the whole product: each analyst runs it on their own machine (see
[ANALYST_LOCAL_SETUP.md](ANALYST_LOCAL_SETUP.md)); the same server can later be
hosted for a team or a Copilot Studio agent over HTTP with Entra ID auth.

## Two ways to run it

| Transport | When | Command |
|-----------|------|---------|
| **stdio** | Local, single user, zero network. Claude Desktop / Claude Code / VS Code launch it as a subprocess. Best for testing. | `./run-mcp.sh` (= `python -m app.mcp_server --transport stdio`) |
| **Streamable HTTP** | Shared/remote: Copilot Studio, Claude Enterprise connectors, teams. | `./run-mcp.sh --transport streamable-http` → `http://127.0.0.1:8800/mcp` |

Settings come from `backend/.env`. `DEMO_MODE=True` runs against a built-in
two-workspace sample fleet with no Azure at all — for trying the tools only. With
`DEMO_MODE=False` (the default) nothing is ever simulated: a failed call returns a
structured error (see *Error contract* below) rather than sample data.

## Tools

All tools take/return JSON. Incident IDs are **namespaced refs**
`<workspace_id>::<incident_guid>` (exactly as in the REST API), which is how a
call routes to the right delegated tenant. Always get refs from
`sentinel_list_incidents`; don't guess them.

| Tool | Kind | Purpose |
|------|------|---------|
| `sentinel_list_workspaces` | read | The fleet: ids (use as `workspace` selector) and tenant / subscription / resource-group coordinates |
| `sentinel_list_incidents` | read | Compact summaries across one / several / `all` workspaces; filters + `limit` |
| `sentinel_get_incident` | read | Full entity graph, alerts, comments, classification |
| `sentinel_extract_indicators` | read | Flat, deduped IOC lists (ips, hosts, accounts, hashes, urls, azure_resources…) for hand-off to intel / asset tools |
| `sentinel_triage_incident` | write | Claims the incident for the analyst (if unassigned), runs intel + the hunt catalog, then returns a verdict (server LLM configured) or an **evidence pack** (`EVIDENCE_COLLECTED`, verdict null) for the MCP client to reason over; `ALREADY_ASSIGNED` / `RECENTLY_TRIAGED` instead of duplicating work (`force` to override) |
| `sentinel_get_triage_report` | read | Fetch an existing report |
| `sentinel_list_tables` | read | Which tables the workspace ingests (from `Usage`) and which catalog hunts that supports |
| `sentinel_hunt_incident` | read | Runs the entity-driven hunt catalog (Entra sign-in / audit / risk, Defender XDR Device* / Identity / Email / CloudApp, AzureActivity, AzureDiagnostics, SecurityEvent, Office, CEF, Syslog, alerts, TI) for an incident; `dry_run` returns the KQL only |
| `sentinel_run_kql` | read | Ad-hoc KQL against any ingested table (Lighthouse-delegated); errors reported, never simulated |
| `sentinel_check_ip_reputation` / `sentinel_check_file_hash` | read | Threat-intel lookups |
| `sentinel_add_comment` | write | Post a note to the incident in its tenant |
| `sentinel_update_incident_status` | **destructive** | Status / severity / classification / labels; closing requires a classification |
| `sentinel_assign_incident` | write | Assign (by UPN) / unassign; `only_if_unassigned` for safe claims |

Tools carry MCP annotations (`readOnlyHint`, `destructiveHint`) so well-behaved
clients ask the analyst before destructive calls.

**Scope: Microsoft Sentinel only.** Everything above runs through Azure Resource
Manager (Sentinel incidents API) and Log Analytics, which Azure Lighthouse delegates.
There are deliberately no Entra ID / Microsoft Graph or Defender XDR tools here:
neither is delegated by Lighthouse, so a server running as a Lighthouse analyst
could not perform them honestly across customer tenants.

## Local setup (stdio) — testing on a laptop

> Rolling this out to every analyst? Use **`AZURE_AUTH_MODE=user`** so each person
> authenticates as themselves with `az login` (no secrets on laptops, per-analyst
> attribution) — step-by-step in **[ANALYST_LOCAL_SETUP.md](ANALYST_LOCAL_SETUP.md)**.
> `./run-mcp.sh --check` diagnoses an install; `--print-config <client>` prints the snippet.

```bash
cd backend
python -m venv venv && source venv/bin/activate     # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                 # DEMO_MODE=True is fine to start
./run-mcp.sh --help
```

Quick protocol check without any client:

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"check","version":"0"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | ./run-mcp.sh
```

### Claude Code

```bash
# from the repo root (adjust the path); --scope project shares it via .mcp.json
claude mcp add sentinel-soc --scope project -- /ABSOLUTE/PATH/backend/run-mcp.sh
```

Then: *"list the open High incidents across all workspaces and triage the newest one."*

### Claude Desktop

`claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "sentinel-soc": {
      "command": "/ABSOLUTE/PATH/backend/run-mcp.sh",
      "args": ["--transport", "stdio"]
    }
  }
}
```

On Windows use the venv interpreter directly and set `PYTHONPATH` to the backend
folder:

```json
{ "mcpServers": { "sentinel-soc": {
  "command": "C:\\path\\backend\\venv\\Scripts\\python.exe",
  "args": ["-m", "app.mcp_server", "--transport", "stdio"],
  "env": { "PYTHONPATH": "C:\\path\\backend" }
}}}
```

### VS Code (GitHub Copilot agent mode)

`.vscode/mcp.json`:

```json
{
  "servers": {
    "sentinel-soc": { "type": "stdio", "command": "${workspaceFolder}/backend/run-mcp.sh" }
  }
}
```

or, against a running HTTP server:

```json
{ "servers": { "sentinel-soc": { "type": "http", "url": "http://127.0.0.1:8800/mcp" } } }
```

### Local HTTP (no auth)

```bash
./run-mcp.sh --transport streamable-http           # 127.0.0.1:8800, MCP_AUTH_MODE=none
```

With `--auth none` the server refuses nothing — it is bound to loopback by default
and logs a warning if you bind it elsewhere. **Never expose an unauthenticated
instance beyond localhost.**

When bound to loopback the MCP SDK also enables **DNS-rebinding protection**: it
only accepts requests whose `Host` header is `127.0.0.1:<port>` or
`localhost:<port>`, and answers anything else with `421 Misdirected Request`. So
point local clients at `http://127.0.0.1:8800/mcp` (or `localhost`), not at a
machine hostname or a tunnel domain. Binding to a non-loopback `--host` (remote
hosting) turns that check off — which is why remote deployments must use
`MCP_AUTH_MODE=entra` behind HTTPS instead.

## Shared / remote hosting (Streamable HTTP + Entra ID)

For Copilot Studio, Claude Enterprise connectors, or a team endpoint, run the HTTP
transport **with Microsoft Entra ID bearer auth**:

### 1. Register the MCP server as an API in Entra

1. **App registration** (e.g. `sentinel-soc-mcp`) in your managing tenant.
2. **Expose an API** → set the Application ID URI (`api://<client-id>`) → add a
   scope, e.g. `Sentinel.Triage` (admin consent). Optionally add **App roles** for
   daemon clients.
3. Note the **Directory (tenant) ID** and **Application (client) ID**.

### 2. Configure and run

```env
MCP_AUTH_MODE=entra
MCP_ENTRA_TENANT_ID=<managing-tenant-guid>          # defaults to AZURE_TENANT_ID
MCP_ENTRA_AUDIENCE=<mcp-server-client-id>           # bare id and api://<id> are both accepted
MCP_REQUIRED_SCOPES=Sentinel.Triage                 # optional; scp or roles claim must contain these
MCP_PUBLIC_URL=https://soc-mcp.example.com/mcp      # the URL clients will use
MCP_HOST=0.0.0.0
MCP_PORT=8800
```

```bash
./run-mcp.sh --transport streamable-http
```

Put it behind HTTPS (ingress / App Gateway / Container Apps). The server:

- validates every bearer token's **signature** (tenant JWKS, with key-rotation
  refresh), **issuer** (v2.0 and v1.0 forms), **expiry**, and **audience**, and
  enforces `MCP_REQUIRED_SCOPES` against `scp`/`roles`;
- answers unauthenticated requests with **401** and a `WWW-Authenticate: Bearer …
  resource_metadata="…"` header, and publishes **RFC 9728 protected-resource
  metadata** at the path-based well-known URL derived from `MCP_PUBLIC_URL` — for
  `https://soc-mcp.example.com/mcp` that is
  `https://soc-mcp.example.com/.well-known/oauth-protected-resource/mcp` — pointing
  clients at your Entra tenant as the authorization server, so MCP clients can
  discover how to obtain a token.

### 3. Connect clients

- **Copilot Studio** — add it to an existing agent with the MCP onboarding wizard
  (OAuth 2.0 → Manual against Entra), optionally disabling overlapping tools via
  `MCP_DISABLED_TOOLS`, then publish to **Teams**. Step-by-step, including the
  Entra app registrations and a cross-tool (intel + cloud inventory) workflow:
  **[COPILOT_STUDIO.md](COPILOT_STUDIO.md)**.
- **Claude Enterprise** — an org admin adds the server URL as a **custom connector**
  with OAuth client credentials from a client app registration (redirect URI per
  Anthropic's connector docs). Analysts then use the tools in claude.ai / desktop.
- **GitHub Copilot (org)** — add the HTTP URL to the organization's MCP
  configuration for the coding agent, or per-repo via `.vscode/mcp.json`.

Each client authenticates **as the analyst** (delegated scope), so actions are
attributable per person in the incident audit comments.

## Error contract (what analysts see when something fails)

Every tool runs inside a guard. A failure is returned as:

```json
{"error": "FORBIDDEN",
 "message": "Azure refused the call (403): ana@mssp.example has no Microsoft Sentinel Responder access on workspace 'fabrikam'.",
 "what_to_check": ["Confirm `az account show` is the managing tenant, not a customer tenant.", "..."],
 "tell_admin": "Workspace 'fabrikam' (subscription ..., resource group ..., workspace ...) returns 403 for ana@mssp.example. The Lighthouse delegation ...",
 "workspace": "fabrikam", "incident_ref": "fabrikam::...", "http_status": 403, "detail": "..."}
```

Codes: `NOT_AUTHENTICATED`, `FLEET_NOT_CONFIGURED`, `WORKSPACE_UNKNOWN`,
`WORKSPACE_INCOMPLETE`, `FORBIDDEN`, `WORKSPACE_NOT_FOUND`, `INCIDENT_NOT_FOUND`,
`CONFLICT`, `THROTTLED`, `AZURE_UNAVAILABLE`, `AZURE_ERROR`, `NETWORK`,
`NETWORK_TIMEOUT`, `UNEXPECTED` (bug / environment; traceback on stderr).
`sentinel_list_incidents` keeps going when one customer fails and lists that
workspace under `workspace_errors`. KQL results use `status: ERROR` with
`error_type` (`TABLE_NOT_FOUND`, `QUERY_INVALID`, `FORBIDDEN`, `NOT_AUTHENTICATED`,
`TIMEOUT`, `QUERY_FAILED`); intel lookups use `NOT_CONFIGURED` / `ERROR`. The
server instructions tell the MCP client to relay `message`, `what_to_check` and
`tell_admin` verbatim and never to invent data to fill a gap. Implementation:
`app/services/errors.py`.

## Hosting it for a team (later)

Run the HTTP transport from the same code on any container platform
(`python -m app.mcp_server --transport streamable-http --host 0.0.0.0`) with
`MCP_AUTH_MODE=entra`, a service principal or managed identity (`AZURE_AUTH_MODE`),
and the fleet file mounted read-only; put it behind HTTPS. Per-analyst attribution
then comes from the delegated bearer token rather than from `az login`.

## Notes and limits

- **Trim the tool set**: `MCP_DISABLED_TOOLS="sentinel_check_ip_reputation,sentinel_check_file_hash"`
  skips registering tools — useful when the consuming agent already has a dedicated
  threat-intel server, and because Copilot Studio counts every MCP tool against the
  agent's tool limit.
- **Flat schemas**: optional parameters use `""` / `0` / `[]` / `{}` to mean
  "not set" rather than nullable types, so tools survive import into Copilot Studio
  (which filters `$ref` inputs and truncates `type` arrays / nullable unions).
- **No races between analysts**: Sentinel's incident *owner* is the coordination
  lock. Triage claims unassigned incidents with an ETag-conditional assignment and
  refuses incidents owned by someone else; `sentinel_update_incident_status` and
  `sentinel_assign_incident` send `If-Match`, so a concurrent change returns
  `CONFLICT` rather than overwriting it. This works across every analyst's local
  server and the Sentinel portal because the state lives in Sentinel, not
  in any one process. Tune with `TRIAGE_CLAIM_ON_RUN` / `TRIAGE_DEDUPE_MINUTES`.
- **Shared state**: the triage result cache is process-local. For a multi-replica
  hosted deployment back the store with Redis/Postgres.
- **stdio = no auth by design**: it is a local subprocess channel; bearer auth is
  ignored for stdio. The server never writes anything but JSON-RPC to stdout (logs
  and the first-run banner go to stderr).
- **Tests**: `tests/test_mcp_server.py` exercises real `tools/list` / `tools/call`
  round-trips over the in-memory transport and the Entra verifier with signed RS256
  test tokens (signature, audience, issuer, expiry, scopes).
