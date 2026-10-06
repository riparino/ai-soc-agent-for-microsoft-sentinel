# 🛡️ Microsoft Sentinel AI SOC Agent — Local Analyst MCP Server

> ⚠️ **Branch rule: do not push `analyst-local` to `main`, and do not merge or
> rebase `main` into it.** `main` is the hosted web console and is managed
> separately (PR #1). Commit analyst-side work here only. To make git refuse an
> accidental push to `main` from your clone: `git config core.hooksPath .githooks`.

An **MCP server** each SOC analyst runs on their own machine. It plugs Microsoft
Sentinel — every customer workspace delegated to us through **Azure Lighthouse** —
into Claude Desktop, Claude Code or VS Code as tools: list and read incidents,
hunt with KQL across whatever the customer ingests, run AI-assisted triage,
comment, assign, classify and close. There is **no web UI** on this branch and
nothing to host: the server runs as the signed-in analyst (`az login`), so there
are no secrets on laptops and every action in Sentinel is attributed to the
person who took it.

**Analyst runbook:** [`backend/docs/ANALYST_LOCAL_SETUP.md`](backend/docs/ANALYST_LOCAL_SETUP.md)

```bash
az login --tenant <managing-tenant-id>
git clone -b analyst-local https://github.com/riparino/ai-soc-agent-for-microsoft-sentinel.git
cd ai-soc-agent-for-microsoft-sentinel/backend
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt   # Windows: .\venv\Scripts\Activate.ps1
cp .env.example .env                            # set AZURE_TENANT_ID; the rest is pre-set for analysts
./run-mcp.sh --discover-workspaces              # builds workspaces.json from Azure Resource Graph with your login
./run-mcp.sh --check                            # Windows: .\run-mcp.ps1 --check
./run-mcp.sh --print-config claude-desktop      # paste into your MCP client (or: vscode, claude-code)
```

## How it works

- **Identity.** `AZURE_AUTH_MODE=user` builds an Azure CLI / PowerShell / Developer
  CLI credential chain. One `az login` to the managing tenant is enough: Lighthouse
  projects every delegated subscription into that session, and the analysts' group
  holds **Microsoft Sentinel Responder** in each customer delegation, which covers
  incidents *and* KQL (`Microsoft.OperationalInsights/workspaces/query/*/read`).
- **Fleet.** `--discover-workspaces` runs an Azure Resource Graph query at tenant
  scope (the portal's *Open query* equivalent) and writes `workspaces.json` with
  coordinates only. Incident refs are namespaced `<workspace_id>::<incident_guid>`,
  so every tool call routes to the right customer workspace.
- **Hunting.** Which tables a workspace ingests is read from its `Usage` table; the
  catalog of 31 entity-driven KQL hunts (Entra sign-in / non-interactive / service
  principal / managed identity / audit / risk, Defender XDR `Device*`,
  `IdentityLogonEvents`, `EmailEvents`, `CloudAppEvents`, `AzureActivity`,
  `AzureDiagnostics`, `SecurityEvent`, `OfficeActivity`, `CommonSecurityLog`,
  `Syslog`, `SecurityAlert`, both TI tables) is selected by the incident's
  accounts, IPs, hosts, hashes, URLs, apps and resources. Skipped hunts say why.
- **Triage.** Claims the incident (Sentinel owner = the lock, ETag-conditional),
  extracts entities, checks intel, runs the hunts. With no server-side LLM — the
  normal local setup — it returns an **evidence pack** and the MCP client reasons
  to the verdict; with Azure OpenAI configured the server writes the verdict and
  posts it as a comment. Repeat triage within 30 minutes is deduplicated.
- **No mock data, ever, outside `DEMO_MODE`.** A failed call returns a structured
  error (`error`, `message`, `what_to_check`, `tell_admin`) instead of sample rows,
  a fabricated alert or an invented score. `./run-mcp.sh --check` prints a block
  analysts can paste to the admin.
- **Scope.** Microsoft Sentinel only. No Entra ID / Microsoft Graph or Defender
  XDR *actions* (Lighthouse doesn't delegate them); XDR *telemetry* already in
  Sentinel is hunted like any other table.

## Tools (14)

| Tool | Kind | Purpose |
|------|------|---------|
| `sentinel_list_workspaces` | read | The fleet: ids and tenant / subscription / resource-group coordinates |
| `sentinel_list_incidents` | read | Summaries across one / several / `all` workspaces, filters + limit, per-workspace errors |
| `sentinel_get_incident` | read | Entities, alerts, comments, owner, etag, classification |
| `sentinel_extract_indicators` | read | Flat, deduped IOC lists for hand-off to intel / asset tools |
| `sentinel_list_tables` | read | Tables the workspace ingests (from `Usage`) and which hunts that supports |
| `sentinel_hunt_incident` | read | Runs the hunt catalog for an incident; `dry_run` returns the KQL only |
| `sentinel_run_kql` | read | Ad-hoc KQL against any ingested table |
| `sentinel_triage_incident` | write | Claim + hunts + intel → verdict (server LLM) or evidence pack |
| `sentinel_get_triage_report` | read | Fetch an existing result |
| `sentinel_check_ip_reputation` / `sentinel_check_file_hash` | read | AbuseIPDB / VirusTotal when keys are set, else `NOT_CONFIGURED` |
| `sentinel_add_comment` | write | Post a note to the incident in its tenant |
| `sentinel_update_incident_status` | destructive | Status / severity / classification / labels; closing needs a classification; ETag-protected |
| `sentinel_assign_incident` | write | Assign by UPN / unassign; `only_if_unassigned` for safe claims; ETag-protected |

Details, transports and (optional) team hosting with Entra ID bearer auth:
[`backend/docs/MCP_SERVER.md`](backend/docs/MCP_SERVER.md). Adding it to a Copilot
Studio agent: [`backend/docs/COPILOT_STUDIO.md`](backend/docs/COPILOT_STUDIO.md).

## Configuration (`backend/.env`)

| Key | Analyst value | Notes |
|-----|---------------|-------|
| `DEMO_MODE` | `False` | `True` = built-in sample fleet and simulated results, for trying the tools without Azure |
| `AZURE_AUTH_MODE` | `user` | `service_principal` / `managed_identity` for hosted deployments |
| `AZURE_TENANT_ID` | managing tenant id | the only value an analyst must fill in |
| `WORKSPACES_CONFIG_PATH` | `./workspaces.json` | generated by `--discover-workspaces`; relative paths resolve against `backend/` |
| `AZURE_OPENAI_*` / `OPENAI_API_KEY` | empty | optional server-side verdicts |
| `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` | empty | optional external intel |
| `TRIAGE_CLAIM_ON_RUN` / `TRIAGE_DEDUPE_MINUTES` | `True` / `30` | analyst coordination |
| `HUNT_TABLE_LOOKBACK_DAYS` / `HUNT_MAX_QUERIES` / `HUNT_MAX_ROWS` | `7` / `12` / `25` | hunting limits |
| `MCP_*` | defaults | only for the HTTP transport (team hosting) |

## When something fails

Every error carries `what_to_check` (for the analyst) and, when it isn't theirs to
fix, `tell_admin` (the sentence to send). Codes: `NOT_AUTHENTICATED`,
`FLEET_NOT_CONFIGURED`, `WORKSPACE_UNKNOWN`, `FORBIDDEN`, `WORKSPACE_NOT_FOUND`,
`INCIDENT_NOT_FOUND`, `CONFLICT`, `THROTTLED`, `AZURE_UNAVAILABLE`, `NETWORK`,
`NETWORK_TIMEOUT`, `UNEXPECTED`; KQL hunts carry `TABLE_NOT_FOUND` /
`QUERY_INVALID` / `FORBIDDEN`; intel lookups `NOT_CONFIGURED`. The full table with
meanings and actions is in the runbook, section 8.

## For the SOC admin

- **Lighthouse**: authorize `lighthouse-sentinel-responders` with Microsoft Sentinel
  Responder in each customer delegation. That is the whole per-customer step.
- **Analysts** self-serve: clone, `az login`, `--discover-workspaces`, `--check`.
- **Verdicts**: leave the server LLM unset and let the MCP client reason, or set
  Azure OpenAI values for server-side verdicts posted as comments.
- **Hosting for a team / Copilot Studio** (optional, later): the same server runs
  the Streamable HTTP transport with Entra ID bearer auth — `MCP_SERVER.md`.

## Testing

```bash
cd backend
ruff check --select E9,F63,F7,F82,F app tests
pytest -q          # 85 tests: routing, discovery, hunting catalog, coordination, MCP protocol, Entra auth, live-mode guardrails
```

Tests run on the demo fleet (`tests/conftest.py` sets `DEMO_MODE=True`); the
live-mode guardrail tests flip it off to prove nothing is simulated.

## Repository layout

```
backend/
  app/mcp_server.py                 # the MCP server, CLI (--check, --discover-workspaces, --print-config)
  app/services/
    azure_credentials.py            # auth modes; signed-in identity for attribution
    workspace_registry.py           # the fleet: load, namespace, route
    workspace_discovery.py          # Azure Resource Graph -> workspaces.json
    sentinel_client.py              # Sentinel incidents API (ETag-conditional writes), demo mock
    kql_runner.py                   # Log Analytics queries, table discovery
    hunting_catalog.py / hunting.py # 31 KQL hunts, selection & execution
    indicators.py                   # entity -> indicator lists
    threat_intel.py                 # AbuseIPDB / VirusTotal / Sentinel TI tables
    triage_coordinator.py           # claim / dedupe / conflict handling
    errors.py                       # the analyst-facing error contract
  app/agent/                        # triage agent + prompt (verdict with LLM, evidence pack without)
  docs/                             # ANALYST_LOCAL_SETUP, MCP_SERVER, COPILOT_STUDIO
  tests/
  run-mcp.sh / run-mcp.ps1          # launchers
.githooks/pre-push                  # opt-in: refuse pushes to main
```

## Branch map

| Branch | Purpose |
|--------|---------|
| `analyst-local` | This branch: the per-analyst MCP server. Never merged to `main`. |
| `main` | The hosted web SOC console (FastAPI + React); the multi-tenant re-architecture PR (#1) lands there. |
| `claude/*` | Working branches behind pull requests; not for direct use. |
