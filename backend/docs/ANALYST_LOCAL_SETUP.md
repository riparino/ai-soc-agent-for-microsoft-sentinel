# Run the Sentinel MCP server on your own machine — analyst setup

You get Microsoft Sentinel — every customer workspace delegated to us through
Azure Lighthouse — as tools inside Claude Desktop, Claude Code or VS Code. There
is no web app, no shared server and **no secrets on your laptop**: the server
runs as *you* (your `az login`), your Lighthouse-delegated **Microsoft Sentinel
Responder** role applies across every customer workspace, and every comment,
assignment or closure you make is recorded in Sentinel under your name.

Scope is **Microsoft Sentinel only**: incidents, comments, status and assignment,
hunting with KQL across whatever the customer ingests, and AI-assisted triage.
There are no Entra ID (Microsoft Graph) or Defender XDR *actions* — Lighthouse
doesn't delegate those — and nothing is ever simulated: if a call fails you get
an error that says what happened and what to tell the SOC admin.

## 1. Before you start

**From the SOC admin** — you should already have both:

- Membership of **`lighthouse-sentinel-responders`**, the group authorized with
  Microsoft Sentinel Responder in every customer delegation. That one role covers
  incidents *and* KQL (it carries `Microsoft.OperationalInsights/workspaces/query/*/read`).
- Our **managing tenant ID** (`<managing-tenant-id>` below).

**On your machine** — Python 3.11+, Git, the Azure CLI, and your MCP client:

| | macOS (Homebrew) | Windows (winget) |
|---|---|---|
| Python 3.11+ | `brew install python@3.12` | `winget install Python.Python.3.12` |
| Git | `brew install git` | `winget install Git.Git` |
| Azure CLI | `brew install azure-cli` | `winget install Microsoft.AzureCLI` |

Open a new terminal after installing so `az`, `git` and `python` are on PATH.
MCP client: Claude Desktop, Claude Code, or VS Code with GitHub Copilot.

## 2. Sign in, clone, install

Clone the **`analyst-local`** branch specifically — the default branch is the
hosted web console and does not contain this server.

**macOS / Linux**

```bash
az login --tenant <managing-tenant-id>
git clone -b analyst-local https://github.com/riparino/ai-soc-agent-for-microsoft-sentinel.git
cd ai-soc-agent-for-microsoft-sentinel/backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

**Windows (PowerShell)**

```powershell
az login --tenant <managing-tenant-id>
git clone -b analyst-local https://github.com/riparino/ai-soc-agent-for-microsoft-sentinel.git
cd ai-soc-agent-for-microsoft-sentinel\backend
python -m venv venv; .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

`az login` opens a browser; pick your work account. If you have several tenants,
`--tenant` makes sure the session is for the managing tenant (where the Lighthouse
delegations are projected).

## 3. Configure `.env` and generate your workspace list

Open `backend/.env` and set **one** line — everything else already has the right
defaults for an analyst machine:

```env
AZURE_TENANT_ID="<managing-tenant-id>"
```

(`DEMO_MODE=False`, `AZURE_AUTH_MODE=user` and `WORKSPACES_CONFIG_PATH=./workspaces.json`
are already set. Leave the OpenAI and threat-intel keys empty: your MCP client is
the reasoning engine.)

Then generate the customer workspace list with your own login:

```bash
./run-mcp.sh --discover-workspaces          # Windows: .\run-mcp.ps1 --discover-workspaces
```

This runs an **Azure Resource Graph** query at tenant scope — the same data as the
**Open query** button on the Microsoft Sentinel workspace list in the Azure portal.
Lighthouse projects every delegated subscription into your session, so the result
is every customer Sentinel workspace you can read: subscription, resource group,
workspace name, Log Analytics GUID and tenant ID, written to `backend/workspaces.json`
next to `.env` (coordinates only, no secrets).

- Re-run it whenever a customer is onboarded or offboarded. It **merges**: ids and
  display names you edited by hand are kept, coordinates are refreshed, new
  workspaces are appended, and workspaces you can no longer see are kept but flagged.
- `--dry-run` prints the file instead of writing it; `--include-all-workspaces`
  also lists Log Analytics workspaces that aren't Sentinel-enabled.

## 4. Check the install

```bash
./run-mcp.sh --check                        # Windows: .\run-mcp.ps1 --check
```

You should see your own name under **Signed in as**, every workspace **OK**,
**KQL: OK**, and **READY** at the end. If not, the output names the fix, and when
it can't be fixed from your side it prints a block that starts with
`--- sentinel-mcp check ---` — **copy that block to the SOC admin**. It contains no
secrets (your UPN, tenant, versions and the failing items).

## 5. Connect your client

```bash
./run-mcp.sh --print-config claude-desktop  # or: vscode | claude-code
```

| Client | Paste the printed snippet into |
|--------|-------------------------------|
| Claude Desktop | Settings → Developer → Edit Config (`claude_desktop_config.json`), then restart Claude Desktop |
| VS Code (GitHub Copilot) | `.vscode/mcp.json` in your workspace |
| Claude Code | It prints a `claude mcp add …` command — run it |

The snippet points at this install's Python and sets `PYTHONPATH`, so the client
can start the server from any folder. On Windows use `.\run-mcp.ps1` wherever
you see `./run-mcp.sh`.

## 6. Use it

Ask your client things like:

- "List the open High incidents across all workspaces."
- "Open the newest one and extract its indicators."
- "Which tables does the Fabrikam workspace ingest?"
- "Hunt this incident" / "Show me the hunts you would run" (dry run with the KQL).
- "Run a KQL query for failed sign-ins in that workspace over the last 24 hours."
- "Triage this incident."
- "Add a comment with our conclusion." / "Close it as a false positive, reason: authorized scanner."

**What triage does.** `sentinel_triage_incident` claims the incident for you if it
is unassigned, extracts the entities, checks threat intel, reads which tables the
workspace ingests and runs the matching hunts from the catalog. Because no model
runs on your laptop, it then returns an **evidence pack** (`status:
EVIDENCE_COLLECTED`, `verdict: null`): the hunt results with their exact KQL, intel
results, data coverage and gaps, alerts and comments. **Your MCP client is the
analyst's AI**: it reasons over that evidence, proposes TRUE / FALSE POSITIVE or
ESCALATE with the gaps named, and records the conclusion with
`sentinel_add_comment`. (If the admin configures a server-side Azure OpenAI
deployment, the server writes the verdict itself and posts it as a comment.)

**No collisions between analysts.** Sentinel's incident *owner* is the lock. If a
colleague already owns the incident you get `ALREADY_ASSIGNED` with their name; if
it was AI-triaged in the last 30 minutes you get `RECENTLY_TRIAGED` pointing at the
existing findings; `force=true` runs anyway without taking ownership. Status
changes and assignments are ETag-protected: a concurrent edit returns `CONFLICT` —
re-read and retry.

**Closing** is marked destructive, so the client asks you to confirm, and closing
always requires a classification (for a false positive: status *Closed*,
classification *FalsePositive*, a reason).

## 7. What triage actually looks at

Triage and `sentinel_hunt_incident` don't run a fixed pair of queries. For each
incident the server first reads the workspace's **`Usage`** table to learn which
Log Analytics tables received data in the last 7 days, then runs the hunts from the
catalog (`app/services/hunting_catalog.py`, 31 hunts) whose tables exist and whose
indicators the incident has — accounts, IPs, hosts, hashes, URLs, apps, resources:

| Family | Tables | What it pivots on |
|--------|--------|-------------------|
| Entra ID | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs`, `AADRiskyUsers`, `AADUserRiskEvents`, `AADRiskyServicePrincipals`, `AADServicePrincipalRiskEvents` | interactive & token sign-in baselines, who else used the incident IPs, workload-identity sign-ins, risk state & detections, directory changes |
| Defender XDR telemetry | `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceEvents`, `DeviceInfo`, `DeviceRegistryEvents`, `IdentityLogonEvents`, `EmailEvents`, `EmailUrlInfo`, `CloudAppEvents` | endpoint logons, LOLBin / encoded command lines, connections to the C2, hash sightings & executions, device inventory, AV/ASR/tamper events, registry persistence, on-prem AD logons, phishing mail & URLs, SaaS activity |
| Azure | `AzureActivity`, `AzureDiagnostics` | control-plane operations and resource logs (Key Vault, Firewall, SQL, App Gateway…) by the accounts / from the IPs / on the resources |
| Security logs | `SecurityEvent`, `OfficeActivity`, `CommonSecurityLog`, `Syslog` | Windows logon / process / account events, M365 operations, firewall & proxy sessions, Linux auth |
| Alerts & TI | `SecurityAlert`, `ThreatIntelIndicators`, `ThreatIntelligenceIndicator` | other alerts naming the same entities; TI matches on IPs, URLs, domains, hashes |

- Tables the customer doesn't ingest are **skipped and listed**, so the result says
  what it could *not* see. If `Usage` can't be read, every applicable hunt runs and
  a missing table shows up as a `TABLE_NOT_FOUND` error on that hunt.
- Every hunt result carries its exact KQL; refine it with `sentinel_run_kql`.
- A failed query is reported (`TABLE_NOT_FOUND`, `QUERY_INVALID`, `FORBIDDEN`…),
  never replaced with sample rows.
- Need another pivot? Add a `Hunt(...)` to the catalog: table(s), indicator kinds,
  window, purpose, KQL template. Triage and the MCP tool pick it up automatically.

## 8. If something fails

Every tool error is an object with `error`, `message`, `what_to_check` and, when
it isn't yours to fix, `tell_admin` — the exact sentence to send. Your MCP client
will show these to you; here is what they mean:

| `error` | What happened | You | Tell the admin |
|---------|---------------|-----|----------------|
| `NOT_AUTHENTICATED` | No Azure token: `az login` expired or is for another tenant | `az login --tenant <managing-tenant-id>`, then `--check` | — |
| `FLEET_NOT_CONFIGURED` | `workspaces.json` missing/empty | `./run-mcp.sh --discover-workspaces` | — |
| `WORKSPACE_UNKNOWN` | A workspace id that isn't in your file | Use `sentinel_list_workspaces`; re-run discovery if the customer is new | — |
| `FORBIDDEN` (403) | No Sentinel Responder on that workspace | Check `az account show` is the managing tenant; if only one customer fails it's their delegation | Yes — paste `tell_admin` (names the customer) |
| `WORKSPACE_NOT_FOUND` (404) | Stale coordinates (renamed / moved / offboarded) | Re-run discovery | If it still 404s |
| `INCIDENT_NOT_FOUND` | Wrong or deleted incident ref | Use the ref from `sentinel_list_incidents` | — |
| `CONFLICT` | Someone changed the incident a moment ago | Re-read, then retry | — |
| `ALREADY_ASSIGNED` / `RECENTLY_TRIAGED` | Not an error: a colleague has it | Coordinate, or `force=true` | — |
| `THROTTLED` (429) | Azure rate limit | Wait a minute; query one workspace instead of `all` | — |
| `AZURE_UNAVAILABLE` (5xx) | Azure-side problem | Retry later; check status.azure.com | If it persists |
| `NETWORK` / `NETWORK_TIMEOUT` | Can't reach Azure | VPN / proxy must allow management.azure.com, login.microsoftonline.com, api.loganalytics.io | If your network needs an allow-list |
| KQL `TABLE_NOT_FOUND` / `QUERY_INVALID` | Table not ingested / bad KQL | Check `sentinel_list_tables`; fix the query | A catalog hunt that fails everywhere (one-line fix) |
| `NOT_CONFIGURED` (threat intel) | No AbuseIPDB / VirusTotal key on this server | Use your other intel tool; optional key in `.env` | — |
| `EVIDENCE_COLLECTED` (triage) | Not an error: no server LLM, your client reasons over the evidence | Ask the client for its verdict | — |
| `UNEXPECTED` | A bug or environment problem | Re-run `--check` | Yes — `--check` block + the error block |

`--check` problems and fixes:

| Symptom | Fix |
|---------|-----|
| *NOT LIVE - no usable credentials* | `.env` has `DEMO_MODE=False` and `AZURE_AUTH_MODE=user`? Then `az login --tenant <managing-tenant-id>`. |
| *FAILED to obtain an ARM token (…)* | The bracket has azure-identity's reason: no CLI session (`az login`), `az` not on PATH (reopen the terminal / reinstall), or wrong tenant. |
| *token tenant … differs from AZURE_TENANT_ID* | `az login --tenant <managing-tenant-id>` |
| A workspace shows `403` | `lighthouse-sentinel-responders` isn't authorized on that customer's delegation. Send the line to the admin. |
| A workspace shows `404` | Re-run `--discover-workspaces`. |
| *KQL: FAILED … FORBIDDEN* | Your role reaches incidents but not log data — unusual with Sentinel Responder; send the block to the admin. |
| *fleet file not found* / fewer customers than expected | Run `--discover-workspaces`. It lists only what your account can read, so a missing customer means a missing delegation — tell the admin which. |
| Tools stop working after days | `az login` expired. Sign in again; nothing else changes. |
| Windows: *running scripts is disabled* | `powershell -ExecutionPolicy Bypass -File .\run-mcp.ps1 --check` |
| The client says the server didn't start | Run `./run-mcp.sh --check` in a terminal; the client swallows startup errors, the terminal shows them. |

**What to send the admin:** the `--- sentinel-mcp check ---` block from `--check`
(or the tool's error block incl. `tell_admin`), the workspace id / incident ref,
and what you asked the client to do. No secrets are in any of it.

## 9. Updating

```bash
cd ai-soc-agent-for-microsoft-sentinel && git pull && cd backend
source venv/bin/activate && pip install -r requirements.txt     # Windows: .\venv\Scripts\Activate.ps1
./run-mcp.sh --check
```

## For the SOC admin: rolling this out

1. **Lighthouse**: `lighthouse-sentinel-responders` carries **Microsoft Sentinel
   Responder** in each customer delegation (incidents + KQL); analysts are already
   members, so onboarding a customer means authorizing that group in the new
   delegation — no per-analyst Azure changes. Analysts `az login` to the managing
   tenant once; Lighthouse projects every delegated workspace into that session.
2. **Fleet file**: analysts generate their own with `--discover-workspaces`
   (Azure Resource Graph, scoped to what their account can read). If you prefer a
   curated list, publish `workspaces.json` yourself — coordinates only, no secrets.
3. **No sample data, no invented verdicts**: `DEMO_MODE=False` is the default. A
   failed call is an error with `tell_admin`; triage without a server LLM is an
   evidence pack. If you want server-side verdicts, set the Azure OpenAI values in
   `.env` on the analysts' machines (or host the server — see `MCP_SERVER.md`).
4. **Updates**: analysts `git pull` and re-run `--check`. Pinning a release tag
   avoids surprise changes.
5. **Audit**: actions land in Sentinel comments under the analyst's identity and in
   the customer tenant's Azure Activity Log; the local server keeps no state worth
   backing up.
6. **Branch rule**: this code lives on `analyst-local` only. **Never push it to
   `main`** (the hosted web console) or merge `main` back in. Opt-in guard for your
   clone: `git config core.hooksPath .githooks` makes git refuse a push to `main`.
