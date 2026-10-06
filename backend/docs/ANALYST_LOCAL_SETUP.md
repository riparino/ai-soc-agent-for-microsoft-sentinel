# Run the Sentinel MCP server locally — analyst setup

Each analyst runs the MCP server **on their own machine** and uses it from Claude
Desktop, Claude Code or VS Code. There is no shared server, no open port and **no
secrets on the laptop**: the server authenticates to Azure as *you*, using your
`az login` session. Under Azure Lighthouse your own delegated Sentinel roles apply
across every customer workspace, and every comment, assignment or closure you make
is recorded in Sentinel under your name.

## What you need (one-time, from your SOC admin)

- Membership in the SOC analysts group that holds the Lighthouse authorizations
  (**Microsoft Sentinel Responder** + **Log Analytics Reader** on the customer
  subscriptions). Read-only role = you can list/triage but not comment or close.
- The fleet file `workspaces.json` (customer subscription / resource group /
  workspace names — no secrets).
- Python 3.11+, Git, and the **Azure CLI** (`az`).

## Setup

### macOS / Linux

```bash
az login --tenant <managing-tenant-id>             # your MSSP / home tenant
git clone -b analyst-local https://github.com/riparino/ai-soc-agent-for-microsoft-sentinel.git
cd ai-soc-agent-for-microsoft-sentinel/backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### Windows (PowerShell)

```powershell
az login --tenant <managing-tenant-id>
git clone -b analyst-local https://github.com/riparino/ai-soc-agent-for-microsoft-sentinel.git
cd ai-soc-agent-for-microsoft-sentinel\backend
python -m venv venv; .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

### `.env` — the only lines that matter for local use

```env
DEMO_MODE=False
AZURE_AUTH_MODE=user                     # use my az login session; no client secret
AZURE_TENANT_ID=<managing-tenant-id>     # the tenant you signed in to
WORKSPACES_CONFIG_PATH=./workspaces.json # the fleet file from your admin
MCP_DISABLED_TOOLS=sentinel_check_ip_reputation,sentinel_check_file_hash   # optional
```

Leave `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` empty. You don't need an Azure
OpenAI key either: when you use the server from Claude or Copilot, *that* model does
the reasoning; the server's own `sentinel_triage_incident` falls back to its built-in
deterministic engine unless you configure one.

Put `workspaces.json` next to `.env` (or point `WORKSPACES_CONFIG_PATH` at it).

### Check, then connect your client

```bash
./run-mcp.sh --check          # Windows: .\run-mcp.ps1 --check
```

You should see your name under *Signed in as*, the fleet listed, and `OK` beside
each workspace, then `READY`. Then print the config for your client and paste it:

```bash
./run-mcp.sh --print-config claude-desktop   # → Claude Desktop: Settings → Developer → Edit Config
./run-mcp.sh --print-config vscode           # → .vscode/mcp.json
./run-mcp.sh --print-config claude-code      # → prints the `claude mcp add …` command to run
```

The printed config uses this venv's Python and sets `PYTHONPATH`, so the client can
launch the server from any working directory; the server loads the backend `.env`
on its own. Restart the client and try:

> "List the open High incidents across all workspaces."
> "Extract the indicators from the newest one and summarize the risk."
> "Add a comment to that incident with your findings."

## Everyday use

- `az login` sessions expire (typically after your tenant's policy, often ~90 days
  of inactivity, sooner with Conditional Access). If tools start failing with 401,
  run `az login --tenant <managing-tenant-id>` again and retry.
- Destructive tools (close/classify, remediation) ask the client to confirm first.
  Closing requires a classification. Identity actions (revoke sessions, disable
  account) are refused for delegated tenants without a per-customer Graph app —
  that's expected (Azure Lighthouse doesn't delegate Microsoft Graph).
- Everything you do is attributed to you: audit comments read
  *"Your Name (you@mssp.example) via AI SOC Agent (MCP)"*, and Azure records your
  identity in the customer's activity log.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `--check` says *NOT LIVE - no usable credentials* | `.env` has `DEMO_MODE=False` and `AZURE_AUTH_MODE=user`? Then run `az login --tenant <managing-tenant-id>`. |
| *Signed in as: FAILED to obtain an ARM token* | No CLI session for that tenant: `az login --tenant …`. On Windows make sure `az` is on PATH for the same user. |
| A workspace shows `403` | Your account lacks a delegated role on that customer subscription — ask the admin to add you to the Lighthouse-authorized group. |
| A workspace shows `404` | Typo in the fleet file (subscription id / resource group / workspace name). |
| Client shows the server but tools error with *WORKSPACE_NOT_FOUND* | `WORKSPACES_CONFIG_PATH` doesn't resolve — use an absolute path. |
| Windows: *running scripts is disabled* | `powershell -ExecutionPolicy Bypass -File .\run-mcp.ps1 --check` |
| Browser login wanted instead of CLI | set `AZURE_INTERACTIVE_LOGIN=True` (opens a browser when no CLI session exists). |

## For the SOC admin: rolling this out

1. **Lighthouse**: assign Sentinel Responder + Log Analytics Reader to a security
   group (e.g. `SOC-Analysts`) in each customer delegation; add analysts to the
   group — no per-analyst Azure changes afterwards.
2. **Fleet file**: publish `workspaces.json` with coordinates only. Do **not** put
   per-customer `graph_client_secret` values in the analysts' copy; keep any
   Graph app registrations on a central server deployment.
3. **Updates**: analysts `git pull` and re-run `--check`. Pinning a release tag
   avoids surprise changes.
4. **Audit**: actions land in Sentinel comments under the analyst's identity and in
   the customer tenant's Azure Activity Log; the local server keeps no state worth
   backing up (triage reports are in-memory).
