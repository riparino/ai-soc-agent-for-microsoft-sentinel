# Run the Sentinel MCP server locally — analyst setup

Each analyst runs the MCP server **on their own machine** and uses it from Claude
Desktop, Claude Code or VS Code. There is no shared server, no open port and **no
secrets on the laptop**: the server authenticates to Azure as *you*, using your
`az login` session. Under Azure Lighthouse your own delegated Sentinel roles apply
across every customer workspace, and every comment, assignment or closure you make
is recorded in Sentinel under your name.

The scope is **Microsoft Sentinel only**: incidents, comments, status and
assignment, AI triage, and KQL against the customer's Log Analytics data. There are
no Entra ID (Microsoft Graph) or Defender XDR actions here — Azure Lighthouse
doesn't delegate those, and the Sentinel roles you already hold are all this needs.

## What you need (one-time, from your SOC admin)

- You should already be a member of **`lighthouse-sentinel-responders`**, the group
  that holds the Lighthouse authorizations (**Microsoft Sentinel Responder** +
  **Log Analytics Reader** on the customer subscriptions). Nothing to request —
  if a customer workspace later shows `403`, that group's delegation is what to check.
- Our managing tenant ID.
- Python 3.11+, Git, and the **Azure CLI** (`az`).

You generate the fleet file (`workspaces.json`) yourself in step 3 — it comes from
Azure Resource Graph using your own login, so it lists exactly the customer
workspaces you can see.

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

### Generate the fleet file (`workspaces.json`)

```bash
./run-mcp.sh --discover-workspaces        # Windows: .\run-mcp.ps1 --discover-workspaces
```

This runs an **Azure Resource Graph** query at tenant scope with your `az login`
identity. Resource Graph includes every Azure Lighthouse-delegated subscription you
can read, so the result is the full list of customer Sentinel workspaces you have
access to — subscription, resource group, workspace name, Log Analytics GUID and the
customer tenant ID — written to `backend/workspaces.json` next to `.env`.

- Re-run it any time a customer is onboarded or offboarded. It **merges**: ids,
  display names and the managing-tenant flag you edited by hand are kept,
  coordinates are refreshed, new workspaces are appended, and workspaces you can no
  longer see are kept but flagged.
- `--dry-run` prints the file instead of writing it; `--include-all-workspaces` also
  lists Log Analytics workspaces that aren't Sentinel-enabled.
- Portal equivalent: in the Azure portal's **Microsoft Sentinel** (or Log Analytics
  workspaces) list, **Open query** opens Azure Resource Graph Explorer with the same
  data; **Run query → Download as CSV** gives you the list by hand. The tool just
  saves you the CSV-to-JSON step. The query it runs:

  ```kusto
  resources
  | where type =~ 'microsoft.operationalinsights/workspaces'
  | join kind=inner (
      resources
      | where type =~ 'microsoft.operationsmanagement/solutions' and name startswith 'SecurityInsights('
      | project id = tolower(tostring(properties.workspaceResourceId)))
    on $left.['id'] == $right.['id']
  | project name, resourceGroup, subscriptionId, tenantId, customerId = tostring(properties.customerId)
  ```

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
- **Triage claims the incident for you.** `sentinel_triage_incident` first assigns an
  unassigned incident to you (Sentinel's owner field is the lock, and the write is
  ETag-conditional), so two analysts can't both end up triaging the same incident:
  if a colleague already owns it you get *ALREADY_ASSIGNED* with their name instead
  of a duplicate investigation, and if it was AI-triaged in the last 30 minutes you
  get *RECENTLY_TRIAGED* pointing at the existing findings. Add `force=true` to run
  anyway (it never takes ownership away from anyone). Status changes and assignments
  are ETag-protected too: a concurrent edit returns *CONFLICT* — re-read and retry.
- Closing / reclassifying is marked destructive, so the client asks you to confirm
  first, and closing always requires a classification. To close a false positive,
  set status *Closed* with classification *FalsePositive* and a reason.
- Everything you do is attributed to you: audit comments read
  *"Your Name (you@mssp.example) via AI SOC Agent (MCP)"*, and Azure records your
  identity in the customer's activity log.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `--check` says *NOT LIVE - no usable credentials* | `.env` has `DEMO_MODE=False` and `AZURE_AUTH_MODE=user`? Then run `az login --tenant <managing-tenant-id>`. |
| *Signed in as: FAILED to obtain an ARM token* | No CLI session for that tenant: `az login --tenant …`. On Windows make sure `az` is on PATH for the same user. |
| A workspace shows `403` | `lighthouse-sentinel-responders` isn't authorized on that customer's delegation (or you've dropped out of the group). Ask the admin. |
| A workspace shows `404` | Typo in the fleet file (subscription id / resource group / workspace name). |
| `--check` says *fleet file not found* / only sample workspaces load | Run `./run-mcp.sh --discover-workspaces`, or point `WORKSPACES_CONFIG_PATH` at your file (relative paths resolve against the `backend` folder). |
| Discovery finds fewer customers than you expect | Resource Graph only returns what your account can read: ask the admin to confirm the `lighthouse-sentinel-responders` delegation covers that customer. |
| Windows: *running scripts is disabled* | `powershell -ExecutionPolicy Bypass -File .\run-mcp.ps1 --check` |
| Browser login wanted instead of CLI | set `AZURE_INTERACTIVE_LOGIN=True` (opens a browser when no CLI session exists). |

## For the SOC admin: rolling this out

1. **Lighthouse**: `lighthouse-sentinel-responders` carries Sentinel Responder +
   Log Analytics Reader in each customer delegation; analysts are already members,
   so onboarding a customer means authorizing that group in the new delegation —
   no per-analyst Azure changes.
2. **Fleet file**: analysts generate their own with `--discover-workspaces`
   (Azure Resource Graph, scoped to what their account can read). If you prefer a
   curated list, publish `workspaces.json` yourself — it holds workspace
   coordinates only, no secrets.
3. **Updates**: analysts `git pull` and re-run `--check`. Pinning a release tag
   avoids surprise changes.
4. **Audit**: actions land in Sentinel comments under the analyst's identity and in
   the customer tenant's Azure Activity Log; the local server keeps no state worth
   backing up (triage reports are in-memory).
