# Add Sentinel to a Copilot Studio agent (alongside other MCP servers)

This guide adds the Sentinel AI SOC Agent MCP server to an **existing Copilot
Studio agent** — for example one that already has threat-intelligence (Recorded
Future) and cloud-security (Wiz) MCP servers — so the orchestrator can chain:

> *Sentinel incident → extract indicators → enrich IPs/hashes with threat intel →
> look up hosts/resources in cloud inventory → write findings back to the incident
> → classify / remediate.*

Copilot Studio facts this guide relies on (verified against Microsoft Learn):

- Copilot Studio connects to MCP servers over **Streamable HTTP only** (SSE was
  dropped in Aug 2025) and needs **generative orchestration** enabled.
- It adds a server via the **MCP onboarding wizard** (*Tools → Add a tool → Model
  Context Protocol → New tool*): server name, **server description**, URL, and
  **OAuth 2.0 (Manual)**. After *Create* it shows a **callback/redirect URL** you must
  add to an Entra **client** app registration.
- Each MCP tool **counts against the agent's tool limit**, and the number of MCP
  servers used concurrently in one conversation is capped — keep the tool set lean.
- Tool descriptions come from the server and **can't be edited in Copilot Studio**;
  the orchestrator routes on the *server description* you type plus the tool
  descriptions the server publishes.
- Tools whose input schema uses `$ref`, `type` arrays, or nullable unions get
  **filtered or truncated**. This server publishes flat schemas (and a test guards
  that), so all tools survive import.

## 0. Decide which tools to expose

Because your agent already has dedicated intel and infra servers, disable the
overlapping built-in lookups so the orchestrator uses Recorded Future for intel
and the tool count stays small:

```env
MCP_DISABLED_TOOLS="sentinel_check_ip_reputation,sentinel_check_file_hash"
```

What remains is purely Sentinel: `sentinel_list_workspaces`, `sentinel_list_incidents`,
`sentinel_get_incident`, **`sentinel_extract_indicators`** (flat IOC lists for
hand-off), `sentinel_list_tenant_users`, `sentinel_triage_incident`,
`sentinel_get_triage_report`, `sentinel_run_kql`, `sentinel_add_comment`,
`sentinel_update_incident_status`, `sentinel_assign_incident`,
`sentinel_remediate_incident`.

## 1. Host the server on a public HTTPS URL

Copilot Studio can't reach `localhost`. Two options:

### a) Dev tunnel — quickest way to test from your laptop

```bash
# one-time: https://learn.microsoft.com/azure/developer/dev-tunnels/get-started
devtunnel user login
devtunnel create soc-mcp --allow-anonymous
devtunnel port create soc-mcp -p 8800
devtunnel host soc-mcp            # prints https://<id>-8800.<region>.devtunnels.ms
```

Run the server bound to all interfaces (the tunnel's `Host` header isn't loopback,
so a loopback bind would answer `421`) **with Entra auth on**, and tell it its
public URL:

```bash
cd backend
MCP_AUTH_MODE=entra \
MCP_ENTRA_TENANT_ID=<tenant-guid> \
MCP_ENTRA_AUDIENCE=<server-app-client-id> \
MCP_PUBLIC_URL=https://<id>-8800.<region>.devtunnels.ms/mcp \
MCP_DISABLED_TOOLS=sentinel_check_ip_reputation,sentinel_check_file_hash \
./run-mcp.sh --transport streamable-http --host 0.0.0.0
```

(`--allow-anonymous` only means the *tunnel* doesn't require a Microsoft login;
the server still enforces Entra bearer tokens.)

### b) Azure Container Apps — for the team

Build the existing image and run it with the MCP command (same image as the web
app; only the entrypoint differs):

```bash
az acr build -r <acr> -t sentinel-soc-agent:latest .
az containerapp create -n sentinel-soc-mcp -g <rg> --environment <aca-env> \
  --image <acr>.azurecr.io/sentinel-soc-agent:latest \
  --command python --args "-m" "app.mcp_server" "--transport" "streamable-http" "--host" "0.0.0.0" \
  --ingress external --target-port 8800 \
  --secrets azure-client-secret=<sp-secret> \
  --env-vars DEMO_MODE=false AZURE_TENANT_ID=<tenant> AZURE_CLIENT_ID=<sp-id> \
             AZURE_CLIENT_SECRET=secretref:azure-client-secret \
             WORKSPACES_CONFIG_PATH=/etc/sentinel/workspaces.json \
             MCP_AUTH_MODE=entra MCP_ENTRA_AUDIENCE=<server-app-client-id> \
             MCP_PUBLIC_URL=https://<app-fqdn>/mcp \
             MCP_DISABLED_TOOLS=sentinel_check_ip_reputation,sentinel_check_file_hash
```

Mount `workspaces.json` as a secret volume (or use `WORKSPACES_JSON`). Container
Apps terminates TLS, so `MCP_PUBLIC_URL` is `https://<app-fqdn>/mcp`. (AKS works
the same way: a second Deployment with that `command`, exposed under `/mcp`.)

## 2. Register two Entra apps

**Server app** (the API — `sentinel-soc-mcp`):
1. App registration → *Expose an API* → set Application ID URI `api://<server-client-id>`.
2. Add a scope `Sentinel.Triage` (admin consent). Note the **client ID** → `MCP_ENTRA_AUDIENCE`.

**Client app** (what Copilot Studio uses — `sentinel-soc-mcp-client`):
1. New **single-tenant** app registration, platform **Web** (confidential client;
   not "Mobile and desktop").
2. *Certificates & secrets* → create a client secret (copy it).
3. *API permissions → Add → APIs my organization uses →* `sentinel-soc-mcp` →
   delegated `Sentinel.Triage` → **Grant admin consent**.
4. Leave the redirect URI empty for now — Copilot Studio generates it in step 3.

## 3. Add the server in Copilot Studio

In your agent: **Tools → + Add a tool → Model Context Protocol → New tool**.

| Field | Value |
|-------|-------|
| Server name | `Microsoft Sentinel SOC` |
| Server description | *(see recommended text below)* |
| Server URL | `https://<your-host>/mcp` (must equal `MCP_PUBLIC_URL`) |
| Authentication | **OAuth 2.0 → Manual** |
| Client ID | client app's Application (client) ID |
| Client secret | the secret from step 2 |
| Authorization URL | `https://login.microsoftonline.com/<tenant-guid>/oauth2/v2.0/authorize` |
| Token URL template | `https://login.microsoftonline.com/<tenant-guid>/oauth2/v2.0/token` |
| Refresh URL | `https://login.microsoftonline.com/<tenant-guid>/oauth2/v2.0/token` |
| Scopes | `api://<server-client-id>/Sentinel.Triage offline_access` |

Select **Create**, then **copy the Redirect URL** it displays and add it to the
*client* app registration (*Authentication → Add a platform/URI → Web*). Back in
the wizard: **Next → Create a new connection → sign in** (as yourself) **→ Add to agent**.

**Recommended server description** (the orchestrator routes on this):

> Microsoft Sentinel security incidents across all managed customer workspaces
> (Azure Lighthouse). Use for anything about Sentinel incidents: list or filter
> incidents per customer workspace or fleet-wide, read an incident's entities,
> alerts and comments, extract its indicators (IPs, hosts, accounts, hashes) for
> enrichment with other tools, run KQL hunts in a workspace, run AI triage to get a
> verdict and root-cause analysis, add comments, assign, classify/close, and run
> containment actions. Not for general threat-intelligence or cloud-asset lookups —
> use the dedicated intel and cloud-security tools for those.

Because every Copilot Studio user signs in through the connection, tokens carry the
analyst's identity: `scp` includes `Sentinel.Triage`, the server validates it, and
audit comments posted to incidents are attributable per person.

## 4. Teach the agent the cross-tool workflow

Paste into the agent's **Instructions** (adapt tool names to your intel/cloud servers):

```text
You are a SOC analyst assistant with three tool sets: Microsoft Sentinel (incidents),
Recorded Future (threat intelligence), and Wiz (cloud assets and exposures).

When asked to investigate or triage a Sentinel incident:
1. If given an incident number rather than a ref, call sentinel_list_incidents
   (optionally with the customer's workspace) and match the incidentNumber; always
   use the returned namespaced id as incident_ref thereafter.
2. Call sentinel_extract_indicators to get the incident's IPs, hosts, accounts,
   hashes, URLs and Azure resources as lists.
3. Enrich: send IPs, hashes and URLs to Recorded Future; send hosts and
   azure_resources to Wiz for asset ownership, exposure and criticality.
4. Optionally call sentinel_triage_incident for the AI verdict and RCA, and
   sentinel_run_kql (with the incident's workspaceId) for targeted hunts.
5. Summarize: verdict, confidence, key evidence (cite the intel and asset findings),
   recommended actions. Then call sentinel_add_comment to record the enrichment
   summary on the incident.
6. Only change status/classification or run remediation after the analyst
   explicitly confirms. Closing requires a classification. If a remediation
   returns BLOCKED_GRAPH_SCOPE, explain that identity actions are not available
   for that delegated tenant and suggest the documented alternatives.

Incident refs look like "<workspace_id>::<guid>"; never invent them. Empty
parameter values mean "not set".
```

## 5. Test and publish

1. **Preview** the agent and ask: *"Show me the open High incidents across all
   workspaces."* Then: *"Extract indicators from the newest one and check them in
   Recorded Future; look the hosts up in Wiz."*
2. Open the **activity trace** to confirm which tools ran with what arguments.
3. **Publish** and add the **Teams** channel so the SOC can `@mention` it in a channel.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Tools missing after import | A schema construct Copilot Studio drops. All tools here are flat; if you added a tool, run `pytest -k copilot` to check. |
| `401` when the agent calls a tool | Token audience/scope mismatch: `MCP_ENTRA_AUDIENCE` must be the *server* app id; the wizard's scope must be `api://<server-id>/Sentinel.Triage`; admin consent granted on the client app. |
| `421 Misdirected Request` | Server bound to loopback behind a tunnel/proxy. Start with `--host 0.0.0.0` (and Entra auth). |
| Resource metadata points to the wrong host | `MCP_PUBLIC_URL` must be the exact public URL (`https://…/mcp`). |
| Orchestrator picks the wrong server | Sharpen the **server description**; disable overlapping tools with `MCP_DISABLED_TOOLS`. |
| Connector blocked | Power Platform **DLP policies** govern MCP connectors; have an admin allow the connector in the environment. |
