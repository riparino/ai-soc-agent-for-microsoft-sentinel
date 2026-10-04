# Multi-Workspace / Multi-Tenant Architecture (Azure Lighthouse Fleet)

The AI SOC Agent manages a **fleet** of Microsoft Sentinel workspaces that live in
delegated customer tenants (an Azure Lighthouse deployment) from **one** running
instance. This document describes how workspace context flows through the backend,
how incidents are routed, and the important Microsoft Graph limitation.

## Key idea: one credential, many workspaces

Under **Azure Lighthouse**, a single service principal in the **managing (home)
tenant** can reach **Azure Resource Manager** (`management.azure.com`) and **Log
Analytics** (`api.loganalytics.io`) across every delegated customer subscription.
So the ARM and Log Analytics tokens are **shared** by the whole fleet — the only
per-workspace data we need is the customer's subscription / resource group /
workspace coordinates.

The managing-tenant credentials remain in `settings` (`AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, or managed identity). They are **auth**
config, not workspace context.

## The workspace registry

`app/services/workspace_registry.py` is the single source of truth for the fleet.
Each workspace is a `WorkspaceConfig`:

| Field | Meaning |
|-------|---------|
| `id` | Stable, URL-safe id used to **namespace incident IDs** |
| `display_name` | Human-friendly name shown in the UI selector |
| `tenant_id` | Customer tenant GUID |
| `subscription_id`, `resource_group`, `workspace_name` | ARM coordinates |
| `workspace_guid` | Log Analytics `customerId` GUID (auto-resolved via ARM if omitted) |
| `is_managing_tenant` | True for the workspace in the home tenant |
| `graph_tenant_id`, `graph_client_id`, `graph_client_secret` | Optional per-customer Microsoft Graph app registration |

### Where the fleet is loaded from (in priority order)

1. **`WORKSPACES_JSON`** — an inline JSON array of workspace entries.
2. **`WORKSPACES_CONFIG_PATH`** — a path to a JSON file (array, or `{ "workspaces": [...] }`).
   This scales comfortably to ~hundreds of entries.
3. **Legacy single workspace** — the single `AZURE_*` coordinates (treated as the
   managing-tenant workspace). Fully backward compatible.
4. **Demo seed** — two demo workspaces (`contoso`, `fabrikam`) when nothing is
   configured, so routing and aggregation are demonstrable without live Azure.

See [`workspaces.example.json`](../workspaces.example.json) for the file format.

## Request routing via namespaced incident IDs

Incidents are **namespaced** so a request always routes back to the workspace the
incident belongs to. The list/stats endpoints return incident IDs of the form:

```
<workspace_id>::<raw_incident_guid>
```

Every subsequent call (`get_incident`, triage, chat, comment, status update,
assignment, remediation, the triage WebSocket) carries this namespaced ref, and the
backend resolves the owning `WorkspaceConfig` from the ref — no global state, no
extra parameter required. Each incident also carries `workspaceId`,
`workspaceName`, and `workspaceTenantId` fields for display and aggregation.

### Workspace selection

`GET /api/incidents` and `GET /api/incidents/stats/summary` accept a `workspace`
query parameter:

* omitted / `all` → **aggregate the whole fleet**
* a single id (e.g. `contoso`) → one workspace
* a comma-separated list (e.g. `contoso,fabrikam`) → a subset

The frontend exposes this as a workspace/tenant dropdown in the incident queue, and
shows the origin workspace on each incident row when aggregating. The stats response
includes a `per_workspace` breakdown.

`GET /api/incidents/workspaces` returns the (secret-free) fleet for the selector.

## ⚠️ Microsoft Graph does NOT honor Azure Lighthouse

Azure Lighthouse delegates **ARM and Log Analytics** only. **Microsoft Graph**
(`graph.microsoft.com`) is **not** delegated: a Graph token minted with the
home-tenant service principal can only ever see the **home tenant's** directory.

This affects two features: **listing Entra ID users** (`get_entra_users`) and
**identity remediation** (revoke sign-in sessions, disable account).

The registry records a per-workspace `graph_mode` that decides behavior:

| `graph_mode` | When | Directory read | Identity write (revoke/disable) |
|--------------|------|----------------|---------------------------------|
| `managing-tenant` | workspace is in the home tenant | Microsoft Graph (home SP) | ✅ allowed |
| `delegated-app` | per-customer Graph app configured (`graph_*` fields) | Microsoft Graph (customer app) | ✅ allowed |
| `log-analytics-only` | delegated tenant, no per-customer Graph app | **SigninLogs telemetry** (via Lighthouse-honored Log Analytics) | ❌ **blocked** |

### What the backend does

* **Listing users**: for `log-analytics-only` workspaces, directory data is derived
  from that workspace's own `SigninLogs` telemetry (which *is* reachable through
  Lighthouse) instead of Graph. The `source` field on each user indicates the
  origin.
* **Identity remediation**: `revoke_sessions` / `disable_account` on a
  `log-analytics-only` workspace are **refused** with a clear
  `BLOCKED_GRAPH_SCOPE` result and an audit comment, rather than silently
  pretending to succeed. ARM/Defender-based actions (`isolate_endpoint`,
  `block_ip`, `trigger_playbook`, `close_false_positive`) work across the fleet
  because they go through ARM / Defender, not Graph.

### How to enable identity features for a delegated customer

Register an application **in the customer tenant**, grant it the required Graph
application permissions (e.g. `User.Read.All`, `User.ReadWrite.All` for disabling
accounts), obtain admin consent, and add its credentials to that workspace's
registry entry:

```json
{
  "id": "fabrikam",
  "display_name": "Fabrikam Inc",
  "tenant_id": "<fabrikam-tenant-guid>",
  "subscription_id": "...",
  "resource_group": "...",
  "workspace_name": "fabrikam-sentinel",
  "graph_tenant_id": "<fabrikam-tenant-guid>",
  "graph_client_id": "<app-id-in-fabrikam>",
  "graph_client_secret": "<secret>"
}
```

The workspace's `graph_mode` then becomes `delegated-app` and identity features are
enabled for it. Otherwise, scope those features to the managing tenant and treat the
`BLOCKED_GRAPH_SCOPE` responses as expected behavior.

## Tests

`tests/test_workspace_routing.py` exercises the registry, incident namespacing,
per-workspace selection and aggregation, ref-based routing, and the Graph scope
limitation — all through the in-memory mock path in `services/sentinel_client.py`
(no live Azure required).
