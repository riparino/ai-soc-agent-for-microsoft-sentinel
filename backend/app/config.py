import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Settings for the per-analyst Sentinel MCP server (loaded from backend/.env)."""

    APP_NAME: str = "Microsoft Sentinel AI SOC Agent (MCP)"
    DEBUG: bool = False

    # Azure Sentinel & Azure Resource Manager Config
    # These are the *managing (home) tenant* service-principal credentials. Under
    # Azure Lighthouse a single home-tenant SP can reach ARM + Log Analytics across
    # every delegated customer subscription, so these credentials are shared by the
    # whole workspace fleet. The per-workspace coordinates below describe only the
    # single/default (managing-tenant) workspace; the multi-workspace fleet is
    # defined via WORKSPACES_JSON / WORKSPACES_CONFIG_PATH (see workspace_registry).
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None
    AZURE_SUBSCRIPTION_ID: Optional[str] = None
    AZURE_RESOURCE_GROUP_NAME: Optional[str] = None
    AZURE_WORKSPACE_NAME: Optional[str] = None
    AZURE_WORKSPACE_ID: Optional[str] = None # Log Analytics Workspace ID (customerId GUID)
    USE_MANAGED_IDENTITY: bool = False

    # How this process authenticates to Azure (see services/azure_credentials.py):
    #   auto (default)     - USE_MANAGED_IDENTITY, else the service-principal secret above
    #   service_principal  - shared server deployments
    #   managed_identity   - AKS / Container Apps / VMs
    #   user               - the signed-in analyst (az login) - for running the MCP server
    #                        locally on each analyst's machine; no secrets on the laptop and
    #                        every Sentinel action is attributed to the analyst.
    AZURE_AUTH_MODE: str = "auto"
    # In user mode, fall back to an interactive browser login when no CLI session exists.
    AZURE_INTERACTIVE_LOGIN: bool = False

    # Multi-workspace / multi-tenant fleet registry (Azure Lighthouse).
    # Provide the full fleet of delegated Microsoft Sentinel workspaces either as
    # an inline JSON array (WORKSPACES_JSON) or a path to a JSON file
    # (WORKSPACES_CONFIG_PATH). Each entry supports:
    #   id, display_name, tenant_id, subscription_id, resource_group,
    #   workspace_name, workspace_guid, is_managing_tenant
    # When neither is set the registry falls back to the single AZURE_* workspace
    # above; with nothing configured it is empty (demo workspaces only in DEMO_MODE).
    WORKSPACES_JSON: Optional[str] = None
    WORKSPACES_CONFIG_PATH: Optional[str] = None
    
    # Demo mode: built-in sample workspaces/incidents and simulated query results,
    # for trying the tools with no Azure at all. OFF by default: a live install never
    # substitutes sample data for a failed call - failures are reported as errors.
    DEMO_MODE: bool = False
    
    # LLM Settings (Supports Azure OpenAI, OpenAI, or compatible APIs)
    LLM_PROVIDER: str = "azure_openai" # "azure_openai", "openai", "custom"
    OPENAI_API_KEY: Optional[str] = None
    AZURE_OPENAI_ENDPOINT: Optional[str] = None
    AZURE_OPENAI_API_KEY: Optional[str] = None
    AZURE_OPENAI_API_VERSION: str = "2024-02-15-preview"
    AZURE_OPENAI_DEPLOYMENT_NAME: str = "gpt-4o"
    
    # Threat Intelligence API Keys & Providers
    ABUSEIPDB_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ENABLE_MICROSOFT_THREAT_INTEL: bool = True
    MDTI_API_KEY: Optional[str] = None
    
    # MCP server (exposes the agent's tools to Claude, GitHub Copilot, Copilot Studio…)
    # Transport is chosen on the CLI (`python -m app.mcp_server --transport stdio|streamable-http`).
    # Auth applies to the HTTP transport only:
    #   none  - no bearer auth (local testing / stdio).
    #   entra - validate Microsoft Entra ID bearer tokens (JWKS) issued for MCP_ENTRA_AUDIENCE.
    MCP_AUTH_MODE: str = "none"
    MCP_HOST: str = "127.0.0.1"
    MCP_PORT: int = 8800
    MCP_PUBLIC_URL: Optional[str] = None            # e.g. https://soc-mcp.example.com/mcp
    MCP_ENTRA_TENANT_ID: Optional[str] = None       # defaults to AZURE_TENANT_ID
    MCP_ENTRA_AUDIENCE: Optional[str] = None        # app (client) ID or api://<id>; comma-separated list allowed
    MCP_REQUIRED_SCOPES: Optional[str] = None       # comma-separated scp/roles that must be present, e.g. Sentinel.Triage
    # Comma-separated tool names to NOT register. Keeps the tool count small when the
    # consuming agent already has other MCP servers covering a capability (e.g. a
    # Recorded Future server for threat intel), which matters because Copilot Studio
    # counts every MCP tool against the agent's tool limit.
    MCP_DISABLED_TOOLS: Optional[str] = None        # e.g. "sentinel_check_ip_reputation,sentinel_check_file_hash"

    # Triage coordination between analysts. Sentinel's incident owner is the lock:
    # when claiming is on, running triage first assigns an unassigned incident to the
    # running analyst (ETag-conditional write) and refuses to triage one that another
    # analyst already owns. Recently-triaged incidents (an AI triage comment younger
    # than TRIAGE_DEDUPE_MINUTES) are not re-triaged unless forced.
    TRIAGE_CLAIM_ON_RUN: bool = True
    TRIAGE_DEDUPE_MINUTES: int = 30

    # Hunting: which tables a workspace ingests is read from its Usage table over
    # this many days; at most HUNT_MAX_QUERIES catalog hunts run per triage, each
    # returning at most HUNT_MAX_ROWS rows to the analyst / model.
    HUNT_TABLE_LOOKBACK_DAYS: int = 7
    HUNT_MAX_QUERIES: int = 12
    HUNT_MAX_ROWS: int = 25

    # Post the AI triage report back to the incident as a comment (only when a verdict exists).
    AUTO_POST_COMMENTS_TO_SENTINEL: bool = True
    AUTO_CLOSE_FALSE_POSITIVES: bool = False
    
    class Config:
        # Load the backend's own .env regardless of the process working directory
        # (MCP clients such as Claude Desktop launch the server from an arbitrary
        # cwd); a .env in the cwd still takes precedence when present.
        env_file = (os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"), ".env")
        extra = "ignore"

settings = Settings()
