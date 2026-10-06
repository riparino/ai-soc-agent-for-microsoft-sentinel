from pydantic_settings import BaseSettings
from typing import Optional, List

class Settings(BaseSettings):
    # Application Config
    APP_NAME: str = "Microsoft Sentinel AI Triage Agent"
    APP_ENV: str = "production"
    DEBUG: bool = False
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    CORS_ORIGINS: List[str] = ["*"]
    
    # JWT Authentication
    SECRET_KEY: str = "sentinel-super-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12 # 12 hours
    ADMIN_USERNAME: str = "soc_admin"
    ADMIN_PASSWORD: Optional[str] = None
    
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

    # Multi-workspace / multi-tenant fleet registry (Azure Lighthouse).
    # Provide the full fleet of delegated Microsoft Sentinel workspaces either as
    # an inline JSON array (WORKSPACES_JSON) or a path to a JSON file
    # (WORKSPACES_CONFIG_PATH). Each entry supports:
    #   id, display_name, tenant_id, subscription_id, resource_group,
    #   workspace_name, workspace_guid, is_managing_tenant,
    #   graph_tenant_id, graph_client_id, graph_client_secret
    # When neither is set the registry falls back to the single AZURE_* workspace
    # above (or demo workspaces in DEMO_MODE).
    WORKSPACES_JSON: Optional[str] = None
    WORKSPACES_CONFIG_PATH: Optional[str] = None
    
    # Simulation / Demo Mode (allows running standalone without live Azure credentials)
    DEMO_MODE: bool = True
    
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

    # Auto-Triage & Polling Settings
    ENABLE_AUTO_POLLING: bool = False
    POLL_INTERVAL_SECONDS: int = 120
    AUTO_POST_COMMENTS_TO_SENTINEL: bool = True
    AUTO_CLOSE_FALSE_POSITIVES: bool = False
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
