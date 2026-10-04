import logging
import secrets
from pydantic_settings import BaseSettings
from typing import Optional, List

# Known-insecure value that shipped as the historical default. It is treated as
# "unset" everywhere so a deployment can never silently run with a public key.
INSECURE_DEFAULT_SECRET_KEY = "sentinel-super-secret-key-change-in-production-2026"

class Settings(BaseSettings):
    # Application Config
    APP_NAME: str = "Microsoft Sentinel AI Triage Agent"
    APP_ENV: str = "production"
    DEBUG: bool = False
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    # Explicit allow-list of browser origins. Never use "*" together with
    # credentialed requests. Override via the CORS_ORIGINS env var in production.
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]

    # JWT Authentication. SECRET_KEY has no usable default: it must be supplied
    # via the environment / secret store. See _enforce_secret_key() below.
    SECRET_KEY: Optional[str] = None
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12 # 12 hours
    ADMIN_USERNAME: str = "soc_admin"
    ADMIN_PASSWORD: Optional[str] = None
    
    # Azure Sentinel & Azure Resource Manager Config
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None
    AZURE_SUBSCRIPTION_ID: Optional[str] = None
    AZURE_RESOURCE_GROUP_NAME: Optional[str] = None
    AZURE_WORKSPACE_NAME: Optional[str] = None
    AZURE_WORKSPACE_ID: Optional[str] = None # Log Analytics Workspace ID
    USE_MANAGED_IDENTITY: bool = False
    
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
    
    # Auto-Triage & Polling Settings
    ENABLE_AUTO_POLLING: bool = False
    POLL_INTERVAL_SECONDS: int = 120
    AUTO_POST_COMMENTS_TO_SENTINEL: bool = True
    AUTO_CLOSE_FALSE_POSITIVES: bool = False
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()


def _enforce_secret_key() -> None:
    """Fail closed on a missing or known-insecure JWT signing key.

    - Live mode (DEMO_MODE=False): a strong, unique SECRET_KEY is mandatory;
      the process refuses to start otherwise so it can never sign tokens with
      a publicly known key.
    - Demo mode: generate an ephemeral random key so local runs work, but warn
      loudly. Ephemeral keys do not survive restarts and are not shared across
      replicas, so any real deployment must set SECRET_KEY explicitly.
    """
    key = settings.SECRET_KEY
    is_insecure = (not key) or key == INSECURE_DEFAULT_SECRET_KEY

    if not is_insecure:
        return

    if not settings.DEMO_MODE:
        raise RuntimeError(
            "SECRET_KEY is unset or uses the known-insecure default while DEMO_MODE "
            "is disabled. Set a strong, unique SECRET_KEY (e.g. "
            "`python -c \"import secrets; print(secrets.token_urlsafe(64))\"`) via the "
            "environment or secret store before starting in live mode."
        )

    settings.SECRET_KEY = secrets.token_urlsafe(64)
    logging.getLogger("sentinel_soc_agent").warning(
        "SECRET_KEY was unset or left at the insecure default; generated an "
        "ephemeral key for DEMO mode. Tokens will not persist across restarts or "
        "work across replicas. Set SECRET_KEY explicitly for any real deployment."
    )


_enforce_secret_key()
