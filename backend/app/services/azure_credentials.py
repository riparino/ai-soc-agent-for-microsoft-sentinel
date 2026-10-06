"""
Single place that decides *how* this process authenticates to Azure.

Every Azure call (ARM for Sentinel incidents, Log Analytics for KQL, Graph for the
managing tenant) uses one credential built here, so the Sentinel client, the KQL
runner and the MCP server all agree on the identity in use.

Auth modes (``AZURE_AUTH_MODE``):

  * ``auto``              - legacy behaviour: ``USE_MANAGED_IDENTITY`` -> managed
                            identity; else a service-principal secret if the
                            AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET triple is set.
  * ``service_principal`` - ClientSecretCredential (shared server deployments).
  * ``managed_identity``  - DefaultAzureCredential (AKS / Container Apps / VMs).
  * ``user``              - the signed-in *analyst*: Azure CLI (``az login``),
                            Azure PowerShell or Azure Developer CLI credentials,
                            optionally falling back to an interactive browser
                            login. This is the mode for running the MCP server
                            locally on each analyst's machine: no secrets on the
                            laptop, and under Azure Lighthouse the analyst's own
                            delegated Sentinel roles apply across customer
                            workspaces, so every action is attributable to them.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

from app.config import settings

logger = logging.getLogger(__name__)

AUTH_MODES = ("auto", "service_principal", "managed_identity", "user")
ARM_SCOPE = "https://management.azure.com/.default"

_identity_lock = threading.Lock()
_identity_cache: dict[int, Optional[dict[str, Any]]] = {}


def _has_service_principal() -> bool:
    return bool(settings.AZURE_TENANT_ID and settings.AZURE_CLIENT_ID and settings.AZURE_CLIENT_SECRET)


def resolve_auth_mode() -> str:
    """Return the effective auth mode: one of service_principal / managed_identity /
    user / none (nothing usable configured)."""
    mode = (settings.AZURE_AUTH_MODE or "auto").strip().lower()
    if mode not in AUTH_MODES:
        logger.warning("Unknown AZURE_AUTH_MODE=%r; treating as 'auto'.", mode)
        mode = "auto"
    if mode == "auto":
        if settings.USE_MANAGED_IDENTITY:
            return "managed_identity"
        if _has_service_principal():
            return "service_principal"
        return "none"
    if mode == "service_principal" and not _has_service_principal():
        logger.warning("AZURE_AUTH_MODE=service_principal but AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET are incomplete.")
        return "none"
    return mode


def has_live_credentials() -> bool:
    return resolve_auth_mode() != "none"


def build_credential():
    """Build the azure-identity credential for the effective auth mode, or None."""
    mode = resolve_auth_mode()
    if mode == "none":
        return None
    from azure.identity import (
        AzureCliCredential,
        AzureDeveloperCliCredential,
        AzurePowerShellCredential,
        ChainedTokenCredential,
        ClientSecretCredential,
        DefaultAzureCredential,
        InteractiveBrowserCredential,
    )

    if mode == "service_principal":
        return ClientSecretCredential(
            tenant_id=settings.AZURE_TENANT_ID,
            client_id=settings.AZURE_CLIENT_ID,
            client_secret=settings.AZURE_CLIENT_SECRET,
        )
    if mode == "managed_identity":
        return DefaultAzureCredential()

    # user: prefer whatever the analyst already signed in with on this machine.
    tenant_kwargs = {"tenant_id": settings.AZURE_TENANT_ID} if settings.AZURE_TENANT_ID else {}
    chain = [
        AzureCliCredential(**tenant_kwargs),
        AzurePowerShellCredential(**tenant_kwargs),
        AzureDeveloperCliCredential(**tenant_kwargs),
    ]
    if settings.AZURE_INTERACTIVE_LOGIN:
        # Opens a browser if no CLI session exists. Off by default: a server
        # spawned by an MCP client should not pop a browser unexpectedly.
        chain.append(InteractiveBrowserCredential(**tenant_kwargs))
    return ChainedTokenCredential(*chain)


def _decode_unverified_claims(token: str) -> dict[str, Any]:
    from jose import jwt as jose_jwt

    return jose_jwt.get_unverified_claims(token)


def get_signed_in_identity(credential, refresh: bool = False) -> Optional[dict[str, Any]]:
    """Describe the identity behind ``credential`` by reading the claims of an ARM
    token it issues (the token is ours, so unverified decoding is fine here).

    Returns ``{"kind": "user"|"app", "upn", "name", "object_id", "tenant_id"}`` or
    None when no token can be obtained. Cached per credential for the process.
    """
    if credential is None:
        return None
    key = id(credential)
    with _identity_lock:
        if not refresh and key in _identity_cache:
            return _identity_cache[key]
    identity: Optional[dict[str, Any]] = None
    try:
        token = credential.get_token(ARM_SCOPE).token
        claims = _decode_unverified_claims(token)
        upn = claims.get("preferred_username") or claims.get("upn") or claims.get("unique_name") or claims.get("email")
        is_app = not upn and bool(claims.get("appid") or claims.get("azp"))
        identity = {
            "kind": "app" if is_app else "user",
            "upn": upn,
            "name": claims.get("name") or upn or claims.get("appid") or claims.get("azp"),
            "object_id": claims.get("oid"),
            "tenant_id": claims.get("tid"),
        }
    except Exception as e:  # noqa: BLE001 - diagnostics only
        logger.warning("Could not resolve signed-in Azure identity: %s", e)
    with _identity_lock:
        _identity_cache[key] = identity
    return identity


def actor_label(credential, fallback: str = "AI SOC Agent") -> str:
    """Human-readable actor for audit comments: the analyst when running as a user."""
    identity = get_signed_in_identity(credential)
    if identity and identity.get("kind") == "user":
        who = identity.get("name") or identity.get("upn")
        if identity.get("upn") and identity.get("name") and identity["upn"] != identity["name"]:
            who = f"{identity['name']} ({identity['upn']})"
        return f"{who} via {fallback}"
    return fallback
