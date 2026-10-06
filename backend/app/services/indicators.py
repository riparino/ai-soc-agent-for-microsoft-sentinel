"""Flatten a Sentinel incident's entity graph into plain indicator lists.

Shared by the MCP server (``sentinel_extract_indicators``), the hunting service
and the triage agent so every consumer sees the same accounts / IPs / hosts /
hashes / URLs for an incident.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def dedupe(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for v in values:
        if v is None or v == "":
            continue
        key = str(v).lower()
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def extract_indicators(incident: dict[str, Any]) -> dict[str, Any]:
    """Per-type, deduped indicator lists of plain strings for an incident."""
    ips: list[str] = []
    accounts: list[str] = []
    hosts: list[str] = []
    hashes: list[str] = []
    urls: list[str] = []
    resources: list[str] = []
    processes: list[str] = []
    cloud_apps: list[str] = []
    mailboxes: list[str] = []

    for e in incident.get("entities") or []:
        kind = str(e.get("kind", "")).lower()
        if kind == "ip":
            ips.append(e.get("address"))
        elif kind == "account":
            accounts.append(e.get("upn") or e.get("name"))
        elif kind == "host":
            hosts.append(e.get("name"))
        elif kind == "filehash":
            hashes.append(e.get("sha256") or e.get("name"))
        elif kind == "url":
            urls.append(e.get("url") or e.get("name"))
        elif kind == "azureresource":
            resources.append(e.get("resourceId") or e.get("name"))
        elif kind == "process":
            processes.append(e.get("commandLine") or e.get("processName"))
        elif kind == "cloudapplication":
            cloud_apps.append(e.get("name"))
        elif kind == "mailbox":
            mailboxes.append(e.get("name"))

    result = {
        "incident_ref": incident.get("id"),
        "workspace_id": incident.get("workspaceId"),
        "workspace_name": incident.get("workspaceName"),
        "ips": dedupe(ips),
        "accounts": dedupe(accounts),
        "hosts": dedupe(hosts),
        "file_hashes": dedupe(hashes),
        "urls": dedupe(urls),
        "azure_resources": dedupe(resources),
        "processes": dedupe(processes),
        "cloud_apps": dedupe(cloud_apps),
        "mailboxes": dedupe(mailboxes),
    }
    result["counts"] = {k: len(v) for k, v in result.items() if isinstance(v, list)}
    return result


def account_short_names(accounts: list[str]) -> list[str]:
    """``jdoe@contoso.com`` / ``CONTOSO\\jdoe`` -> ``jdoe`` (for Device*/SecurityEvent tables)."""
    out: list[str] = []
    for a in accounts:
        s = str(a)
        s = s.split("@", 1)[0]
        s = s.rsplit("\\", 1)[-1]
        if len(s) >= 3:
            out.append(s)
    return dedupe(out)


def host_short_names(hosts: list[str]) -> list[str]:
    """``FINANCE-SRV-01.corp.contoso.com`` -> ``finance-srv-01``."""
    out: list[str] = []
    for h in hosts:
        s = str(h).split(".", 1)[0].strip()
        if len(s) >= 3:
            out.append(s)
    return dedupe(out)


def url_domains(urls: list[str]) -> list[str]:
    out: list[str] = []
    for u in urls:
        s = str(u).strip()
        if "://" not in s:
            s = "//" + s
        try:
            host = urlsplit(s).hostname
        except ValueError:
            host = None
        if host and "." in host:
            out.append(host.lower())
    return dedupe(out)
