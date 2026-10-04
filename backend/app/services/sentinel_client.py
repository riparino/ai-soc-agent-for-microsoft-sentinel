import logging
import uuid
import re
import asyncio
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from app.config import settings
from app.services.workspace_registry import workspace_registry, WorkspaceConfig

logger = logging.getLogger(__name__)

# Sample Mock Incidents for Standalone Testing / Demo Mode
MOCK_INCIDENTS: List[Dict[str, Any]] = [
    {
        "id": "inc-2026-9041",
        "incidentNumber": 9041,
        "title": "Suspicious PowerShell Invocations with Encoded Arguments from Word Process",
        "description": "Microsoft Defender for Endpoint detected WINWORD.EXE launching powershell.exe with Base64 encoded payload and execution bypass flags.",
        "severity": "High",
        "status": "New",
        "createdTimeUtc": (datetime.utcnow() - timedelta(minutes=25)).isoformat() + "Z",
        "lastModifiedTimeUtc": (datetime.utcnow() - timedelta(minutes=10)).isoformat() + "Z",
        "tactics": ["Execution", "DefenseEvasion", "InitialAccess"],
        "techniques": ["T1059.001", "T1027", "T1566.001"],
        "assignedTo": None,
        "alertsCount": 3,
        "alerts": [
            {
                "id": "al-9041-1",
                "title": "Suspicious PowerShell Invocations with Encoded Arguments",
                "description": "powershell.exe executed with hidden window and base64 encoded parameters from parent WINWORD.EXE process.",
                "severity": "High",
                "vendor": "Microsoft Defender for Endpoint (EDR)",
                "product": "Microsoft Defender for Endpoint",
                "tactics": ["Execution", "DefenseEvasion"],
                "techniques": ["T1059.001", "T1027"],
                "timeGenerated": (datetime.utcnow() - timedelta(minutes=25)).isoformat() + "Z",
                "alertLink": "https://security.microsoft.com/alerts"
            },
            {
                "id": "al-9041-2",
                "title": "Office Application Spawning Script Interpreter",
                "description": "WINWORD.EXE launched command interpreter powershell.exe with non-standard arguments.",
                "severity": "High",
                "vendor": "Microsoft Defender XDR",
                "product": "Defender Attack Surface Reduction",
                "tactics": ["InitialAccess", "Execution"],
                "techniques": ["T1566.001"],
                "timeGenerated": (datetime.utcnow() - timedelta(minutes=26)).isoformat() + "Z",
                "alertLink": "https://security.microsoft.com/alerts"
            }
        ],
        "entities": [
            {"kind": "Host", "name": "WKS-EXEC-094", "os": "Windows 11 Enterprise"},
            {"kind": "Account", "name": "jdoe@cybersecurity.corp", "upn": "jdoe@cybersecurity.corp", "aadUserId": "d3b07384-d113-4917-8e68-3e4df6a8369d"},
            {"kind": "Ip", "address": "45.148.10.12", "direction": "Outbound", "location": "Frankfurt, Germany"},
            {"kind": "Process", "processName": "powershell.exe", "commandLine": "powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."}
        ],
        "comments": [
            {
                "id": "c-1",
                "author": "System Automation",
                "message": "Incident automatically created from Microsoft Defender XDR alert correlation engine.",
                "createdTimeUtc": (datetime.utcnow() - timedelta(minutes=24)).isoformat() + "Z"
            }
        ],
        "labels": ["DefenderForEndpoint", "EncodedPowerShell", "PhishingCandidate"]
    },
    {
        "id": "inc-2026-9042",
        "incidentNumber": 9042,
        "title": "Impossible Travel and Risky Sign-in from Tor Exit Node",
        "description": "User account was successfully authenticated from Austin, US and 15 minutes later from a known Tor Exit Node in Moscow, Russia.",
        "severity": "High",
        "status": "New",
        "createdTimeUtc": (datetime.utcnow() - timedelta(minutes=45)).isoformat() + "Z",
        "lastModifiedTimeUtc": (datetime.utcnow() - timedelta(minutes=30)).isoformat() + "Z",
        "tactics": ["InitialAccess", "CredentialAccess"],
        "techniques": ["T1078.004", "T1110"],
        "assignedTo": None,
        "alertsCount": 2,
        "alerts": [
            {
                "id": "al-9042-1",
                "title": "Sign-in from anonymous IP address (Tor Network)",
                "description": "User jdoe@cybersecurity.corp signed in from IP address 185.220.101.5 associated with an active Tor exit node.",
                "severity": "High",
                "vendor": "Microsoft Entra ID Protection",
                "product": "Entra ID Protection",
                "tactics": ["InitialAccess"],
                "techniques": ["T1078.004"],
                "timeGenerated": (datetime.utcnow() - timedelta(minutes=45)).isoformat() + "Z",
                "alertLink": "https://portal.azure.com"
            }
        ],
        "entities": [
            {"kind": "Account", "name": "jdoe@cybersecurity.corp", "upn": "jdoe@cybersecurity.corp"},
            {"kind": "Ip", "address": "185.220.101.5", "location": "Moscow, Russia"},
            {"kind": "Ip", "address": "198.51.100.4", "location": "Austin, United States"}
        ],
        "comments": [],
        "labels": ["EntraIDProtection", "ImpossibleTravel", "TorExitNode"]
    },
    {
        "id": "inc-2026-9043",
        "incidentNumber": 9043,
        "title": "Multiple Failed Authentication Attempts Followed by Success (Password Spray)",
        "description": "Over 120 failed sign-in attempts recorded across 40 user accounts from a single external IP address within 5 minutes, culminating in a single successful authentication.",
        "severity": "Medium",
        "status": "New",
        "createdTimeUtc": (datetime.utcnow() - timedelta(hours=2)).isoformat() + "Z",
        "lastModifiedTimeUtc": (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z",
        "tactics": ["CredentialAccess"],
        "techniques": ["T1110.003"],
        "assignedTo": None,
        "alertsCount": 1,
        "alerts": [
            {
                "id": "al-9043-1",
                "title": "Password Spray Attack Pattern Detected",
                "description": "Distributed authentication failures against tenant Entra ID tenant.",
                "severity": "Medium",
                "vendor": "Microsoft Sentinel Analytics Rule",
                "product": "Microsoft Sentinel",
                "tactics": ["CredentialAccess"],
                "techniques": ["T1110.003"],
                "timeGenerated": (datetime.utcnow() - timedelta(hours=2)).isoformat() + "Z",
                "alertLink": "https://portal.azure.com"
            }
        ],
        "entities": [
            {"kind": "Ip", "address": "194.26.29.114", "location": "Kyiv, Ukraine"},
            {"kind": "Account", "name": "finance-shared@cybersecurity.corp", "upn": "finance-shared@cybersecurity.corp"}
        ],
        "comments": [],
        "labels": ["PasswordSpray", "EntraID"]
    },
    {
        "id": "inc-2026-9044",
        "incidentNumber": 9044,
        "title": "Routine Vulnerability Scanner Activity against DMZ Web Application",
        "description": "Rapid HTTP GET/POST requests with SQL injection signatures originating from authorized internal scanner subnet (Qualys Agent).",
        "severity": "Low",
        "status": "New",
        "createdTimeUtc": (datetime.utcnow() - timedelta(hours=4)).isoformat() + "Z",
        "lastModifiedTimeUtc": (datetime.utcnow() - timedelta(hours=3)).isoformat() + "Z",
        "tactics": ["Reconnaissance"],
        "techniques": ["T1595.002"],
        "assignedTo": None,
        "alertsCount": 1,
        "alerts": [
            {
                "id": "al-9044-1",
                "title": "Web Application Vulnerability Scan Signatures",
                "description": "SQLi/XSS test patterns detected from known internal security scanner.",
                "severity": "Low",
                "vendor": "Microsoft Defender for Cloud (WAF)",
                "product": "Azure WAF",
                "tactics": ["Reconnaissance"],
                "techniques": ["T1595.002"],
                "timeGenerated": (datetime.utcnow() - timedelta(hours=4)).isoformat() + "Z",
                "alertLink": "https://portal.azure.com"
            }
        ],
        "entities": [
            {"kind": "Ip", "address": "10.240.12.88", "location": "Internal Subnet (DMZ)"},
            {"kind": "Host", "name": "DMZ-WEB-APP-01", "os": "Ubuntu Linux 22.04"}
        ],
        "comments": [],
        "labels": ["Scanner", "VulnerabilityScan", "FalsePositiveCandidate"]
    }
]

def parse_sentinel_entity(e: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse raw Azure Sentinel ARM entity JSON into uniform schema"""
    kind = e.get("kind") or e.get("type", "").split("/")[-1]
    props = e.get("properties", {})

    if not kind:
        return None

    k_lower = kind.lower()

    if k_lower in ["account", "user"]:
        acc_name = props.get("accountName") or props.get("name") or ""
        upn_suffix = props.get("upnSuffix") or ""
        upn = props.get("userPrincipalName") or props.get("upn") or (f"{acc_name}@{upn_suffix}" if acc_name and upn_suffix else acc_name)
        display_name = props.get("displayName") or acc_name or upn
        return {
            "kind": "Account",
            "name": display_name or upn or "User Account",
            "upn": upn or display_name,
            "accountName": acc_name,
            "aadUserId": props.get("aadUserId") or props.get("puid", ""),
            "isDomainJoined": props.get("isDomainJoined", False)
        }

    elif k_lower in ["host", "machine"]:
        host_name = props.get("hostName") or props.get("netBiosName") or props.get("name") or ""
        dns_domain = props.get("dnsDomain") or ""
        fqdn = f"{host_name}.{dns_domain}" if host_name and dns_domain else host_name
        return {
            "kind": "Host",
            "name": fqdn or host_name or "Host Device",
            "os": props.get("osFamily") or props.get("osVersion") or "Windows / Linux",
            "azureResourceId": props.get("azureID") or props.get("resourceId", "")
        }

    elif k_lower in ["ip", "ipaddress"]:
        addr = props.get("address") or props.get("ipAddress") or ""
        if not addr:
            return None
        loc_obj = props.get("location") or {}
        location_str = ""
        if isinstance(loc_obj, dict):
            country = loc_obj.get("countryName") or loc_obj.get("countryCode")
            city = loc_obj.get("city")
            location_str = f"{city}, {country}" if city and country else (country or city or "")
        return {
            "kind": "Ip",
            "address": addr,
            "location": location_str or ("Internal RFC1918" if addr.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3")) else "External Public IP")
        }

    elif k_lower in ["process"]:
        proc_name = props.get("processName") or props.get("imageFile", {}).get("fileName") or "process.exe"
        cmd = props.get("commandLine") or ""
        return {
            "kind": "Process",
            "processName": proc_name,
            "commandLine": cmd,
            "processId": props.get("processId") or props.get("pid", "")
        }

    elif k_lower in ["file", "filehash"]:
        file_name = props.get("fileName") or "unknown_file"
        hashes = props.get("hashes") or []
        sha256 = ""
        if isinstance(hashes, list):
            for h in hashes:
                if isinstance(h, dict) and h.get("algorithm", "").upper() == "SHA256":
                    sha256 = h.get("value", "")
        elif isinstance(hashes, dict):
            sha256 = hashes.get("sha256") or hashes.get("SHA256") or ""
        return {
            "kind": "FileHash",
            "name": file_name,
            "sha256": sha256 or props.get("hashValue", ""),
            "path": props.get("directory", "")
        }

    elif k_lower in ["url"]:
        u = props.get("url") or ""
        return {"kind": "Url", "name": u, "url": u}

    elif k_lower in ["azureresource"]:
        res_id = props.get("resourceId") or ""
        res_name = res_id.split("/")[-1] if res_id else "Azure Resource"
        return {"kind": "AzureResource", "name": res_name, "resourceId": res_id}

    elif k_lower in ["cloudapplication"]:
        return {
            "kind": "CloudApplication",
            "name": props.get("appName") or props.get("appId") or "Cloud App",
            "appId": props.get("appId", "")
        }

    elif k_lower in ["mailbox", "mailmessage"]:
        return {
            "kind": "Mailbox",
            "name": props.get("mailboxPrimaryAddress") or props.get("recipient") or props.get("sender") or "Mailbox",
            "subject": props.get("subject", "")
        }

    return None

def extract_entities_from_text(text: str) -> List[Dict[str, Any]]:
    """Fallback extractor for IPs, emails, and hostnames when ARM API entities are empty"""
    extracted = []
    seen = set()

    # 1. IP Addresses
    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    for ip in ip_matches:
        if ip not in seen and not ip.startswith(("0.0.0.", "255.255.", "127.0.0.1")):
            seen.add(ip)
            is_internal = ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3"))
            extracted.append({
                "kind": "Ip",
                "address": ip,
                "location": "Internal Network" if is_internal else "External IP Address"
            })

    # 2. Email / UPNs
    email_matches = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
    for email in email_matches:
        if email not in seen:
            seen.add(email)
            extracted.append({
                "kind": "Account",
                "name": email,
                "upn": email
            })

    # 3. Hostnames (e.g. WKS-..., SRV-..., VM-..., DESKTOP-...)
    host_matches = re.findall(r'\b(?:WKS|SRV|VM|DESKTOP|LAPTOP|SERVER)-[A-Za-z0-9_-]+\b', text, re.IGNORECASE)
    for host in host_matches:
        if host.upper() not in seen:
            seen.add(host.upper())
            extracted.append({
                "kind": "Host",
                "name": host.upper(),
                "os": "Windows / Linux"
            })

    return extracted

class SentinelClient:
    """
    Fleet-aware Microsoft Sentinel client.

    A single home-tenant service principal (the managing-tenant credentials in
    ``settings``) is shared across the whole fleet: under Azure Lighthouse the
    same ARM and Log Analytics tokens reach every delegated customer
    subscription. Per-request workspace context is passed explicitly as a
    ``WorkspaceConfig`` (resolved from the incident ref namespace) rather than
    mutated onto the global settings singleton.
    """

    def __init__(self):
        self.credential = None
        self.is_live = False
        self._init_client()

    def _init_client(self):
        """(Re)build the shared home-tenant credential and live/demo state."""
        has_creds = bool(
            (settings.USE_MANAGED_IDENTITY) or
            (settings.AZURE_TENANT_ID and settings.AZURE_CLIENT_ID and settings.AZURE_CLIENT_SECRET)
        )
        self.is_live = bool(not settings.DEMO_MODE and has_creds)
        self.credential = None

        if self.is_live:
            try:
                from azure.identity import DefaultAzureCredential, ClientSecretCredential
                if settings.USE_MANAGED_IDENTITY:
                    self.credential = DefaultAzureCredential()
                elif settings.AZURE_TENANT_ID and settings.AZURE_CLIENT_ID and settings.AZURE_CLIENT_SECRET:
                    self.credential = ClientSecretCredential(
                        tenant_id=settings.AZURE_TENANT_ID,
                        client_id=settings.AZURE_CLIENT_ID,
                        client_secret=settings.AZURE_CLIENT_SECRET
                    )
                else:
                    self.credential = DefaultAzureCredential()
                logger.info("Initialized shared (managing-tenant) Azure credential for the workspace fleet.")
            except Exception as e:
                logger.warning(f"Could not initialize Azure credentials: {e}. Running in simulation/demo mode.")
                self.is_live = False
        # Refresh the workspace fleet in case configuration changed.
        try:
            workspace_registry.reload()
        except Exception as e:
            logger.debug(f"Workspace registry reload note: {e}")

    def _get_arm_token(self) -> Optional[str]:
        """ARM bearer token from the managing tenant (Lighthouse-honored across
        delegated subscriptions)."""
        if self.credential:
            try:
                token_obj = self.credential.get_token("https://management.azure.com/.default")
                return token_obj.token
            except Exception:
                pass
        # Direct OAuth2 REST token fallback (managing tenant).
        if settings.AZURE_TENANT_ID and settings.AZURE_CLIENT_ID and settings.AZURE_CLIENT_SECRET:
            try:
                token_url = f"https://login.microsoftonline.com/{settings.AZURE_TENANT_ID}/oauth2/v2.0/token"
                data = {
                    "grant_type": "client_credentials",
                    "client_id": settings.AZURE_CLIENT_ID,
                    "client_secret": settings.AZURE_CLIENT_SECRET,
                    "scope": "https://management.azure.com/.default"
                }
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(token_url, data=data)
                    if resp.status_code == 200:
                        return resp.json().get("access_token")
            except Exception as e:
                logger.error(f"Failed to obtain Azure ARM bearer token: {e}")
        return None

    def _get_base_url(self, workspace: WorkspaceConfig) -> str:
        """ARM SecurityInsights base URL for an explicit workspace."""
        return workspace.arm_base_url()

    async def resolve_workspace_guid(self, workspace: WorkspaceConfig) -> Optional[str]:
        """Resolve (and cache) the Log Analytics customerId GUID for a workspace.

        Works across delegated subscriptions using the shared managing-tenant ARM
        token (Lighthouse-honored).
        """
        guid = workspace.workspace_guid
        if guid and len(guid) > 30 and "-" in guid:
            return guid
        if not (self.is_live and workspace.has_arm_coordinates()):
            return guid
        token = self._get_arm_token()
        if not token:
            return guid
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(workspace.arm_workspace_url(), headers={"Authorization": f"Bearer {token}"})
                if resp.status_code == 200:
                    cust_id = resp.json().get("properties", {}).get("customerId")
                    if cust_id:
                        workspace.workspace_guid = cust_id
                        logger.info(f"Resolved Log Analytics GUID for workspace '{workspace.id}': {cust_id}")
                        return cust_id
        except Exception as e:
            logger.debug(f"Could not resolve workspace GUID for '{workspace.id}': {e}")
        return workspace.workspace_guid

    # ------------------------------------------------------------- namespacing
    def _namespace(self, incident: Dict[str, Any], workspace: WorkspaceConfig) -> Dict[str, Any]:
        """Stamp workspace routing metadata and namespace the incident id."""
        raw_id = incident.get("id")
        incident["rawId"] = raw_id
        incident["id"] = workspace_registry.make_ref(workspace.id, str(raw_id))
        incident["workspaceId"] = workspace.id
        incident["workspaceName"] = workspace.display_name
        incident["workspaceTenantId"] = workspace.tenant_id
        return incident

    def _mock_home_map(self) -> Dict[str, str]:
        """Deterministically assign each mock incident to a workspace (round-robin
        over the full fleet) so demo routing is stable and testable."""
        order = [w.id for w in workspace_registry.list_workspaces()]
        mapping: Dict[str, str] = {}
        if not order:
            return mapping
        for i, inc in enumerate(MOCK_INCIDENTS):
            mapping[inc["id"]] = order[i % len(order)]
        return mapping

    def _passes_filters(self, inc: Dict[str, Any], filter_status, severity, time_range_days) -> bool:
        if filter_status and filter_status != "All" and inc.get("status", "").lower() != filter_status.lower():
            return False
        if severity and severity != "All" and inc.get("severity", "").lower() != severity.lower():
            return False
        if time_range_days and time_range_days > 0:
            cutoff = datetime.utcnow() - timedelta(days=time_range_days)
            try:
                c_time = datetime.fromisoformat(inc.get("createdTimeUtc", "").replace("Z", "+00:00")).replace(tzinfo=None)
                if c_time < cutoff:
                    return False
            except Exception:
                return True
        return True

    def _sort_incidents(self, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def _key(inc):
            try:
                return datetime.fromisoformat(inc.get("createdTimeUtc", "").replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                return datetime.min
        return sorted(incidents, key=_key, reverse=True)

    # ------------------------------------------------------- entity enrichment
    async def _fetch_incident_entities_and_comments(
        self, client: httpx.AsyncClient, workspace: WorkspaceConfig, incident_id: str, headers: dict
    ) -> tuple:
        """Fetch entities, comments, and correlated alerts for an incident concurrently"""
        entities = []
        comments = []
        alerts = []
        base_url = self._get_base_url(workspace)

        try:
            entities_url = f"{base_url}/incidents/{incident_id}/entities?api-version=2023-11-01"
            e_task = client.post(entities_url, headers=headers)

            comments_url = f"{base_url}/incidents/{incident_id}/comments?api-version=2023-11-01"
            c_task = client.get(comments_url, headers=headers)

            alerts_url = f"{base_url}/incidents/{incident_id}/alerts?api-version=2023-11-01"
            a_task = client.post(alerts_url, headers=headers)

            e_resp, c_resp, a_resp = await asyncio.gather(e_task, c_task, a_task, return_exceptions=True)

            if not isinstance(e_resp, Exception) and e_resp.status_code == 200:
                raw_entities = e_resp.json().get("entities", [])
                for raw in raw_entities:
                    parsed = parse_sentinel_entity(raw)
                    if parsed:
                        entities.append(parsed)

            if not isinstance(c_resp, Exception) and c_resp.status_code == 200:
                c_data = c_resp.json().get("value", [])
                for c in c_data:
                    c_props = c.get("properties", {})
                    comments.append({
                        "id": c.get("name"),
                        "author": c_props.get("author", {}).get("name", "Analyst"),
                        "message": c_props.get("message", ""),
                        "createdTimeUtc": c_props.get("createdTimeUtc")
                    })

            if not isinstance(a_resp, Exception) and a_resp.status_code == 200:
                raw_alerts = a_resp.json().get("value", [])
                for a in raw_alerts:
                    a_props = a.get("properties", {})
                    alert_title = a_props.get("alertDisplayName") or a_props.get("friendlyName") or "Sentinel Alert"
                    product = a_props.get("productName") or "Azure Sentinel"
                    component = a_props.get("productComponentName") or ""
                    vendor = f"{product} ({component})" if component else product

                    raw_tech = a_props.get("additionalData", {}).get("MitreTechniques", "[]")
                    techniques = []
                    try:
                        import json as _json
                        if isinstance(raw_tech, str):
                            techniques = _json.loads(raw_tech)
                        elif isinstance(raw_tech, list):
                            techniques = raw_tech
                    except Exception:
                        techniques = []

                    alerts.append({
                        "id": a.get("name"),
                        "title": alert_title,
                        "description": a_props.get("description", ""),
                        "severity": a_props.get("severity", "Medium"),
                        "vendor": vendor,
                        "product": product,
                        "tactics": a_props.get("tactics", []),
                        "techniques": techniques,
                        "timeGenerated": a_props.get("timeGenerated") or a_props.get("startTimeUtc"),
                        "alertLink": a_props.get("alertLink", "")
                    })

                    for raw_e in a_props.get("entities", []):
                        parsed_e = parse_sentinel_entity(raw_e)
                        if parsed_e and not any(ex.get("name") == parsed_e.get("name") for ex in entities):
                            entities.append(parsed_e)
        except Exception as err:
            logger.debug(f"Note fetching incident {incident_id} relations: {err}")

        return entities, comments, alerts

    # --------------------------------------------------------------- listing
    async def _list_live_for_workspace(
        self,
        client: httpx.AsyncClient,
        workspace: WorkspaceConfig,
        token: str,
        filter_status: Optional[str],
        severity: Optional[str],
        time_range_days: Optional[int],
    ) -> List[Dict[str, Any]]:
        """Fetch & map incidents from a single live workspace (namespaced)."""
        base_url = self._get_base_url(workspace)
        url = f"{base_url}/incidents?api-version=2023-11-01&$orderby=properties/createdTimeUtc desc"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error(f"Failed to query Sentinel API for workspace '{workspace.id}' (HTTP {resp.status_code}): {resp.text}")
            return []

        raw_incidents = resp.json().get("value", [])
        mapped = []
        for item in raw_incidents:
            props = item.get("properties", {})
            inc_id = item.get("name")
            inc_num = props.get("incidentNumber", 0)
            raw_labels = props.get("labels", [])
            labels = [l.get("labelName", "") if isinstance(l, dict) else str(l) for l in raw_labels]
            owner = props.get("owner", {})
            mapped.append({
                "id": inc_id,
                "incidentNumber": inc_num,
                "title": props.get("title", f"Incident #{inc_num}"),
                "description": props.get("description", ""),
                "severity": props.get("severity", "Medium"),
                "status": props.get("status", "New"),
                "createdTimeUtc": props.get("createdTimeUtc", datetime.utcnow().isoformat() + "Z"),
                "lastModifiedTimeUtc": props.get("lastModifiedTimeUtc", props.get("createdTimeUtc")),
                "tactics": props.get("tactics", []),
                "techniques": [],
                "assignedTo": owner.get("assignedTo", owner.get("userPrincipalName")),
                "classification": props.get("classification"),
                "classificationReason": props.get("classificationReason"),
                "classificationComment": props.get("classificationComment"),
                "alertsCount": props.get("relatedAnalyticRuleIds", []) and len(props.get("relatedAnalyticRuleIds", [])) or 1,
                "entities": [],
                "comments": [],
                "labels": labels
            })

        results = [i for i in mapped if self._passes_filters(i, filter_status, severity, time_range_days)]

        # Concurrently enrich the active set with the real entity graph & alerts.
        enrichment_tasks = [
            self._fetch_incident_entities_and_comments(client, workspace, inc["id"], headers)
            for inc in results[:10]
        ]
        if enrichment_tasks:
            enrichment_results = await asyncio.gather(*enrichment_tasks, return_exceptions=True)
            for i, res in enumerate(enrichment_results):
                if not isinstance(res, Exception):
                    ents, comms, alrts = res
                    if not ents:
                        combined_txt = f"{results[i]['title']} {results[i]['description']}"
                        ents = extract_entities_from_text(combined_txt)
                        if results[i].get("assignedTo"):
                            ents.append({"kind": "Account", "name": results[i]["assignedTo"], "upn": results[i]["assignedTo"]})
                    results[i]["entities"] = ents
                    results[i]["comments"] = comms
                    results[i]["alerts"] = alrts

        for inc in results:
            if not inc.get("alerts"):
                inc["alerts"] = [{
                    "id": f"al-{str(inc.get('id', ''))[:8]}",
                    "title": inc.get("title"),
                    "description": inc.get("description") or "Analytic detection triggered in Microsoft Sentinel.",
                    "severity": inc.get("severity", "Medium"),
                    "vendor": "Microsoft Sentinel (Analytics Rule)",
                    "product": "Microsoft Sentinel",
                    "tactics": inc.get("tactics", []),
                    "techniques": inc.get("techniques", []),
                    "timeGenerated": inc.get("createdTimeUtc"),
                    "alertLink": f"https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/IncidentOverviewBlade/id/{inc.get('id')}"
                }]
            self._namespace(inc, workspace)

        logger.info(f"Fetched {len(results)} incidents from Sentinel workspace '{workspace.display_name}' ({workspace.id}).")
        return results

    def _mock_incidents_for(
        self,
        targets: List[WorkspaceConfig],
        filter_status: Optional[str],
        severity: Optional[str],
        time_range_days: Optional[int],
    ) -> List[Dict[str, Any]]:
        """Return namespaced copies of mock incidents routed to the target workspaces."""
        target_ids = {w.id for w in targets}
        ws_by_id = {w.id: w for w in workspace_registry.list_workspaces()}
        home_map = self._mock_home_map()
        results = []
        for inc in MOCK_INCIDENTS:
            home_id = home_map.get(inc["id"])
            if home_id not in target_ids:
                continue
            workspace = ws_by_id.get(home_id)
            if not workspace:
                continue
            if not self._passes_filters(inc, filter_status, severity, time_range_days):
                continue
            results.append(self._namespace({**inc}, workspace))
        return results

    async def list_incidents(
        self,
        filter_status: Optional[str] = None,
        severity: Optional[str] = None,
        time_range_days: Optional[int] = None,
        workspace: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List incidents across one, several, or all workspaces in the fleet.

        ``workspace`` is a selector: ``None``/``"all"`` aggregates the whole fleet,
        or a single id / comma-separated list of ids selects specific workspaces.
        Every returned incident carries a namespaced ``id`` plus ``workspaceId`` /
        ``workspaceName`` so it can be routed back to its origin workspace.
        """
        targets = workspace_registry.resolve_targets(workspace)

        if self.is_live:
            token = self._get_arm_token()
            if token:
                results: List[Dict[str, Any]] = []
                try:
                    async with httpx.AsyncClient(timeout=20.0) as client:
                        for ws in targets:
                            if not ws.has_arm_coordinates():
                                continue
                            try:
                                results.extend(
                                    await self._list_live_for_workspace(
                                        client, ws, token, filter_status, severity, time_range_days
                                    )
                                )
                            except Exception as e:
                                logger.error(f"Exception listing incidents for workspace '{ws.id}': {e}")
                    return self._sort_incidents(results)
                except Exception as e:
                    logger.error(f"Exception during multi-workspace incident retrieval: {e}")

        # Demo / mock fallback.
        return self._sort_incidents(self._mock_incidents_for(targets, filter_status, severity, time_range_days))

    async def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single incident, routing to the workspace encoded in the ref."""
        workspace, raw_id = workspace_registry.resolve_ref(incident_id)

        if self.is_live and workspace.has_arm_coordinates():
            token = self._get_arm_token()
            if token:
                try:
                    base_url = self._get_base_url(workspace)
                    url = f"{base_url}/incidents/{raw_id}?api-version=2023-11-01"
                    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
                    async with httpx.AsyncClient(timeout=15.0) as client:
                        resp = await client.get(url, headers=headers)
                        if resp.status_code == 200:
                            item = resp.json()
                            props = item.get("properties", {})

                            entities, comments, alerts = await self._fetch_incident_entities_and_comments(
                                client, workspace, raw_id, headers
                            )

                            if not entities:
                                combined_txt = f"{props.get('title', '')} {props.get('description', '')}"
                                entities = extract_entities_from_text(combined_txt)

                            if not alerts:
                                alerts = [{
                                    "id": f"al-{str(raw_id)[:8]}",
                                    "title": props.get("title", f"Sentinel Incident #{props.get('incidentNumber', '')}"),
                                    "description": props.get("description") or "Analytic detection triggered in Microsoft Sentinel.",
                                    "severity": props.get("severity", "Medium"),
                                    "vendor": "Microsoft Sentinel (Analytics Rule)",
                                    "product": "Microsoft Sentinel",
                                    "tactics": props.get("tactics", []),
                                    "techniques": [],
                                    "timeGenerated": props.get("createdTimeUtc"),
                                    "alertLink": f"https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/IncidentOverviewBlade/id/{raw_id}"
                                }]

                            owner = props.get("owner", {})
                            owner_upn = owner.get("userPrincipalName") or owner.get("email")
                            if owner_upn and not any(e.get("kind") == "Account" and e.get("upn") == owner_upn for e in entities):
                                entities.append({"kind": "Account", "name": owner.get("assignedTo", owner_upn), "upn": owner_upn})

                            raw_labels = props.get("labels", [])
                            labels = [l.get("labelName", "") if isinstance(l, dict) else str(l) for l in raw_labels]

                            incident = {
                                "id": raw_id,
                                "incidentNumber": props.get("incidentNumber", 0),
                                "title": props.get("title", ""),
                                "description": props.get("description", ""),
                                "severity": props.get("severity", "Medium"),
                                "status": props.get("status", "New"),
                                "createdTimeUtc": props.get("createdTimeUtc"),
                                "lastModifiedTimeUtc": props.get("lastModifiedTimeUtc"),
                                "tactics": props.get("tactics", []),
                                "techniques": [],
                                "assignedTo": owner.get("assignedTo", owner_upn),
                                "classification": props.get("classification"),
                                "classificationReason": props.get("classificationReason"),
                                "classificationComment": props.get("classificationComment"),
                                "entities": entities,
                                "comments": comments,
                                "alerts": alerts,
                                "labels": labels
                            }
                            return self._namespace(incident, workspace)
                except Exception as e:
                    logger.error(f"Error fetching live incident {raw_id} in workspace '{workspace.id}': {e}")

        # Mock fallback.
        for inc in MOCK_INCIDENTS:
            if inc["id"] == raw_id or str(inc.get("incidentNumber")) == raw_id:
                return self._namespace({**inc}, workspace)
        return None

    async def add_comment(self, incident_id: str, message: str, author: str = "AI Sentinel Triage Agent") -> Dict[str, Any]:
        """Post an investigation note to the incident's origin workspace."""
        workspace, raw_id = workspace_registry.resolve_ref(incident_id)

        if self.is_live and workspace.has_arm_coordinates():
            token = self._get_arm_token()
            if token:
                try:
                    comment_name = str(uuid.uuid4())
                    base_url = self._get_base_url(workspace)
                    url = f"{base_url}/incidents/{raw_id}/comments/{comment_name}?api-version=2023-11-01"
                    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
                    payload = {"properties": {"message": message}}
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.put(url, headers=headers, json=payload)
                        if resp.status_code in [200, 201]:
                            logger.info(f"Comment posted to incident {raw_id} in workspace '{workspace.id}'.")
                            return {"status": "SUCCESS", "comment": {"id": comment_name, "message": message, "author": author}}
                except Exception as e:
                    logger.error(f"Failed to post comment to incident {raw_id} in '{workspace.id}': {e}")

        # Mock fallback.
        comment_entry = {
            "id": f"c-{uuid.uuid4().hex[:6]}",
            "author": author,
            "message": message,
            "createdTimeUtc": datetime.utcnow().isoformat() + "Z"
        }
        for inc in MOCK_INCIDENTS:
            if inc["id"] == raw_id or str(inc.get("incidentNumber")) == raw_id:
                inc.setdefault("comments", []).append(comment_entry)
                inc["lastModifiedTimeUtc"] = datetime.utcnow().isoformat() + "Z"
                return {"status": "SUCCESS", "comment": comment_entry}
        return {"status": "NOT_FOUND", "message": f"Incident {incident_id} not found."}

    async def update_status(
        self,
        incident_id: str,
        status: str,
        severity: Optional[str] = None,
        classification: Optional[str] = None,
        classification_reason: Optional[str] = None,
        classification_comment: Optional[str] = None,
        labels: Optional[List[str]] = None,
        updated_by: str = "SOC Analyst"
    ) -> Dict[str, Any]:
        """Update incident status/classification in the incident's origin workspace."""
        workspace, raw_id = workspace_registry.resolve_ref(incident_id)

        if self.is_live and workspace.has_arm_coordinates():
            token = self._get_arm_token()
            if token:
                try:
                    base_url = self._get_base_url(workspace)
                    url = f"{base_url}/incidents/{raw_id}?api-version=2023-11-01"
                    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

                    async with httpx.AsyncClient(timeout=15.0) as client:
                        r_get = await client.get(url, headers=headers)
                        if r_get.status_code == 200:
                            props = r_get.json().get("properties", {})
                            props["status"] = status
                            if severity:
                                props["severity"] = severity

                            if status == "Closed":
                                cls = classification or props.get("classification") or "Undetermined"
                                props["classification"] = cls
                                if cls == "Undetermined":
                                    props.pop("classificationReason", None)
                                elif cls == "TruePositive":
                                    props["classificationReason"] = classification_reason or "SuspiciousActivity"
                                elif cls == "FalsePositive":
                                    props["classificationReason"] = classification_reason or "InaccurateData"
                                elif cls == "BenignPositive":
                                    props["classificationReason"] = classification_reason or "SuspiciousButExpected"
                                props["classificationComment"] = classification_comment or "Closed via Microsoft Sentinel AI Triage Platform"
                            elif status in ["New", "Active"]:
                                props.pop("classification", None)
                                props.pop("classificationReason", None)
                                props.pop("classificationComment", None)

                            if labels:
                                props["labels"] = [{"labelName": l, "labelType": "User"} for l in labels]

                            resp = await client.put(url, headers=headers, json={"properties": props})
                            if resp.status_code in [200, 201]:
                                logger.info(f"Updated incident {raw_id} in '{workspace.id}' status to {status}.")
                                if status == "Closed":
                                    comment_text = (
                                        f"🔒 **Incident Closed by {updated_by}**\n"
                                        f"- **Classification:** `{props.get('classification')}`\n"
                                        f"- **Reason:** `{props.get('classificationReason') or 'None'}`\n"
                                        f"- **Closing Notes:** {props.get('classificationComment')}"
                                    )
                                else:
                                    comment_text = f"📌 **Status Changed to {status}**\nIncident status was changed to **{status}** by **{updated_by}**."

                                await self.add_comment(incident_id, comment_text, author=updated_by)
                                return {"status": "SUCCESS", "incident": resp.json()}
                            else:
                                logger.error(f"Failed to update incident {raw_id} (HTTP {resp.status_code}): {resp.text}")
                except Exception as e:
                    logger.error(f"Error updating incident {raw_id} in '{workspace.id}': {e}")

        # Mock fallback.
        for inc in MOCK_INCIDENTS:
            if inc["id"] == raw_id or str(inc.get("incidentNumber")) == raw_id:
                inc["status"] = status
                if severity:
                    inc["severity"] = severity
                if status == "Closed":
                    inc["classification"] = classification or "Undetermined"
                    inc["classificationReason"] = classification_reason if classification != "Undetermined" else None
                    inc["classificationComment"] = classification_comment or "Closed by SOC Analyst"
                else:
                    inc.pop("classification", None)
                    inc.pop("classificationReason", None)
                    inc.pop("classificationComment", None)
                if labels:
                    current_labels = set(inc.get("labels", []))
                    current_labels.update(labels)
                    inc["labels"] = list(current_labels)
                inc["lastModifiedTimeUtc"] = datetime.utcnow().isoformat() + "Z"
                return {"status": "SUCCESS", "incident": self._namespace({**inc}, workspace)}
        return {"status": "NOT_FOUND", "message": f"Incident {incident_id} not found."}

    async def get_entra_users(self, workspace: Optional[WorkspaceConfig] = None) -> List[Dict[str, Any]]:
        """
        List SOC engineers / tenant users for a workspace.

        Microsoft Graph is NOT delegated by Azure Lighthouse, so directory access
        depends on the workspace's ``graph_mode``:

          * ``delegated-app``   - use the per-customer app registration to read the
            customer tenant's directory via Microsoft Graph.
          * ``managing-tenant`` - use the shared home SP's Graph token (home tenant).
          * ``log-analytics-only`` - Graph cannot see the customer tenant from this
            instance, so users are derived from the workspace's own SigninLogs
            telemetry (which IS reachable via Lighthouse). Identity *write*
            remediation remains unavailable for this workspace.
        """
        workspace = workspace or workspace_registry.managing_workspace() or workspace_registry.default()
        users_map: Dict[str, Dict[str, Any]] = {}

        if self.is_live and workspace:
            graph_credential = None
            graph_source = None
            try:
                mode = workspace.graph_mode
                if mode == "delegated-app":
                    from azure.identity import ClientSecretCredential
                    graph_credential = ClientSecretCredential(
                        tenant_id=workspace.graph_tenant_id,
                        client_id=workspace.graph_client_id,
                        client_secret=workspace.graph_client_secret,
                    )
                    graph_source = f"Microsoft Graph (delegated app · {workspace.display_name})"
                elif mode == "managing-tenant" and self.credential:
                    graph_credential = self.credential
                    graph_source = "Microsoft Graph API (managing tenant)"

                if graph_credential:
                    graph_token = graph_credential.get_token("https://graph.microsoft.com/.default")
                    if graph_token and graph_token.token:
                        headers = {"Authorization": f"Bearer {graph_token.token}", "Content-Type": "application/json"}
                        async with httpx.AsyncClient(timeout=8.0) as client:
                            resp = await client.get(
                                "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,jobTitle,department&$top=100&$orderby=displayName",
                                headers=headers
                            )
                            if resp.status_code == 200:
                                for u in resp.json().get("value", []):
                                    upn = u.get("userPrincipalName") or u.get("mail")
                                    if upn:
                                        users_map[upn.lower()] = {
                                            "objectId": u.get("id"),
                                            "displayName": u.get("displayName") or upn.split("@")[0],
                                            "userPrincipalName": upn,
                                            "email": u.get("mail") or upn,
                                            "jobTitle": u.get("jobTitle") or "SOC Analyst",
                                            "source": graph_source
                                        }
                                if users_map:
                                    logger.info(f"Fetched {len(users_map)} users via {graph_source} for workspace '{workspace.id}'.")
                                    return sorted(list(users_map.values()), key=lambda x: x.get("displayName", ""))
            except Exception as e:
                logger.debug(f"Graph lookup note for workspace '{workspace.id}' (falling back to telemetry): {e}")

        # Log Analytics SigninLogs telemetry (Lighthouse-honored) - the directory
        # fallback for delegated tenants where Graph is unavailable.
        if self.is_live and workspace and self.credential:
            try:
                ws_token = self.credential.get_token("https://api.loganalytics.io/.default")
                ws_id = await self.resolve_workspace_guid(workspace)
                if ws_token and ws_id:
                    query = (
                        "SigninLogs "
                        "| where isnotempty(UserPrincipalName) and isnotempty(UserDisplayName) "
                        "| summarize LastSeen=max(TimeGenerated), SigninCount=count() by UserPrincipalName, UserDisplayName, UserId "
                        "| top 50 by SigninCount desc"
                    )
                    headers = {"Authorization": f"Bearer {ws_token.token}", "Content-Type": "application/json"}
                    async with httpx.AsyncClient(timeout=12.0) as client:
                        resp = await client.post(
                            f"https://api.loganalytics.io/v1/workspaces/{ws_id}/query",
                            headers=headers,
                            json={"query": query}
                        )
                        if resp.status_code == 200:
                            rows = resp.json().get("tables", [{}])[0].get("rows", [])
                            for row in rows:
                                upn = str(row[0]).strip()
                                name = str(row[1]).strip()
                                obj_id = str(row[2]).strip() if len(row) > 2 else None
                                if upn and name and upn.lower() not in users_map:
                                    role_title = "SOC Security Engineer" if "admin" in upn.lower() or "admin" in name.lower() else "Security Analyst"
                                    users_map[upn.lower()] = {
                                        "objectId": obj_id,
                                        "displayName": name,
                                        "userPrincipalName": upn,
                                        "email": upn,
                                        "jobTitle": role_title,
                                        "source": f"SigninLogs telemetry · {workspace.display_name} (Lighthouse)"
                                    }
            except Exception as e:
                logger.error(f"Error querying Entra ID users from Log Analytics for '{workspace.id}': {e}")

        if users_map:
            logger.info(f"Retrieved {len(users_map)} directory users for workspace '{workspace.id if workspace else 'default'}'.")
            return sorted(list(users_map.values()), key=lambda x: x.get("displayName", ""))

        # Standard fallback list of SOC engineers (demo / unconfigured).
        fallback_users = [
            {"objectId": "23d99f38-0162-4ce5-b160-67e1d83ec97e", "displayName": "Ankush Chouhan", "userPrincipalName": "ankush@security.corp", "email": "ankush@security.corp", "jobTitle": "Lead SOC Engineer", "source": "Entra ID Directory"},
            {"objectId": "341c3e9b-7c8c-4fee-9388-94b38cdbe4d3", "displayName": "SOC Administrator", "userPrincipalName": "socadmin@security.corp", "email": "socadmin@security.corp", "jobTitle": "Principal Incident Responder", "source": "Entra ID Directory"},
            {"objectId": "cc3b87e1-ee33-4a90-b2d3-948bcfa6360a", "displayName": "Alex Chen", "userPrincipalName": "alex.chen@security.corp", "email": "alex.chen@security.corp", "jobTitle": "Senior SOC Analyst", "source": "Entra ID Directory"},
            {"objectId": "e3341791-981b-4c78-a46a-7c839312c6a7", "displayName": "Sarah Jenkins", "userPrincipalName": "sarah.j@security.corp", "email": "sarah.j@security.corp", "jobTitle": "Threat Hunting Specialist", "source": "Entra ID Directory"},
            {"objectId": "dd3a9f69-8654-4c41-9abd-97bba090335f", "displayName": "David Vance", "userPrincipalName": "david.v@security.corp", "email": "david.v@security.corp", "jobTitle": "Security Operations Specialist", "source": "Entra ID Directory"},
            {"objectId": "e1d6bad5-9292-4895-a6b0-6dbcf8966de9", "displayName": "Elena Rostova", "userPrincipalName": "elena.r@security.corp", "email": "elena.r@security.corp", "jobTitle": "Tier-2 SOC Analyst", "source": "Entra ID Directory"},
            {"objectId": "8ce11533-351a-4862-abdf-a60d27da5a17", "displayName": "Marcus Thorne", "userPrincipalName": "marcus.t@security.corp", "email": "marcus.t@security.corp", "jobTitle": "Cyber Threat Analyst", "source": "Entra ID Directory"},
            {"objectId": "bab8db06-ff5b-4fb2-9c10-f7dc1c214582", "displayName": "Jordan Lee", "userPrincipalName": "jordan.l@security.corp", "email": "jordan.l@security.corp", "jobTitle": "Cloud Security Engineer", "source": "Entra ID Directory"},
            {"objectId": "6cd93032-66d9-480a-8384-9082402e78ed", "displayName": "Rachel Adams", "userPrincipalName": "rachel.a@security.corp", "email": "rachel.a@security.corp", "jobTitle": "SOC Analyst", "source": "Entra ID Directory"}
        ]
        return fallback_users

    async def assign_incident(
        self,
        incident_id: str,
        user_id: Optional[str] = None,
        user_name: Optional[str] = None,
        user_email: Optional[str] = None,
        user_upn: Optional[str] = None,
        assigned_by: str = "SOC Analyst"
    ) -> Dict[str, Any]:
        """Assign/unassign an incident in its origin workspace."""
        workspace, raw_id = workspace_registry.resolve_ref(incident_id)
        is_unassigning = not bool(user_upn or user_name or user_id)

        owner_obj = {
            "objectId": user_id or None,
            "email": user_email or user_upn or None,
            "assignedTo": user_name if not is_unassigning else None,
            "userPrincipalName": user_upn if not is_unassigning else None
        }

        if self.is_live and workspace.has_arm_coordinates():
            token = self._get_arm_token()
            if token:
                try:
                    base_url = self._get_base_url(workspace)
                    url = f"{base_url}/incidents/{raw_id}?api-version=2023-11-01"
                    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

                    async with httpx.AsyncClient(timeout=15.0) as client:
                        r_get = await client.get(url, headers=headers)
                        if r_get.status_code == 200:
                            props = r_get.json().get("properties", {})
                            props["owner"] = owner_obj

                            resp = await client.put(url, headers=headers, json={"properties": props})
                            if resp.status_code in [200, 201]:
                                assign_desc = "unassigned" if is_unassigning else f"assigned to {user_name} ({user_upn})"
                                logger.info(f"Incident {raw_id} in '{workspace.id}' successfully {assign_desc}.")
                                comment_text = f"👤 **Incident Assignment Update**\nIncident was {assign_desc} by **{assigned_by}** via Sentinel AI Platform."
                                await self.add_comment(incident_id, comment_text, author=assigned_by)
                                return {
                                    "status": "SUCCESS",
                                    "message": f"Incident successfully {assign_desc}.",
                                    "assignedTo": user_name or user_upn,
                                    "owner": owner_obj
                                }
                            else:
                                logger.error(f"Failed to assign incident {raw_id} (HTTP {resp.status_code}): {resp.text}")
                except Exception as e:
                    logger.error(f"Error during incident assignment via ARM API for '{workspace.id}': {e}")

        # Mock fallback.
        for inc in MOCK_INCIDENTS:
            if inc["id"] == raw_id or str(inc.get("incidentNumber")) == raw_id:
                inc["assignedTo"] = user_name or user_upn if not is_unassigning else None
                inc["lastModifiedTimeUtc"] = datetime.utcnow().isoformat() + "Z"
                assign_desc = "unassigned" if is_unassigning else f"assigned to {user_name} ({user_upn})"
                inc.setdefault("comments", []).append({
                    "id": f"c-{uuid.uuid4().hex[:6]}",
                    "author": assigned_by,
                    "message": f"👤 Incident was {assign_desc} by {assigned_by}.",
                    "createdTimeUtc": datetime.utcnow().isoformat() + "Z"
                })
                return {
                    "status": "SUCCESS",
                    "message": f"Incident successfully {assign_desc}.",
                    "assignedTo": user_name or user_upn,
                    "owner": owner_obj
                }

        return {"status": "NOT_FOUND", "message": f"Incident {incident_id} not found."}

sentinel_client = SentinelClient()
