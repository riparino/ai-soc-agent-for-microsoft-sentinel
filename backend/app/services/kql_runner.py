import asyncio
import logging
import time
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from app.config import settings
from app.services.workspace_registry import workspace_registry, WorkspaceConfig

logger = logging.getLogger(__name__)

class KQLRunner:
    """
    Fleet-aware KQL execution against Azure Log Analytics.

    The managing-tenant credential is shared: under Azure Lighthouse a single
    LogsQueryClient / Log Analytics token can query every delegated workspace, so
    the workspace GUID is supplied per call rather than baked into the client.
    """

    # Tables a demo workspace "ingests" (drives hunt selection in DEMO_MODE / tests).
    DEMO_TABLES = (
        "SigninLogs", "AADNonInteractiveUserSignInLogs", "AuditLogs", "AADUserRiskEvents", "AADRiskyUsers",
        "DeviceLogonEvents", "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceInfo", "DeviceEvents",
        "SecurityAlert", "SecurityIncident", "AzureActivity", "OfficeActivity", "CommonSecurityLog",
        "ThreatIntelligenceIndicator", "Usage", "Heartbeat",
    )
    TABLE_CACHE_SECONDS = 30 * 60

    def __init__(self):
        self.client = None
        self._tables_cache: Dict[str, tuple[float, List[Dict[str, Any]]]] = {}
        self._init_azure_client()

    def _init_azure_client(self):
        from app.services.azure_credentials import build_credential, has_live_credentials, resolve_auth_mode

        if not settings.DEMO_MODE and has_live_credentials():
            try:
                from azure.monitor.query import LogsQueryClient

                # Same identity as the Sentinel client (service principal, managed
                # identity, or the signed-in analyst in AZURE_AUTH_MODE=user).
                credential = build_credential()
                self.client = LogsQueryClient(credential)
                logger.info("Initialized Azure Monitor LogsQueryClient for the workspace fleet (auth mode: %s).", resolve_auth_mode())
            except Exception as e:
                logger.warning(f"Failed to initialize Azure Monitor client (fallback to simulation): {e}")
                self.client = None
        else:
            self.client = None

    async def _resolve_workspace(self, workspace: Optional[WorkspaceConfig]) -> Optional[WorkspaceConfig]:
        """Resolve the target workspace and ensure its Log Analytics GUID is known."""
        workspace = workspace or workspace_registry.default()
        if workspace and not (workspace.workspace_guid and "-" in str(workspace.workspace_guid)):
            try:
                from app.services.sentinel_client import sentinel_client
                await sentinel_client.resolve_workspace_guid(workspace)
            except Exception as e:
                logger.debug(f"Could not resolve workspace GUID in KQL runner: {e}")
        return workspace

    async def list_tables(
        self,
        workspace: Optional[WorkspaceConfig] = None,
        days: int = 7,
        force_refresh: bool = False,
    ) -> Optional[List[Dict[str, Any]]]:
        """Tables that actually received data in the last ``days`` days, from the
        workspace's own ``Usage`` table (cheap; one row per DataType). Returns
        ``None`` when availability cannot be determined (query failed), so callers
        can fall back to "try every hunt and report table errors".
        """
        workspace = await self._resolve_workspace(workspace)
        key = f"{workspace.id if workspace else 'default'}:{days}"
        cached = self._tables_cache.get(key)
        if cached and not force_refresh and time.time() - cached[0] < self.TABLE_CACHE_SECONDS:
            return cached[1]

        if settings.DEMO_MODE:
            now = datetime.utcnow().isoformat() + "Z"
            tables = [{"table": t, "last_record": now, "volume_mb": 1.0} for t in self.DEMO_TABLES]
            self._tables_cache[key] = (time.time(), tables)
            return tables

        query = (
            f"Usage | where TimeGenerated > ago({int(days)}d) "
            "| summarize LastRecord=max(TimeGenerated), VolumeMB=round(sum(Quantity), 2) by DataType "
            "| order by VolumeMB desc"
        )
        res = await self.execute_kql(query, timespan_hours=int(days) * 24 + 1, workspace=workspace)
        if res.get("status") != "SUCCESS":
            logger.warning("Table discovery failed for %s: %s", key, res.get("error") or res.get("status"))
            return None
        rows = (res.get("tables") or [{}])[0].get("rows") or []
        tables = [
            {"table": r.get("DataType"), "last_record": r.get("LastRecord"), "volume_mb": r.get("VolumeMB")}
            for r in rows if r.get("DataType")
        ]
        self._tables_cache[key] = (time.time(), tables)
        return tables

    @staticmethod
    def classify_error(message: str) -> str:
        m = (message or "").lower()
        if "resolve table" in m or "could not be resolved" in m or "semanticerror" in m and "table" in m:
            return "TABLE_NOT_FOUND"
        if "semantic" in m or "syntax" in m or "sem0" in m or "syn0" in m:
            return "QUERY_INVALID"
        if "403" in m or "forbidden" in m or "insufficientaccess" in m or "authorizationfailed" in m:
            return "FORBIDDEN"
        if "401" in m or "unauthorized" in m or "token" in m and "expired" in m:
            return "NOT_AUTHENTICATED"
        if "timeout" in m or "timed out" in m:
            return "TIMEOUT"
        return "QUERY_FAILED"

    def _error(self, query: str, workspace: Optional[WorkspaceConfig], message: str, source: str) -> Dict[str, Any]:
        return {
            "status": "ERROR",
            "error_type": self.classify_error(message),
            "error": message[:2000],
            "source": source,
            "workspace_name": workspace.workspace_name if workspace else None,
            "query": query,
            "tables": [],
            "row_count": 0,
        }

    async def execute_kql(
        self,
        query: str,
        timespan_hours: int = 24,
        workspace: Optional[WorkspaceConfig] = None,
    ) -> Dict[str, Any]:
        """Execute a KQL query against a specific workspace's Log Analytics, or
        generate simulated SOC log results in demo mode."""
        workspace = await self._resolve_workspace(workspace)
        workspace_guid = workspace.workspace_guid if workspace else None
        workspace_name = workspace.workspace_name if workspace else None
        logger.info(
            f"Executing KQL (timespan {timespan_hours}h) on workspace "
            f"'{workspace.id if workspace else 'default'}': {query[:100]}..."
        )

        if not self.client:
            self._init_azure_client()

        # Live Azure client path.
        if self.client and workspace_guid and ("-" in str(workspace_guid)) and not settings.DEMO_MODE:
            try:
                timespan = timedelta(hours=timespan_hours)
                start_time = datetime.utcnow()
                response = await asyncio.to_thread(
                    self.client.query_workspace,
                    workspace_id=workspace_guid,
                    query=query,
                    timespan=timespan,
                )
                if getattr(response, "status", None) is not None and str(response.status).lower().endswith("failure"):
                    raise RuntimeError(str(getattr(response, "partial_error", None) or "query failed"))
                latency_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

                tables = []
                for table in response.tables:
                    columns = [col.name if hasattr(col, "name") else str(col) for col in table.columns]
                    rows = []
                    for row in table.rows:
                        row_dict = {}
                        for col_name, val in zip(columns, row):
                            if hasattr(val, "isoformat"):
                                row_dict[col_name] = val.isoformat() + "Z"
                            elif isinstance(val, (dict, list, str, int, float, bool)) or val is None:
                                row_dict[col_name] = val
                            else:
                                row_dict[col_name] = str(val)
                        rows.append(row_dict)
                    tables.append({"name": getattr(table, "name", "PrimaryResult"), "columns": columns, "rows": rows, "count": len(rows)})

                total_rows = sum(t["count"] for t in tables)
                logger.info(f"KQL executed in {latency_ms}ms on '{workspace.id}', returned {total_rows} rows.")
                return {
                    "status": "SUCCESS",
                    "source": "AZURE_LOG_ANALYTICS (LIVE)",
                    "workspace_id": workspace_guid,
                    "workspace_name": workspace_name,
                    "query": query,
                    "latency_ms": latency_ms,
                    "tables": tables,
                    "row_count": total_rows
                }
            except Exception as e:
                logger.warning(f"LogsQueryClient query error: {e}. Attempting direct ARM REST Query API...")
                arm_error = None
                # Direct ARM Log Analytics REST Query fallback (Lighthouse-honored).
                try:
                    from app.services.sentinel_client import sentinel_client
                    arm_token = sentinel_client._get_arm_token()
                    if arm_token and workspace and workspace.has_arm_coordinates():
                        arm_url = (
                            f"https://management.azure.com/subscriptions/{workspace.subscription_id}"
                            f"/resourceGroups/{workspace.resource_group}"
                            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace.workspace_name}"
                            f"/api/query?api-version=2020-08-01"
                        )
                        start_time = datetime.utcnow()
                        async with httpx.AsyncClient(timeout=25.0) as http_c:
                            arm_resp = await http_c.post(
                                arm_url,
                                headers={"Authorization": f"Bearer {arm_token}", "Content-Type": "application/json"},
                                json={"query": query}
                            )
                            if arm_resp.status_code == 200:
                                raw_tables = arm_resp.json().get("tables", [])
                                tables = []
                                for t in raw_tables:
                                    col_names = [c.get("name", str(c)) for c in t.get("columns", [])]
                                    t_rows = [dict(zip(col_names, r)) for r in t.get("rows", [])]
                                    tables.append({"name": t.get("name", "PrimaryResult"), "columns": col_names, "rows": t_rows, "count": len(t_rows)})
                                latency_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
                                total_rows = sum(t["count"] for t in tables)
                                logger.info(f"ARM KQL executed in {latency_ms}ms on '{workspace.id}', returned {total_rows} rows.")
                                return {
                                    "status": "SUCCESS",
                                    "source": "AZURE_LOG_ANALYTICS (ARM REST)",
                                    "workspace_name": workspace_name,
                                    "query": query,
                                    "latency_ms": latency_ms,
                                    "tables": tables,
                                    "row_count": total_rows
                                }
                            arm_error = f"ARM query HTTP {arm_resp.status_code}: {arm_resp.text[:500]}"
                except Exception as arm_err:
                    arm_error = f"{type(arm_err).__name__}: {arm_err}"
                    logger.error(f"ARM REST Query error: {arm_err}")

                # Live mode never falls back to simulated rows: an analyst must see
                # the real failure (missing table, no access, bad KQL), not fake data.
                message = f"{type(e).__name__}: {e}" + (f" | fallback: {arm_error}" if arm_error else "")
                return self._error(query, workspace, message, "AZURE_LOG_ANALYTICS")

        if not settings.DEMO_MODE:
            if not self.client:
                return self._error(query, workspace, "No Azure credentials available for Log Analytics (sign in with `az login` or set AZURE_AUTH_MODE / service principal).", "NONE")
            return self._error(query, workspace, f"Workspace '{workspace.id if workspace else 'default'}' has no resolvable Log Analytics workspace GUID.", "NONE")

        # Simulated KQL execution based on query patterns.
        query_lower = query.lower()
        rows = []
        columns = []

        if "signinlogs" in query_lower:
            columns = ["TimeGenerated", "UserPrincipalName", "IPAddress", "Location", "ResultType", "AppDisplayName", "RiskLevelDuringSignIn"]
            if "fail" in query_lower or "resulttype != 0" in query_lower or "spray" in query_lower:
                for i in range(1, 8):
                    rows.append({
                        "TimeGenerated": (datetime.utcnow() - timedelta(minutes=15 * i)).isoformat() + "Z",
                        "UserPrincipalName": "jdoe@cybersecurity.corp",
                        "IPAddress": "185.220.101.5",
                        "Location": "Russia",
                        "ResultType": "50126",
                        "AppDisplayName": "Azure Portal",
                        "RiskLevelDuringSignIn": "high"
                    })
            else:
                rows = [
                    {
                        "TimeGenerated": (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z",
                        "UserPrincipalName": "jdoe@cybersecurity.corp",
                        "IPAddress": "185.220.101.5",
                        "Location": "Russia",
                        "ResultType": "0",
                        "AppDisplayName": "Microsoft Office 365 Portal",
                        "RiskLevelDuringSignIn": "high"
                    },
                    {
                        "TimeGenerated": (datetime.utcnow() - timedelta(days=2)).isoformat() + "Z",
                        "UserPrincipalName": "jdoe@cybersecurity.corp",
                        "IPAddress": "198.51.100.4",
                        "Location": "United States (Austin, TX)",
                        "ResultType": "0",
                        "AppDisplayName": "Microsoft Office 365 Portal",
                        "RiskLevelDuringSignIn": "none"
                    }
                ]

        elif "devicelogonevents" in query_lower or "identitylogonevents" in query_lower:
            columns = ["DeviceName", "AccountUpn", "Logons", "Failed", "Types", "RemoteIPs", "Accounts", "LocalAdmin", "LastSeen"]
            rows = [{
                "DeviceName": "wks-exec-094.corp.contoso.com", "AccountUpn": "jdoe@cybersecurity.corp", "Logons": 14, "Failed": 9,
                "Types": ["Network", "RemoteInteractive"], "RemoteIPs": ["185.220.101.5", "10.20.4.17"], "Accounts": ["jdoe"], "LocalAdmin": 1,
                "LastSeen": (datetime.utcnow() - timedelta(minutes=50)).isoformat() + "Z",
            }]

        elif "aadnoninteractive" in query_lower or "auditlogs" in query_lower or "riskevents" in query_lower or "riskyusers" in query_lower:
            columns = ["UserPrincipalName", "Events", "Failed", "IPs", "Apps", "Countries", "FromIncidentIPs", "RiskLevel", "RiskState", "LastSeen"]
            rows = [{
                "UserPrincipalName": "jdoe@cybersecurity.corp", "Events": 31, "Failed": 0, "IPs": ["185.220.101.5", "198.51.100.4"],
                "Apps": ["Microsoft Office", "Azure Portal"], "Countries": ["RU", "US"], "FromIncidentIPs": 12, "RiskLevel": "high",
                "RiskState": "atRisk", "LastSeen": (datetime.utcnow() - timedelta(minutes=20)).isoformat() + "Z",
            }]

        elif "securityalert" in query_lower:
            columns = ["AlertName", "Alerts", "Severities", "Products", "Tactics", "FirstSeen", "LastSeen"]
            rows = [{
                "AlertName": "Anonymous IP address", "Alerts": 2, "Severities": ["Medium"], "Products": ["Azure Active Directory Identity Protection"],
                "Tactics": ["InitialAccess"], "FirstSeen": (datetime.utcnow() - timedelta(days=3)).isoformat() + "Z",
                "LastSeen": (datetime.utcnow() - timedelta(hours=2)).isoformat() + "Z",
            }]

        elif "azureactivity" in query_lower or "azurediagnostics" in query_lower:
            columns = ["OperationNameValue", "Count", "Statuses", "Callers", "IPs", "Resources", "LastSeen"]
            rows = [{
                "OperationNameValue": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", "Count": 1, "Statuses": ["Succeeded"],
                "Callers": ["jdoe@cybersecurity.corp"], "IPs": ["185.220.101.5"], "Resources": ["/subscriptions/.../resourceGroups/rg-finance"],
                "LastSeen": (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z",
            }]

        elif "threatintel" in query_lower:
            columns = ["IndicatorId", "ThreatType", "ConfidenceScore", "Description", "SourceSystem", "ExpirationDateTime"]
            rows = [{
                "IndicatorId": "ti-0001", "ThreatType": "Botnet", "ConfidenceScore": 85, "Description": "Tor exit node observed in credential stuffing",
                "SourceSystem": "Microsoft Defender Threat Intelligence", "ExpirationDateTime": (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z",
            }]

        elif "deviceprocessevents" in query_lower or "securityevent" in query_lower:
            columns = ["TimeGenerated", "DeviceName", "AccountName", "FileName", "FolderPath", "ProcessCommandLine", "InitiatingProcessFileName"]
            rows = [
                {
                    "TimeGenerated": (datetime.utcnow() - timedelta(minutes=45)).isoformat() + "Z",
                    "DeviceName": "WKS-EXEC-094",
                    "AccountName": "jdoe",
                    "FileName": "powershell.exe",
                    "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "ProcessCommandLine": "powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
                    "InitiatingProcessFileName": "WINWORD.EXE"
                },
                {
                    "TimeGenerated": (datetime.utcnow() - timedelta(minutes=44)).isoformat() + "Z",
                    "DeviceName": "WKS-EXEC-094",
                    "AccountName": "jdoe",
                    "FileName": "whoami.exe",
                    "FolderPath": "C:\\Windows\\System32\\whoami.exe",
                    "ProcessCommandLine": "whoami /priv",
                    "InitiatingProcessFileName": "powershell.exe"
                }
            ]

        elif "devicenetworkevents" in query_lower or "commonsecuritylog" in query_lower:
            columns = ["TimeGenerated", "DeviceName", "RemoteIP", "RemotePort", "RemoteUrl", "ActionType"]
            rows = [
                {
                    "TimeGenerated": (datetime.utcnow() - timedelta(minutes=40)).isoformat() + "Z",
                    "DeviceName": "WKS-EXEC-094",
                    "RemoteIP": "45.148.10.12",
                    "RemotePort": 443,
                    "RemoteUrl": "https://update-azure-cdn-service.net/beacon",
                    "ActionType": "ConnectionSuccess"
                }
            ]

        elif "aaduserstatus" in query_lower or "identity" in query_lower:
            columns = ["UserPrincipalName", "Department", "IsPrivileged", "RiskLevel", "MFAEnabled"]
            rows = [
                {
                    "UserPrincipalName": "jdoe@cybersecurity.corp",
                    "Department": "Finance & Executive Operations",
                    "IsPrivileged": "True (Global Reader, Billing Admin)",
                    "RiskLevel": "High",
                    "MFAEnabled": "True"
                }
            ]

        else:
            columns = ["TimeGenerated", "Activity", "Source", "Result"]
            rows = [
                {
                    "TimeGenerated": datetime.utcnow().isoformat() + "Z",
                    "Activity": "Security Baseline Query Executed",
                    "Source": "Microsoft Sentinel Log Analytics",
                    "Result": "No abnormal anomalies matching filter found in standard baseline window."
                }
            ]

        return {
            "status": "SUCCESS",
            "source": "SIMULATED_LOG_ANALYTICS (DEMO)",
            "workspace_name": workspace_name,
            "query": query,
            "timespan_hours": timespan_hours,
            "tables": [
                {
                    "name": "PrimaryResult",
                    "columns": columns,
                    "rows": rows,
                    "count": len(rows)
                }
            ],
            "row_count": len(rows)
        }

kql_runner = KQLRunner()
