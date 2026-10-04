import logging
import httpx
from typing import Dict, Any, Optional
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

    def __init__(self):
        self.client = None
        self._init_azure_client()

    def _init_azure_client(self):
        has_creds = bool(
            (settings.USE_MANAGED_IDENTITY) or
            (settings.AZURE_TENANT_ID and settings.AZURE_CLIENT_ID and settings.AZURE_CLIENT_SECRET)
        )
        if not settings.DEMO_MODE and has_creds:
            try:
                from azure.identity import DefaultAzureCredential, ClientSecretCredential
                from azure.monitor.query import LogsQueryClient

                if settings.USE_MANAGED_IDENTITY:
                    credential = DefaultAzureCredential()
                elif settings.AZURE_TENANT_ID and settings.AZURE_CLIENT_ID and settings.AZURE_CLIENT_SECRET:
                    credential = ClientSecretCredential(
                        tenant_id=settings.AZURE_TENANT_ID,
                        client_id=settings.AZURE_CLIENT_ID,
                        client_secret=settings.AZURE_CLIENT_SECRET
                    )
                else:
                    credential = DefaultAzureCredential()

                self.client = LogsQueryClient(credential)
                logger.info("Initialized shared Azure Monitor LogsQueryClient for the workspace fleet.")
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
                response = self.client.query_workspace(
                    workspace_id=workspace_guid,
                    query=query,
                    timespan=timespan
                )
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
                except Exception as arm_err:
                    logger.error(f"ARM REST Query error: {arm_err}")

                logger.warning(f"Live Log Analytics execution unavailable ({e}). Falling back to simulation engine.")

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
