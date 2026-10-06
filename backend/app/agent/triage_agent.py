import json
import logging
import asyncio
from typing import Dict, Any, Optional, Callable
from app.config import settings
from app.agent.prompts import SOC_TRIAGE_SYSTEM_PROMPT
from app.agent.tools import execute_tool_call
from app.services.sentinel_client import sentinel_client
from app.services.workspace_registry import workspace_registry

logger = logging.getLogger(__name__)

class SentinelTriageAgent:
    def __init__(self):
        self.openai_client = None
        self.llm_init_error: Optional[str] = None
        self._init_llm_client()

    def _init_llm_client(self):
        try:
            if settings.LLM_PROVIDER == "azure_openai" and settings.AZURE_OPENAI_ENDPOINT and settings.AZURE_OPENAI_API_KEY:
                from openai import AzureOpenAI
                self.openai_client = AzureOpenAI(
                    azure_endpoint=settings.AZURE_OPENAI_ENDPOINT,
                    api_key=settings.AZURE_OPENAI_API_KEY,
                    api_version=settings.AZURE_OPENAI_API_VERSION
                )
                logger.info("Initialized Azure OpenAI client.")
            elif settings.OPENAI_API_KEY:
                from openai import OpenAI
                self.openai_client = OpenAI(api_key=settings.OPENAI_API_KEY)
                logger.info("Initialized standard OpenAI client.")
        except Exception as e:
            logger.warning(f"Could not initialize OpenAI client: {e}")
            self.llm_init_error = f"{type(e).__name__}: {e}"

    @property
    def llm_configured(self) -> bool:
        return self.openai_client is not None

    async def triage_incident(
        self,
        incident: Dict[str, Any],
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end AI investigation of a Sentinel Incident.
        Yields live updates to progress_callback if provided.
        """
        incident_id = incident.get("id", "unknown")
        title = incident.get("title", "Untitled Incident")
        description = incident.get("description", "")
        entities = incident.get("entities", [])

        # Resolve the workspace this incident belongs to so KQL hunts run against
        # the correct delegated Sentinel workspace (not a global singleton).
        if incident.get("workspaceId"):
            workspace = workspace_registry.get(incident.get("workspaceId")) or workspace_registry.default()
        else:
            workspace, _ = workspace_registry.resolve_ref(incident_id)
        
        async def notify(event_type: str, message: str, details: Optional[Dict[str, Any]] = None):
            logger.info(f"[{incident_id}] [{event_type}] {message}")
            if progress_callback:
                if asyncio.iscoroutinefunction(progress_callback):
                    await progress_callback({
                        "event": event_type,
                        "message": message,
                        "details": details or {},
                        "incident_id": incident_id
                    })
                else:
                    progress_callback({
                        "event": event_type,
                        "message": message,
                        "details": details or {},
                        "incident_id": incident_id
                    })

        await notify("INVESTIGATION_STARTED", f"Starting automated AI triage for Incident #{incident.get('incidentNumber', '')}: '{title}'")
        await asyncio.sleep(0.5)

        # Step 1: Entity Extraction & Context Assessment
        extracted_ips = [e.get("address") for e in entities if e.get("kind") == "Ip" and e.get("address")]
        extracted_accounts = [e.get("upn") or e.get("name") for e in entities if e.get("kind") == "Account"]
        extracted_hosts = [e.get("name") for e in entities if e.get("kind") == "Host"]
        extracted_processes = [e.get("commandLine") or e.get("processName") for e in entities if e.get("kind") == "Process"]

        await notify(
            "ENTITIES_EXTRACTED",
            f"Extracted {len(extracted_ips)} IPs, {len(extracted_accounts)} Accounts, {len(extracted_hosts)} Hosts, {len(extracted_processes)} Processes",
            {
                "ips": extracted_ips,
                "accounts": extracted_accounts,
                "hosts": extracted_hosts,
                "processes": extracted_processes
            }
        )
        await asyncio.sleep(0.6)

        # Step 2: Threat Intelligence Lookups
        ti_results = {}
        for ip in extracted_ips:
            await notify("THREAT_INTEL_CHECK", f"Checking threat reputation for IP: {ip}...")
            res = await execute_tool_call("check_ip_reputation", json.dumps({"ip_address": ip}))
            ti_results[ip] = res
            await notify(
                "THREAT_INTEL_RESULT",
                f"Reputation for {ip}: Verdict = {res.get('verdict')}, Score = {res.get('abuse_confidence_score', 0)}/100",
                res
            )
            await asyncio.sleep(0.4)

        # Step 3: Hunt across the workspace's telemetry (catalog-driven).
        # Which tables exist is read from the workspace (Usage), so hunts cover
        # whatever this customer actually ingests: Entra sign-in / audit / risk,
        # Defender XDR Device* / Identity / Email / CloudApp, AzureActivity,
        # AzureDiagnostics, SecurityEvent, Office, firewall CEF, Syslog, alerts, TI.
        from app.services.hunting import hunt_incident

        async def hunt_progress(event: str, payload: Dict[str, Any]) -> None:
            if event == "HUNT_PLAN":
                tables = payload.get("tables_available") or []
                msg = (
                    f"Workspace ingests {len(tables)} tables in the last {settings.HUNT_TABLE_LOOKBACK_DAYS}d; "
                    f"planned {len(payload.get('planned') or [])} hunts, skipped {len(payload.get('skipped') or [])}"
                    if payload.get("tables_checked") else
                    f"Table inventory unavailable; running {len(payload.get('planned') or [])} applicable hunts and reporting missing tables"
                )
                await notify("HUNT_PLAN", msg, payload)
            elif event == "KQL_EXECUTION":
                await notify("KQL_EXECUTION", f"Hunting [{payload.get('id')}] {payload.get('title')} ({', '.join(payload.get('tables') or [])})", {"query": payload.get("query"), "hunt": payload.get("id")})
            elif event == "KQL_RESULT":
                if payload.get("status") == "SUCCESS":
                    await notify("KQL_RESULT", f"[{payload.get('id')}] {payload.get('row_count', 0)} rows from {', '.join(payload.get('tables') or [])}", payload)
                else:
                    await notify("KQL_ERROR", f"[{payload.get('id')}] {payload.get('error_type')}: {str(payload.get('error') or '')[:200]}", payload)

        hunt = await hunt_incident(incident, workspace=workspace, max_rows=10, progress=hunt_progress)
        executed_kql_queries = [h["query"] for h in hunt["hunts"] if h.get("status") == "SUCCESS"]
        kql_findings = [
            {
                "hunt": h["id"], "type": h["title"], "tables": h["tables"], "purpose": h["purpose"],
                "status": h["status"], "row_count": h.get("row_count", 0), "rows": h.get("rows", []),
                **({"error_type": h.get("error_type"), "error": h.get("error")} if h.get("status") != "SUCCESS" else {}),
            }
            for h in hunt["hunts"]
        ]
        data_coverage = {
            "tables_checked": hunt["tables"]["checked"],
            "tables_available": hunt["tables"]["available"],
            "hunts_skipped": hunt["skipped"],
            "summary": hunt["summary"],
        }
        await asyncio.sleep(0.2)

        # Step 4: True/False Positive Reasoning & Verdict Synthesis
        await notify("REASONING", "Synthesizing evidence with AI reasoning engine, calculating confidence score, and mapping to MITRE ATT&CK tactics...")
        await asyncio.sleep(0.8)

        def evidence_pack(status: str, message: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
            """Everything collected, no invented verdict. The MCP client reasons over it."""
            pack = {
                "incident_id": incident_id,
                "status": status,
                "verdict": None,
                "message": message,
                "incident": {k: incident.get(k) for k in ("id", "incidentNumber", "title", "description", "severity", "status",
                                                           "createdTimeUtc", "tactics", "labels", "owner", "workspaceId", "workspaceName")},
                "entities": {"ips": extracted_ips, "accounts": extracted_accounts, "hosts": extracted_hosts, "processes": extracted_processes},
                "alerts": incident.get("alerts", []),
                "comments": incident.get("comments", [])[-10:],
                "threat_intel": ti_results,
                "data_coverage": data_coverage,
                "kql_findings": kql_findings,
                "kql_queries_used": executed_kql_queries,
                "hunting": {"summary": hunt["summary"], "tables_available": hunt["tables"]["available"], "skipped": hunt["skipped"]},
                "how_to_use": (
                    "Reason over kql_findings (only SUCCESS hunts with rows are evidence), threat_intel and the "
                    "alerts/comments to reach a verdict (TRUE_POSITIVE / FALSE_POSITIVE / SUSPICIOUS_ESCALATE), "
                    "state the visibility gaps from data_coverage, then record the conclusion with sentinel_add_comment."
                ),
            }
            if extra:
                pack.update(extra)
            return pack

        if not settings.DEMO_MODE and not self.openai_client:
            pack = evidence_pack(
                "EVIDENCE_COLLECTED",
                "No server-side LLM is configured (fine for MCP use): the hunts and intel lookups ran; the MCP client should reason over this evidence.",
                {"llm": {"configured": False, "init_error": self.llm_init_error}},
            )
            await notify("EVIDENCE_COLLECTED", f"Evidence pack ready: {hunt['summary']['executed']} hunts, {len(ti_results)} intel lookups; no server LLM, verdict left to the client.", {"summary": hunt["summary"]})
            return pack

        # Server-side LLM verdict (live mode with Azure OpenAI / OpenAI configured)
        if self.openai_client and not settings.DEMO_MODE:
            try:
                model_name = settings.AZURE_OPENAI_DEPLOYMENT_NAME if settings.LLM_PROVIDER == "azure_openai" else "gpt-4o"
                prompt_messages = [
                    {"role": "system", "content": SOC_TRIAGE_SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": json.dumps({
                            "incident": incident,
                            "threat_intel": ti_results,
                            "data_coverage": data_coverage,
                            "kql_findings": kql_findings
                        })
                    }
                ]
                
                try:
                    response = self.openai_client.chat.completions.create(
                        model=model_name,
                        messages=prompt_messages,
                        response_format={"type": "json_object"},
                        max_completion_tokens=2500
                    )
                except Exception as param_err:
                    if "max_completion_tokens" in str(param_err).lower() or "unsupported" in str(param_err).lower():
                        response = self.openai_client.chat.completions.create(
                            model=model_name,
                            messages=prompt_messages,
                            response_format={"type": "json_object"},
                            max_tokens=2500,
                            temperature=0.1
                        )
                    else:
                        raise param_err

                verdict_json = json.loads(response.choices[0].message.content)
                verdict_json.setdefault("kql_queries_used", executed_kql_queries)
                verdict_json["hunting"] = {"summary": hunt["summary"], "tables_available": hunt["tables"]["available"], "skipped": hunt["skipped"]}
                await notify("VERDICT_GENERATED", f"AI Triage completed with verdict: {verdict_json.get('verdict')}", verdict_json)
                
                # Auto-post comment to Sentinel if enabled
                if settings.AUTO_POST_COMMENTS_TO_SENTINEL:
                    comment_summary = f"### 🤖 AI Triage Investigation Report\n**Verdict:** {verdict_json.get('verdict')} (Confidence: {verdict_json.get('confidence_score')}%)\n**Summary:** {verdict_json.get('executive_summary')}\n**Actions:** {', '.join(verdict_json.get('recommended_actions', []))}"
                    await sentinel_client.add_comment(incident_id, comment_summary)
                    await notify("SENTINEL_UPDATED", "Triage report automatically posted as comment to Microsoft Sentinel incident.")
                
                return verdict_json
            except Exception as e:
                logger.error(f"LLM completion error: {e}")
                pack = evidence_pack(
                    "LLM_FAILED",
                    "The hunts and intel lookups ran, but the server-side LLM call failed, so no verdict was produced. The evidence is below for the MCP client to reason over.",
                    {"llm": {"configured": True, "error": f"{type(e).__name__}: {e}"[:500],
                             "what_to_check": ["AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY / AZURE_OPENAI_DEPLOYMENT_NAME in backend/.env",
                                               "The deployment name exists and your key has access; see `llm.error`."],
                             "tell_admin": f"Server LLM call failed during triage: {type(e).__name__}: {str(e)[:200]}"}},
                )
                await notify("LLM_FAILED", f"LLM call failed ({type(e).__name__}); returning evidence pack without a verdict.", {"error": str(e)[:300]})
                return pack

        # Demo-mode deterministic engine (DEMO_MODE only; never used against live data)
        verdict = "SUSPICIOUS_ESCALATE"
        confidence = 85
        severity = incident.get("severity", "Medium")
        evidence = []
        recommendations = []
        mitre_tactics = incident.get("tactics", ["Execution"])
        mitre_techniques = incident.get("techniques", ["T1059.001"])
        tags = ["AI-Triaged"]

        # Check for False Positive patterns (e.g. vulnerability scanner)
        if any("scanner" in label.lower() or "vulnerability" in label.lower() for label in incident.get("labels", [])) or "Scanner" in title:
            verdict = "FALSE_POSITIVE"
            confidence = 94
            severity = "Low"
            evidence.append("Activity confirmed as originating from authorized internal vulnerability scanner subnet (Qualys Agent).")
            evidence.append("No successful remote code execution or state alteration observed.")
            recommendations.append("Close incident as False Positive / Authorized Security Testing.")
            recommendations.append("Update Sentinel analytic rule suppression list if scanner noise persists.")
            tags.extend(["FalsePositive-Scanner", "Auto-Close-Recommended"])
            summary = "The detected web scanning activity was verified as an authorized vulnerability assessment routine conducted by the internal security scanner subnet."

        # Check for True Positive (e.g. Encoded PowerShell, Tor sign-in)
        elif any(res.get("abuse_confidence_score", 0) > 70 for res in ti_results.values()) or "PowerShell" in title or "Tor" in title:
            verdict = "TRUE_POSITIVE"
            confidence = 96
            severity = "High"
            for ip, res in ti_results.items():
                if res.get("abuse_confidence_score", 0) > 50:
                    evidence.append(f"External IP {ip} flagged with high abuse confidence score ({res.get('abuse_confidence_score')}/100) on global threat feeds.")
            if "PowerShell" in title:
                evidence.append("WINWORD.EXE spawned powershell.exe with hidden window and Base64 encoded payload execution.")
                evidence.append("Subsequent execution of privilege inspection command (`whoami /priv`) and C2 egress detected.")
            if "Tor" in title:
                evidence.append("User authenticated from anomalous geographical location (Moscow, RU) 15 minutes after active session in Austin, US (Impossible Travel).")
            
            recommendations.append("Isolate endpoint device from the corporate network via Defender for Endpoint.")
            recommendations.append("Revoke active Entra ID sign-in sessions and enforce password reset with MFA.")
            recommendations.append("Block malicious IP addresses at the perimeter Azure Firewall / NSG.")
            tags.extend(["Confirmed-TruePositive", "Containment-Required", "Malware-Investigation"])
            summary = f"High-confidence true positive malicious activity identified. Active exploitation indicators and high-risk IOC connections detected for entity {extracted_accounts[0] if extracted_accounts else extracted_hosts[0] if extracted_hosts else 'target'}."

        else:
            verdict = "SUSPICIOUS_ESCALATE"
            confidence = 78
            evidence.append("Anomalous authentication rate detected surpassing historical baseline.")
            recommendations.append("Contact user to verify recent sign-in attempts.")
            recommendations.append("Monitor account for further credential spray or password spray activity.")
            tags.extend(["Investigate-Analyst", "Suspicious-Activity"])
            summary = "Elevated volume of anomalies detected against user account without definitive proof of full compromise. Tier-2 analyst verification advised."

        # Identify Primary Entities Grounded in Live Incident
        account_name = extracted_accounts[0] if extracted_accounts else incident.get("assignedTo") or "Identity Not Specified"
        host_name = extracted_hosts[0] if extracted_hosts else ("Endpoint Host" if extracted_processes else "Azure Entra ID Cloud Directory")
        c2_ip = extracted_ips[0] if extracted_ips else None

        title_lower = title.lower()
        desc_lower = description.lower()

        # Contextual RCA Generation based on Actual Alert Category
        if "credential" in title_lower or "service principal" in title_lower or "credential" in desc_lower or "service principal" in desc_lower or "key" in title_lower:
            initial_vector = "Administrative or delegated identity added a new secret/certificate credential to an Entra ID Application / Service Principal where no previous verify KeyCredential was present."
            patient_zero_str = f"{account_name} (Entra ID Actor / Identity)"
            
            kill_chain = [
                {"stage": "Initial Access", "tactic": "T1078.004", "description": f"Session authenticated for identity {account_name} from IP {c2_ip or 'external network'}."},
                {"stage": "Persistence", "tactic": "T1098.001", "description": "New OAuth client secret / certificate credential registered on Target Application / Service Principal."},
                {"stage": "Privilege Escalation", "tactic": "T1484", "description": "Alternate authentication material enables unmonitored daemon token acquisition and Graph API access."},
                {"stage": "Defense Evasion", "tactic": "T1550.001", "description": "Use of Application OAuth token bypasses interactive User MFA and Conditional Access policies."}
            ]
            
            proc_tree = []
            c2_telemetry = {
                "destination_ip": c2_ip or "Azure Management Endpoint",
                "port": 443,
                "protocol": "HTTPS (REST ARM / Microsoft Graph API)",
                "bytes_transferred": "Control Plane Telemetry",
                "reputation": "Entra ID Directory Audit Record"
            } if c2_ip else None

            blast_identities = extracted_accounts or [account_name]
            blast_endpoints = extracted_hosts or []
            blast_targets = [e.get("name") for e in entities if e.get("kind") in ["AzureResource", "CloudApplication"]] or ["Entra ID App Registration", "Service Principal Key Store"]

            capa = [
                "Immediately revoke newly added credentials/certificates from the affected Service Principal in Entra ID App Registrations.",
                "Audit permissions and consent granted to the Application (e.g. Directory.ReadWrite.All, Mail.ReadWrite).",
                f"Invalidate active OAuth refresh tokens for identity '{account_name}' and require FIDO2 MFA challenge.",
                "Review Azure Activity and Directory AuditLogs for any downstream API calls made under this Service Principal identity."
            ]

        elif "powershell" in title_lower or "encoded" in title_lower or "malware" in title_lower or "trojan" in title_lower or "ransom" in title_lower:
            initial_vector = "Malicious or encoded script execution spawned on host workstation."
            patient_zero_str = f"{account_name} on host {host_name}"
            
            kill_chain = [
                {"stage": "Execution", "tactic": "T1059.001", "description": f"PowerShell / script engine launched on {host_name}."},
                {"stage": "Defense Evasion", "tactic": "T1027", "description": "Obfuscated / Base64 encoded payload executed in memory."},
                {"stage": "Discovery", "tactic": "T1033", "description": "Execution of privilege inspection and situational awareness queries."},
                {"stage": "Command & Control", "tactic": "T1071", "description": f"Outbound egress connection established to {c2_ip or 'external IP'}."}
            ]

            proc_tree = []
            for p in extracted_processes:
                proc_tree.append({"pid": "Process", "process": p.split(" ")[0], "command": p})
            if not proc_tree:
                proc_tree = [
                    {"pid": "PID-Active", "process": "powershell.exe", "command": "powershell.exe -nop -w hidden -enc ..."}
                ]

            c2_telemetry = {
                "destination_ip": c2_ip or "External Threat Infrastructure",
                "port": 443,
                "protocol": "TCP / HTTPS",
                "bytes_transferred": "Interactive Stream",
                "reputation": "Suspicious External Endpoint"
            } if c2_ip else None

            blast_identities = extracted_accounts or [account_name]
            blast_endpoints = extracted_hosts or [host_name]
            blast_targets = [host_name, "Local SAM / LSASS Process Memory"]

            capa = [
                f"Isolate host '{host_name}' via Microsoft Defender for Endpoint.",
                f"Revoke all active sessions for user account '{account_name}'.",
                "Collect memory dump and initiate full antivirus / EDR remediation scan.",
                "Block any external IP indicators on perimeter firewall / NSG rules."
            ]

        elif "signin" in title_lower or "login" in title_lower or "travel" in title_lower or "spray" in title_lower or "brute" in title_lower:
            initial_vector = f"Anomalous authentication anomaly detected from source IP '{c2_ip or 'external location'}' exceeding security risk baseline."
            patient_zero_str = f"{account_name} (Entra ID User Account)"

            kill_chain = [
                {"stage": "Initial Access", "tactic": "T1078.004", "description": f"Sign-in attempt initiated for user {account_name} from IP {c2_ip or 'external IP'}."},
                {"stage": "Credential Access", "tactic": "T1110", "description": "Anomalous authentication pattern or high-risk sign-in event recorded in SigninLogs."},
                {"stage": "Persistence", "tactic": "T1098", "description": "Potential unauthorized session token creation."}
            ]

            proc_tree = []
            c2_telemetry = {
                "destination_ip": c2_ip or "External Source IP",
                "port": 443,
                "protocol": "HTTPS (Entra ID Authentication)",
                "bytes_transferred": "OAuth Token Exchange",
                "reputation": "External Unrecognized Sign-in Source"
            } if c2_ip else None

            blast_identities = extracted_accounts or [account_name]
            blast_endpoints = []
            blast_targets = ["Microsoft 365 Exchange Online", "Azure Portal", "Entra ID Applications"]

            capa = [
                f"Revoke active Entra ID sessions for '{account_name}' and enforce immediate password reset.",
                "Review Entra ID SigninLogs and NonInteractiveSigninLogs for downstream resource access.",
                "Enforce Conditional Access policy requiring compliant device and Phishing-Resistant MFA."
            ]

        else:
            initial_vector = description if description else f"Security anomaly detected by Sentinel analytic detection rule: '{title}'"
            patient_zero_str = f"{account_name} ({'Host ' + host_name if extracted_hosts else 'Cloud Identity'})"

            kill_chain = [
                {"stage": "Detection", "tactic": mitre_tactics[0] if mitre_tactics else "Execution", "description": title}
            ]
            proc_tree = [{"pid": "N/A", "process": p, "command": p} for p in extracted_processes]
            c2_telemetry = {
                "destination_ip": c2_ip,
                "port": 443,
                "protocol": "TCP / IP",
                "bytes_transferred": "Standard Telemetry",
                "reputation": "Correlated Indicator"
            } if c2_ip else None

            blast_identities = extracted_accounts or [account_name]
            blast_endpoints = extracted_hosts or []
            blast_targets = [e.get("name") for e in entities if e.get("name")] or [title]

            capa = [
                f"Investigate correlated audit logs for identity '{account_name}'.",
                "Validate whether this activity corresponds to authorized administrative change request.",
                "Update Sentinel analytic rule threshold or suppression list if benign."
            ]

        rca_data = {
            "patient_zero": patient_zero_str,
            "initial_access_vector": initial_vector,
            "kill_chain_progression": kill_chain,
            "process_tree": proc_tree,
            "network_c2_telemetry": c2_telemetry or {
                "destination_ip": c2_ip or "No External C2 Observed",
                "port": 443,
                "protocol": "HTTPS",
                "bytes_transferred": "0 KB",
                "reputation": "Internal / Cloud Control Plane"
            },
            "blast_radius": {
                "compromised_identities": blast_identities,
                "compromised_endpoints": blast_endpoints,
                "targeted_assets": blast_targets,
                "data_loss_risk": "High - Privilege / Credential Modification" if "credential" in title_lower or verdict == "TRUE_POSITIVE" else "Low / Contained"
            },
            "corrective_and_preventive_actions": capa
        }

        final_report = {
            "incident_id": incident_id,
            "verdict": verdict,
            "confidence_score": confidence,
            "severity_assessment": severity,
            "mitre_attack": {
                "tactics": mitre_tactics,
                "techniques": mitre_techniques
            },
            "executive_summary": summary,
            "evidence_findings": evidence,
            "recommended_actions": recommendations,
            "kql_queries_used": executed_kql_queries,
            "hunting": {"summary": hunt["summary"], "tables_available": hunt["tables"]["available"], "skipped": hunt["skipped"]},
            "root_cause_analysis": rca_data,
            "suggested_sentinel_status": "Closed" if verdict == "FALSE_POSITIVE" and settings.AUTO_CLOSE_FALSE_POSITIVES else "Active",
            "suggested_classification": "FalsePositive" if verdict == "FALSE_POSITIVE" else "TruePositive" if verdict == "TRUE_POSITIVE" else "Undetermined",
            "tags_to_apply": tags
        }

        await notify("VERDICT_GENERATED", f"AI Triage completed: {verdict} ({confidence}% confidence)", final_report)

        # Auto-post to Sentinel
        if settings.AUTO_POST_COMMENTS_TO_SENTINEL:
            comment_md = f"### 🤖 AI Sentinel Triage Report\n**Verdict:** `{verdict}` | **Confidence:** `{confidence}%`\n\n**Executive Summary:**\n{summary}\n\n**Key Findings:**\n" + "\n".join([f"- {f}" for f in evidence]) + "\n\n**Recommended Actions:**\n" + "\n".join([f"- {a}" for a in recommendations])
            await sentinel_client.add_comment(incident_id, comment_md)
            await notify("SENTINEL_UPDATED", "Triage summary posted as comment into Microsoft Sentinel incident.")

        return final_report


triage_agent = SentinelTriageAgent()
