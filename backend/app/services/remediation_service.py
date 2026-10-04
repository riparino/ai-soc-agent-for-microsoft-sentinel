import logging
from datetime import datetime
from typing import Dict, Any, Optional
from app.config import settings
from app.services.sentinel_client import sentinel_client

logger = logging.getLogger(__name__)

class RemediationService:
    """
    Automated Security Orchestration, Automation, and Response (SOAR)
    Remediation engine for Microsoft Sentinel, Microsoft Entra ID, and Defender XDR.
    """

    # Containment actions whose live integrations are NOT implemented yet. In
    # live mode these must not claim success; in demo mode they are simulated and
    # clearly labelled as such. Only `close_false_positive` performs real work.
    _SIMULATED_ACTIONS = {
        "isolate_endpoint": {
            "description": "isolate endpoint '{entity}' from the network via Microsoft Defender for Endpoint",
            "tags": ["Containment-DeviceIsolated", "Defender-Isolated"],
        },
        "revoke_sessions": {
            "description": "revoke active Microsoft Entra ID sessions and refresh tokens for '{entity}'",
            "tags": ["Containment-SessionsRevoked", "EntraID-Revoked"],
        },
        "block_ip": {
            "description": "block IP '{entity}' at the perimeter firewall and Sentinel threat-intel feed",
            "tags": ["Perimeter-Blocked", "IOC-Blacklisted"],
        },
        "disable_account": {
            "description": "disable account '{entity}' in Microsoft Entra ID",
            "tags": ["Account-Disabled", "Compromise-Contained"],
        },
        "trigger_playbook": {
            "description": "trigger a Sentinel SOAR playbook for this incident",
            "tags": ["Playbook-Triggered", "SOAR-Automated"],
        },
    }

    async def execute_remediation(
        self,
        incident_id: str,
        action_type: str,
        entity: str,
        analyst_name: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes a targeted containment or remediation action and logs the audit trail into Sentinel.

        Actions whose live Azure/Defender/Graph integrations are not implemented
        return status SIMULATED (demo mode) or NOT_IMPLEMENTED (live mode); they
        never report SUCCESS for an action that did not actually take effect.
        """
        parameters = parameters or {}
        timestamp = datetime.utcnow().isoformat() + "Z"
        logger.info(f"Executing remediation '{action_type}' for entity '{entity}' by {analyst_name}")

        # Real, implemented action: close the incident as a false positive.
        if action_type == "close_false_positive":
            reason = parameters.get("reason", "Authorized Security Testing / Benign Scanner Noise")
            await sentinel_client.update_status(
                incident_id=incident_id,
                status="Closed",
                classification="FalsePositive",
                classification_reason=reason,
                labels=["Closed-FalsePositive", "AI-Verified"]
            )
            result_message = f"Incident #{incident_id} closed in Microsoft Sentinel as False Positive. Reason: {reason}."
            await sentinel_client.add_comment(
                incident_id,
                f"### ⚡ Remediation Executed\n- **Action:** `close_false_positive`\n"
                f"- **Executed By:** `{analyst_name}`\n- **Timestamp:** `{timestamp}`\n"
                f"- **Result:** {result_message}",
                author=analyst_name,
            )
            return {
                "status": "SUCCESS",
                "action_type": action_type,
                "entity": entity,
                "result_message": result_message,
                "executed_by": analyst_name,
                "timestamp": timestamp,
                "applied_tags": ["Closed-FalsePositive"],
                "simulated": False,
            }

        spec = self._SIMULATED_ACTIONS.get(action_type)
        if spec is None:
            return {
                "status": "ERROR",
                "message": f"Remediation action '{action_type}' is not supported.",
            }

        intent = spec["description"].format(entity=entity)

        # Live mode: the integration does not exist, so do not pretend it ran and
        # do not write a false containment record into the incident.
        if not settings.DEMO_MODE:
            result_message = (
                f"NOT EXECUTED: the live integration to {intent} is not implemented in this build. "
                f"No change was made. Perform this containment action manually in the relevant portal."
            )
            logger.warning(f"Remediation '{action_type}' requested in live mode but not implemented; no action taken.")
            return {
                "status": "NOT_IMPLEMENTED",
                "action_type": action_type,
                "entity": entity,
                "result_message": result_message,
                "executed_by": analyst_name,
                "timestamp": timestamp,
                "applied_tags": [],
                "simulated": False,
            }

        # Demo mode: simulate and label the audit trail explicitly as a simulation.
        result_message = f"[SIMULATION] Demo mode: would {intent}. No real change was made."
        applied_tags = [f"SIMULATED-{t}" for t in spec["tags"]]
        await sentinel_client.add_comment(
            incident_id,
            f"### 🧪 Simulated Remediation (Demo Mode)\n- **Action:** `{action_type}`\n"
            f"- **Target Entity:** `{entity}`\n- **Executed By:** `{analyst_name}`\n"
            f"- **Timestamp:** `{timestamp}`\n- **Result:** {result_message}",
            author=analyst_name,
        )
        incident = await sentinel_client.get_incident(incident_id)
        if incident:
            existing_labels = incident.get("labels", [])
            new_labels = list(set(existing_labels + applied_tags))
            await sentinel_client.update_status(
                incident_id=incident_id, status=incident.get("status", "Active"), labels=new_labels
            )

        return {
            "status": "SIMULATED",
            "action_type": action_type,
            "entity": entity,
            "result_message": result_message,
            "executed_by": analyst_name,
            "timestamp": timestamp,
            "applied_tags": applied_tags,
            "simulated": True,
        }

remediation_service = RemediationService()
