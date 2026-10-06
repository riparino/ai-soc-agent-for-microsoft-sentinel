"""
Coordinate triage between analysts so two people don't work the same incident.

Sentinel's incident *owner* is the lock, and the write that sets it is
ETag-conditional (see ``SentinelClient.assign_incident``), so the coordination
holds across every analyst's local MCP server, the web console and the Sentinel /
Defender portals alike — there is no side channel to keep in sync.

Order of operations for ``run_coordinated_triage``:

1. Re-read the incident (fresh owner, etag, comments).
2. If another analyst owns it and ``claim`` is on -> ``ALREADY_ASSIGNED`` (no work).
3. If an AI triage comment younger than ``dedupe_minutes`` exists -> ``RECENTLY_TRIAGED``.
4. If unassigned and ``claim`` is on -> assign to the actor with ``only_if_unassigned``
   (ETag-conditional). Losing that race -> ``ALREADY_ASSIGNED`` / ``CONFLICT``.
5. Run the triage agent and return its report, annotated with ``coordination``.

``force=True`` skips 2-3 (and never steals ownership). An actor without a usable
identity (service principal, demo mode) can't claim, so only dedupe applies.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

from app.config import settings
from app.services.sentinel_client import sentinel_client
from app.services.triage_store import TRIAGE_REPORTS_CACHE

logger = logging.getLogger(__name__)

# Both triage-agent comment variants start with this (LLM and deterministic paths).
AI_TRIAGE_COMMENT_MARKER = "### 🤖 AI"


def _parse_utc(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:  # noqa: BLE001
        return None


def recent_ai_triage(incident: Dict[str, Any], window_minutes: int) -> Optional[Dict[str, Any]]:
    """Return the newest AI triage comment within the window, if any."""
    if window_minutes <= 0:
        return None
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    newest: Optional[Dict[str, Any]] = None
    for c in incident.get("comments") or []:
        if not str(c.get("message", "")).startswith(AI_TRIAGE_COMMENT_MARKER):
            continue
        ts = _parse_utc(c.get("createdTimeUtc"))
        if ts and ts >= cutoff and (newest is None or ts > _parse_utc(newest.get("createdTimeUtc"))):
            newest = c
    return newest


def actor_can_claim(actor: Optional[Dict[str, Any]]) -> bool:
    return bool(actor and (actor.get("upn") or actor.get("object_id")) and actor.get("kind", "user") == "user")


async def run_coordinated_triage(
    incident_ref: str,
    actor: Optional[Dict[str, Any]],
    claim: bool = True,
    dedupe: bool = True,
    force: bool = False,
    progress_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    dedupe_minutes: Optional[int] = None,
) -> Dict[str, Any]:
    from app.agent.triage_agent import triage_agent

    window = settings.TRIAGE_DEDUPE_MINUTES if dedupe_minutes is None else dedupe_minutes
    incident = await sentinel_client.get_incident(incident_ref)
    if not incident:
        return {"status": "NOT_FOUND", "incident_ref": incident_ref}

    owner = incident.get("owner") or {}
    owned_by_other = sentinel_client._owner_is_set(owner) and not (
        actor and sentinel_client._same_owner(owner, actor.get("object_id"), actor.get("upn"), actor.get("name"))
    )
    coordination: Dict[str, Any] = {"claim_requested": claim, "claimed": False, "owner": owner or None}

    if not force:
        if claim and owned_by_other:
            return {
                "status": "ALREADY_ASSIGNED",
                "incident_ref": incident["id"],
                "owner": owner,
                "message": f"Incident is assigned to {owner.get('assignedTo') or owner.get('userPrincipalName') or owner.get('email')}; not triaging it to avoid duplicate work.",
                "hint": "Coordinate with the owner, read their findings in the incident comments, or re-run with force=true to triage anyway (ownership is not changed).",
            }
        recent = recent_ai_triage(incident, window)
        if dedupe and recent:
            return {
                "status": "RECENTLY_TRIAGED",
                "incident_ref": incident["id"],
                "triaged_at": recent.get("createdTimeUtc"),
                "triaged_by": recent.get("author"),
                "owner": owner or None,
                "message": f"An AI triage report was posted on this incident at {recent.get('createdTimeUtc')} (within the last {window} minutes).",
                "hint": "Read it via sentinel_get_incident (comments) or sentinel_get_triage_report; re-run with force=true to triage again.",
            }

    if claim and not owned_by_other and not sentinel_client._owner_is_set(owner):
        if actor_can_claim(actor):
            res = await sentinel_client.assign_incident(
                incident["id"],
                user_id=actor.get("object_id"),
                user_name=actor.get("name"),
                user_email=actor.get("email") or actor.get("upn"),
                user_upn=actor.get("upn"),
                assigned_by=actor.get("name") or actor.get("upn") or "analyst",
                only_if_unassigned=True,
                expected_etag=incident.get("etag"),
            )
            if res.get("status") in ("ALREADY_ASSIGNED", "CONFLICT"):
                # Someone else claimed it between our read and our write.
                fresh = await sentinel_client.get_incident(incident["id"]) or incident
                fresh_owner = fresh.get("owner") or res.get("owner") or {}
                if actor and sentinel_client._same_owner(fresh_owner, actor.get("object_id"), actor.get("upn"), actor.get("name")):
                    coordination["claimed"] = True
                    coordination["owner"] = fresh_owner
                    incident = fresh
                else:
                    return {
                        "status": "ALREADY_ASSIGNED",
                        "incident_ref": incident["id"],
                        "owner": fresh_owner,
                        "message": "Another analyst claimed this incident a moment ago.",
                        "hint": "Pick another incident, or coordinate with the owner.",
                    }
            elif res.get("status") == "SUCCESS":
                coordination["claimed"] = True
                coordination["owner"] = res.get("owner")
                incident = await sentinel_client.get_incident(incident["id"]) or incident
            else:
                logger.warning("Claim failed for %s: %s", incident["id"], res.get("message") or res.get("status"))
                coordination["claim_error"] = res.get("message") or res.get("status")
        else:
            coordination["claim_skipped"] = "no user identity to assign to (service principal / demo mode)"

    report = await triage_agent.triage_incident(incident, progress_callback=progress_callback)
    TRIAGE_REPORTS_CACHE[incident["id"]] = report
    report["coordination"] = coordination
    return report
