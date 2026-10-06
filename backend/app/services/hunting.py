"""Run the hunting catalog for an incident against its own Sentinel workspace.

Selection: a hunt runs when the incident has at least one indicator of a kind the
hunt pivots on AND every table it needs received data recently (per
``KQLRunner.list_tables``). When table availability is unknown the hunt runs anyway
and a missing table surfaces as a per-hunt ``TABLE_NOT_FOUND`` error instead of
being silently skipped.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Iterable, Optional

from app.config import settings
from app.services.hunting_catalog import FAMILIES, HUNTS, HUNTS_BY_ID, Hunt, build_context
from app.services.indicators import extract_indicators
from app.services.kql_runner import kql_runner
from app.services.workspace_registry import WorkspaceConfig, workspace_registry

logger = logging.getLogger(__name__)

ProgressFn = Callable[[str, dict[str, Any]], Any]


def _split(csv: Optional[Iterable[str] | str]) -> list[str]:
    if not csv:
        return []
    if isinstance(csv, str):
        return [p.strip() for p in csv.split(",") if p.strip()]
    return [str(p).strip() for p in csv if str(p).strip()]


def plan_hunts(
    indicators: dict[str, Any],
    available_tables: Optional[list[str]],
    *,
    hunt_ids: Optional[Iterable[str] | str] = None,
    families: Optional[Iterable[str] | str] = None,
    max_hunts: Optional[int] = None,
) -> tuple[list[Hunt], list[dict[str, Any]]]:
    """Return (hunts to run, skipped hunts with reasons)."""
    wanted_ids = set(_split(hunt_ids))
    wanted_families = set(_split(families))
    unknown = [i for i in wanted_ids if i not in HUNTS_BY_ID]
    unknown_f = [f for f in wanted_families if f not in FAMILIES]
    available = (
        {(t["table"] if isinstance(t, dict) else str(t)).lower() for t in available_tables}
        if available_tables is not None else None
    )

    selected: list[Hunt] = []
    skipped: list[dict[str, Any]] = []
    for h in HUNTS:
        if wanted_ids and h.id not in wanted_ids:
            continue
        if wanted_families and h.family not in wanted_families:
            continue
        if not h.applicable(indicators):
            skipped.append({"id": h.id, "title": h.title, "reason": f"incident has no {' / '.join(h.needs)} entities"})
            continue
        missing = h.missing_tables(available)
        if missing:
            skipped.append({"id": h.id, "title": h.title, "reason": f"table not ingested in this workspace: {', '.join(missing)}"})
            continue
        selected.append(h)
    limit = max_hunts or settings.HUNT_MAX_QUERIES
    if limit and len(selected) > limit:
        for h in selected[limit:]:
            skipped.append({"id": h.id, "title": h.title, "reason": f"over the per-run limit of {limit} hunts (raise max_hunts or pick hunts explicitly)"})
        selected = selected[:limit]
    for i in unknown:
        skipped.append({"id": i, "reason": "unknown hunt id"})
    for f in unknown_f:
        skipped.append({"id": f, "reason": f"unknown family (valid: {', '.join(FAMILIES)})"})
    return selected, skipped


async def _notify(progress: Optional[ProgressFn], event: str, payload: dict[str, Any]) -> None:
    if not progress:
        return
    try:
        out = progress(event, payload)
        if asyncio.iscoroutine(out) or isinstance(out, Awaitable):
            await out
    except Exception as e:  # progress reporting must never break a hunt
        logger.debug("hunt progress callback failed: %s", e)


async def hunt_incident(
    incident: dict[str, Any],
    *,
    workspace: Optional[WorkspaceConfig] = None,
    hunt_ids: Optional[Iterable[str] | str] = None,
    families: Optional[Iterable[str] | str] = None,
    max_hunts: Optional[int] = None,
    max_rows: Optional[int] = None,
    dry_run: bool = False,
    lookback_days: Optional[int] = None,
    progress: Optional[ProgressFn] = None,
    concurrency: int = 4,
) -> dict[str, Any]:
    indicators = extract_indicators(incident)
    if workspace is None:
        ws_id = incident.get("workspaceId")
        workspace = workspace_registry.get(ws_id) if ws_id else None
        if workspace is None:
            workspace, _ = workspace_registry.resolve_ref(str(incident.get("id", "")))
    days = lookback_days or settings.HUNT_TABLE_LOOKBACK_DAYS
    rows_cap = max_rows or settings.HUNT_MAX_ROWS

    tables = await kql_runner.list_tables(workspace, days=days)
    selected, skipped = plan_hunts(indicators, tables, hunt_ids=hunt_ids, families=families, max_hunts=max_hunts)
    await _notify(progress, "HUNT_PLAN", {
        "tables_checked": tables is not None,
        "tables_available": [t["table"] for t in tables] if tables else [],
        "planned": [h.id for h in selected],
        "skipped": skipped,
    })

    results: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(max(1, concurrency))

    async def run_one(h: Hunt) -> dict[str, Any]:
        ctx = build_context(indicators, h.window_hours)
        query = h.render(ctx)
        base = {"id": h.id, "title": h.title, "family": h.family, "tables": list(h.tables), "purpose": h.purpose,
                "window_hours": h.window_hours, "query": query}
        if dry_run:
            return {**base, "status": "PLANNED", "row_count": 0, "rows": []}
        await _notify(progress, "KQL_EXECUTION", {**base})
        async with sem:
            try:
                res = await kql_runner.execute_kql(query, timespan_hours=h.window_hours, workspace=workspace)
            except Exception as e:  # defensive: a runner bug must not kill the whole hunt
                res = {"status": "ERROR", "error_type": "QUERY_FAILED", "error": f"{type(e).__name__}: {e}", "tables": [], "row_count": 0}
        rows: list[dict[str, Any]] = []
        for t in res.get("tables") or []:
            rows.extend(t.get("rows") or [])
        out = {
            **base,
            "status": res.get("status", "ERROR"),
            "source": res.get("source"),
            "row_count": res.get("row_count", len(rows)),
            "rows": rows[:rows_cap],
            "truncated": len(rows) > rows_cap,
        }
        if res.get("status") != "SUCCESS":
            out["error_type"] = res.get("error_type", "QUERY_FAILED")
            out["error"] = res.get("error")
        await _notify(progress, "KQL_RESULT", {k: v for k, v in out.items() if k != "rows"})
        return out

    if selected:
        results = list(await asyncio.gather(*(run_one(h) for h in selected)))

    executed = [r for r in results if r["status"] == "SUCCESS"]
    return {
        "incident_ref": incident.get("id"),
        "workspace_id": workspace.id if workspace else incident.get("workspaceId"),
        "indicators": indicators,
        "tables": {
            "checked": tables is not None,
            "lookback_days": days,
            "available": [t["table"] for t in tables] if tables else [],
            "detail": tables or [],
        },
        "hunts": results,
        "skipped": skipped,
        "summary": {
            "planned": len(selected),
            "executed": len(executed),
            "with_hits": sum(1 for r in executed if r["row_count"]),
            "errors": sum(1 for r in results if r["status"] not in ("SUCCESS", "PLANNED")),
            "rows": sum(r["row_count"] for r in executed),
            "dry_run": dry_run,
        },
    }
