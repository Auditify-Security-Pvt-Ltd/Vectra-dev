"""
Network scan scheduler — local JSON persistence + asyncio background ticker.
Schedules are stored in backend/data/network_schedules.json and loaded on startup.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/network/schedules", tags=["Network Schedules"])

# ── Persistence ───────────────────────────────────────────────────────

_DATA_DIR       = Path(__file__).parent.parent / "data"
_SCHEDULES_FILE = _DATA_DIR / "network_schedules.json"
_SCHEDULES: Dict[str, dict] = {}
_SCHEDULER_TASK: "asyncio.Task | None" = None


# ── Pydantic models ───────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    userId:   str
    target:   str
    profile:  str = "QUICK_SCAN"
    interval: str  # "once" | "daily" | "weekly" | "monthly"
    enabled:  bool = True
    label:    Optional[str] = None


class ScheduleUpdate(BaseModel):
    target:   Optional[str]  = None
    profile:  Optional[str]  = None
    interval: Optional[str]  = None
    enabled:  Optional[bool] = None
    label:    Optional[str]  = None


# ── Persistence helpers ───────────────────────────────────────────────

def _save() -> None:
    try:
        _DATA_DIR.mkdir(exist_ok=True)
        _SCHEDULES_FILE.write_text(json.dumps(_SCHEDULES, indent=2))
    except Exception as exc:
        logger.error(f"[SCHED] save error: {exc}")


def _load() -> None:
    if not _SCHEDULES_FILE.exists():
        return
    try:
        data = json.loads(_SCHEDULES_FILE.read_text())
        _SCHEDULES.update(data)
        logger.info(f"[SCHED] Loaded {len(_SCHEDULES)} schedule(s)")
    except Exception as exc:
        logger.error(f"[SCHED] load error: {exc}")


# ── Interval helpers ──────────────────────────────────────────────────

def _next_run_dt(sched: dict) -> Optional[datetime]:
    interval = sched.get("interval", "once")
    last_run = sched.get("lastRun")

    if interval == "once":
        return None if last_run else datetime.now(timezone.utc)

    if not last_run:
        return datetime.now(timezone.utc)

    try:
        last_dt = datetime.fromisoformat(last_run)
    except Exception:
        return datetime.now(timezone.utc)

    deltas: Dict[str, timedelta] = {
        "daily":   timedelta(days=1),
        "weekly":  timedelta(weeks=1),
        "monthly": timedelta(days=30),
    }
    delta = deltas.get(interval)
    return (last_dt + delta) if delta else None


def _next_run_iso(sched: dict) -> Optional[str]:
    dt = _next_run_dt(sched)
    return dt.isoformat() if dt else None


def _is_due(sched: dict) -> bool:
    if not sched.get("enabled", True):
        return False
    next_dt = _next_run_dt(sched)
    if not next_dt:
        return False
    return datetime.now(timezone.utc) >= next_dt


# ── Scheduler tick ────────────────────────────────────────────────────

async def _tick() -> None:
    # Import at call time to avoid circular imports at module load
    from api.network_scans import _SCANS, _QUEUE, _execute_network_scan, _blank_scan

    now = datetime.now(timezone.utc).isoformat()
    for sched_id, sched in list(_SCHEDULES.items()):
        if not _is_due(sched):
            continue

        scan_id = f"nscan_{uuid.uuid4().hex[:12]}"
        user_id = sched["userId"]
        target  = sched["target"]
        profile = sched["profile"]

        _SCANS[scan_id] = _blank_scan(scan_id, target, profile, user_id)
        _QUEUE.enqueue(user_id, scan_id, target, profile)
        asyncio.create_task(_QUEUE.try_start_next(user_id, _execute_network_scan))

        _SCHEDULES[sched_id]["lastRun"]    = now
        _SCHEDULES[sched_id]["lastScanId"] = scan_id
        _save()

        logger.info(f"[SCHED] Triggered {scan_id} for {target} (schedule={sched_id})")


async def _scheduler_loop() -> None:
    await asyncio.sleep(30)  # let startup settle
    while True:
        try:
            await _tick()
        except Exception as exc:
            logger.error(f"[SCHED] tick error: {exc}", exc_info=True)
        await asyncio.sleep(60)


def start_scheduler() -> None:
    global _SCHEDULER_TASK
    _load()
    if _SCHEDULER_TASK is None or _SCHEDULER_TASK.done():
        _SCHEDULER_TASK = asyncio.create_task(_scheduler_loop())
        logger.info(f"[SCHED] Scheduler started — {len(_SCHEDULES)} schedule(s) loaded")


# ── REST endpoints ────────────────────────────────────────────────────

@router.get("")
async def list_schedules(userId: Optional[str] = None) -> List[dict]:
    results = list(_SCHEDULES.values())
    if userId:
        results = [s for s in results if s.get("userId") == userId]
    return [{**s, "nextRun": _next_run_iso(s)} for s in results]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_schedule(body: ScheduleCreate) -> dict:
    sched_id = f"sched_{uuid.uuid4().hex[:12]}"
    now      = datetime.now(timezone.utc).isoformat()
    sched: Dict[str, Any] = {
        "scheduleId": sched_id,
        "userId":     body.userId,
        "target":     body.target,
        "profile":    body.profile,
        "interval":   body.interval,
        "enabled":    body.enabled,
        "label":      body.label or body.target,
        "createdAt":  now,
        "lastRun":    None,
        "lastScanId": None,
    }
    _SCHEDULES[sched_id] = sched
    _save()
    return {**sched, "nextRun": _next_run_iso(sched)}


@router.put("/{sched_id}")
async def update_schedule(sched_id: str, body: ScheduleUpdate) -> dict:
    if sched_id not in _SCHEDULES:
        raise HTTPException(status_code=404, detail="Schedule not found")
    for field, val in body.model_dump(exclude_none=True).items():
        _SCHEDULES[sched_id][field] = val
    _save()
    sched = _SCHEDULES[sched_id]
    return {**sched, "nextRun": _next_run_iso(sched)}


@router.delete("/{sched_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(sched_id: str) -> None:
    if sched_id not in _SCHEDULES:
        raise HTTPException(status_code=404, detail="Schedule not found")
    del _SCHEDULES[sched_id]
    _save()


@router.post("/{sched_id}/trigger")
async def trigger_schedule(sched_id: str) -> dict:
    """Manually trigger a scheduled scan immediately."""
    if sched_id not in _SCHEDULES:
        raise HTTPException(status_code=404, detail="Schedule not found")

    from api.network_scans import _SCANS, _QUEUE, _execute_network_scan, _blank_scan

    sched   = _SCHEDULES[sched_id]
    scan_id = f"nscan_{uuid.uuid4().hex[:12]}"
    user_id = sched["userId"]

    _SCANS[scan_id] = _blank_scan(scan_id, sched["target"], sched["profile"], user_id)
    _QUEUE.enqueue(user_id, scan_id, sched["target"], sched["profile"])
    asyncio.create_task(_QUEUE.try_start_next(user_id, _execute_network_scan))

    now = datetime.now(timezone.utc).isoformat()
    _SCHEDULES[sched_id]["lastRun"]    = now
    _SCHEDULES[sched_id]["lastScanId"] = scan_id
    _save()

    return {"success": True, "scanId": scan_id, "scheduleId": sched_id}
