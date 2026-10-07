"""
Network scan scheduler — local JSON persistence + asyncio background ticker.
Schedules are stored in backend/data/network_schedules.json and loaded on startup.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from services import firebase, quota
from services.auth import Identity, require_user
from services.scan_guard import claim_for_uid, effective_uid
from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/network/schedules", tags=["Network Schedules"])

# ── Persistence ───────────────────────────────────────────────────────

# SCHEDULES_DIR points at durable storage on hosts with ephemeral disks
# (e.g. a Cloud Storage volume on Cloud Run).
_DATA_DIR       = Path(os.getenv("SCHEDULES_DIR") or Path(__file__).parent.parent / "data")
_SCHEDULES_FILE = _DATA_DIR / "network_schedules.json"
_SCHEDULES: Dict[str, dict] = {}
_SCHEDULER_TASK: "asyncio.Task | None" = None


# ── Pydantic models ───────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    userId:   str = ""   # legacy; ignored when the caller has a verified token
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


# ── Authorization ─────────────────────────────────────────────────────

def _enforced() -> bool:
    return firebase.is_configured()


def _can_access(identity: Identity, sched: dict) -> bool:
    """A schedule is visible to members of the organization of its creator."""
    if not _enforced():
        return True
    caller_org = quota.resolve_org_id(identity.uid)
    return bool(caller_org) and quota.resolve_org_id(sched.get("userId", "")) == caller_org


def _get_authorized(sched_id: str, identity: Identity) -> dict:
    if _enforced():
        identity.require_verified()
    sched = _SCHEDULES.get(sched_id)
    if not sched or not _can_access(identity, sched):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return sched


def _launch(sched_id: str, sched: dict) -> Optional[str]:
    """
    Start one run of a schedule, charged to the creator's organization.
    Returns the scan id, or None when the organization cannot scan (the reason
    is stored on the schedule as lastError).
    """
    from api.network_scans import _SCANS, _QUEUE, _execute_network_scan, _blank_scan, _build_scan_id

    user_id = sched["userId"]
    claim, reason = claim_for_uid(user_id, "network", _build_scan_id())
    now = datetime.now(timezone.utc).isoformat()
    _SCHEDULES[sched_id]["lastRun"] = now

    if claim is None:
        _SCHEDULES[sched_id]["lastError"] = reason
        _save()
        return None

    scan_id = claim.scanId
    _SCANS[scan_id] = _blank_scan(scan_id, sched["target"], sched["profile"], user_id)
    _QUEUE.enqueue(user_id, scan_id, sched["target"], sched["profile"])
    asyncio.create_task(_QUEUE.try_start_next(user_id, _execute_network_scan))

    _SCHEDULES[sched_id]["lastScanId"] = scan_id
    _SCHEDULES[sched_id]["lastError"]  = None
    _save()
    return scan_id


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
    for sched_id, sched in list(_SCHEDULES.items()):
        if not _is_due(sched):
            continue
        scan_id = _launch(sched_id, sched)
        if scan_id:
            logger.info(f"[SCHED] Triggered {scan_id} for {sched['target']} (schedule={sched_id})")


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
async def list_schedules(
    userId: Optional[str] = None,
    identity: Identity = Depends(require_user),
) -> List[dict]:
    results = list(_SCHEDULES.values())
    if _enforced():
        identity.require_verified()
        results = [s for s in results if _can_access(identity, s)]
    elif userId:
        results = [s for s in results if s.get("userId") == userId]
    return [{**s, "nextRun": _next_run_iso(s)} for s in results]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_schedule(body: ScheduleCreate, identity: Identity = Depends(require_user)) -> dict:
    if _enforced():
        identity.require_verified()
    sched_id = f"sched_{uuid.uuid4().hex[:12]}"
    now      = datetime.now(timezone.utc).isoformat()
    sched: Dict[str, Any] = {
        "scheduleId": sched_id,
        # Bound to the verified caller; every run is charged to their organization.
        "userId":     effective_uid(identity, body.userId),
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
async def update_schedule(sched_id: str, body: ScheduleUpdate, identity: Identity = Depends(require_user)) -> dict:
    _get_authorized(sched_id, identity)
    for field, val in body.model_dump(exclude_none=True).items():
        _SCHEDULES[sched_id][field] = val
    _save()
    sched = _SCHEDULES[sched_id]
    return {**sched, "nextRun": _next_run_iso(sched)}


@router.delete("/{sched_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(sched_id: str, identity: Identity = Depends(require_user)) -> None:
    _get_authorized(sched_id, identity)
    del _SCHEDULES[sched_id]
    _save()


@router.post("/{sched_id}/trigger")
async def trigger_schedule(sched_id: str, identity: Identity = Depends(require_user)) -> dict:
    """Manually trigger a scheduled scan immediately. Consumes organization quota."""
    sched   = _get_authorized(sched_id, identity)
    scan_id = _launch(sched_id, sched)
    if scan_id is None:
        reason = sched.get("lastError") or "Scan not allowed"
        limit  = "scan limit" in reason
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED if limit else status.HTTP_403_FORBIDDEN,
            detail={"code": "SCAN_LIMIT_REACHED" if limit else "SCAN_NOT_ALLOWED", "message": reason},
        )
    return {"success": True, "scanId": scan_id, "scheduleId": sched_id}
