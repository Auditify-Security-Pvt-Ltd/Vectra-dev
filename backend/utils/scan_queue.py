"""
Per-user + global network scan queue with concurrency control and stale detection.

═══════════════════════════════════════════════════════════════════════════════
ROOT CAUSE OF "QUEUED FOREVER" BUG (FIXED):
  The old _count_active_for() counted "queued" status scans as occupying a slot.
  With MAX_CONCURRENT_SCANS_PER_USER=1 (old default), the very first queued scan
  immediately filled the only available slot before it ever started, because
  "queued" was included in the active_statuses frozenset passed from _ACTIVE.

  Result: try_start_next() saw count=1 >= limit=1 on every call → loop never ran.

FIX: Track live worker slots using the _tasks dict, not status strings.
  A slot is occupied iff scan_id is in _tasks (live asyncio Task registered).
  Queued scans have no task → they don't occupy a slot → scan starts correctly.
  On completion, _tasks[scan_id] is deleted before try_start_next fires.
═══════════════════════════════════════════════════════════════════════════════

Tunable via environment variables:
  MAX_CONCURRENT_SCANS_PER_USER   default: 1  (one active scan per user; the rest wait)
  MAX_NETWORK_WORKERS             default: 5  (global cap across all users)
  QUICK_SCAN_TIMEOUT_SECS         default: 900   (15 min)
  FULL_SCAN_TIMEOUT_SECS          default: 1800  (30 min)
  STALE_SCAN_SECS                 default: 120   (2 min stuck → stale warning)
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Configurable defaults ────────────────────────────────────────────────────
MAX_CONCURRENT_SCANS_PER_USER = int(os.getenv("MAX_CONCURRENT_SCANS_PER_USER", "1"))
MAX_NETWORK_WORKERS           = int(os.getenv("MAX_NETWORK_WORKERS",            "5"))
QUICK_SCAN_TIMEOUT_SECS       = int(os.getenv("QUICK_SCAN_TIMEOUT_SECS",        str(15 * 60)))
FULL_SCAN_TIMEOUT_SECS        = int(os.getenv("FULL_SCAN_TIMEOUT_SECS",         str(30 * 60)))
STALE_SCAN_SECS               = int(os.getenv("STALE_SCAN_SECS",                "120"))


class UserScanQueue:
    """
    Independent FIFO queue per user, with a global worker cap.

    Concurrency slots are tracked via the _tasks dict (live asyncio Tasks),
    NOT via scan status strings. This eliminates the "queued forever" bug where
    'queued' status was mistakenly counted as an occupied slot.

    Public API:
      enqueue(user_id, scan_id, target, profile)
      remove(scan_id)
      try_start_next(user_id, runner)   — idempotent, safe to call concurrently
      stale_scans() → list of (scan_id, user_id, wait_secs)
    """

    def __init__(
        self,
        scans: Dict[str, dict],
        tasks: Dict[str, asyncio.Task],
        active_statuses: frozenset,          # kept for API compatibility; no longer used for slot counting
    ) -> None:
        self._scans  = scans
        self._tasks  = tasks
        # user_id → [(scan_id, target, profile, enqueue_monotonic_time), ...]
        self._queues: Dict[str, List[Tuple[str, str, str, float]]] = {}
        # Per-user asyncio locks so concurrent try_start_next calls don't double-start
        self._locks:  Dict[str, asyncio.Lock] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def enqueue(self, user_id: str, scan_id: str, target: str, profile: str) -> None:
        q = self._queues.setdefault(user_id, [])
        q.append((scan_id, target, profile, time.monotonic()))
        logger.info(
            f"[QUEUE] SCAN_QUEUED scan={scan_id} user={user_id} "
            f"target={target} profile={profile} | queue depth={len(q)}"
        )

    def remove(self, scan_id: str) -> None:
        """Remove a queued scan (e.g. on cancellation)."""
        for user_id, q in self._queues.items():
            before = len(q)
            self._queues[user_id] = [e for e in q if e[0] != scan_id]
            if len(self._queues[user_id]) < before:
                logger.info(f"[QUEUE] Scan {scan_id} removed from queue (user={user_id})")
                return

    async def try_start_next(
        self,
        user_id: str,
        runner: Callable[[str, str, str], Awaitable[None]],
    ) -> None:
        """
        Attempt to start the next queued scan for this user.
        Safe to call concurrently — a per-user lock prevents double-starts.
        """
        lock = self._locks.setdefault(user_id, asyncio.Lock())
        if lock.locked():
            # Another try_start_next for this user is already deciding — skip
            return
        async with lock:
            await self._do_start_next(user_id, runner)

    async def wake(
        self,
        freed_by: Optional[str],
        runner: Callable[[str, str, str], Awaitable[None]],
    ) -> None:
        """
        A worker slot was freed. The freeing user's next scan goes first, then
        other users oldest-waiting first — a user held back only by the global
        cap must not stay queued just because the slot was someone else's.
        """
        waiting = [(q[0][3], uid) for uid, q in self._queues.items() if q and uid != freed_by]
        order = ([freed_by] if freed_by and self._queues.get(freed_by) else []) + [uid for _, uid in sorted(waiting)]
        logger.info(f"[QUEUE] SCAN_SCHEDULER_WAKE freed_by={freed_by} users_waiting={len(order)}")
        for uid in order:
            if self._count_running_globally() >= MAX_NETWORK_WORKERS:
                break
            await self.try_start_next(uid, runner)

    def stale_scans(self) -> List[Tuple[str, str, float]]:
        """
        Return (scan_id, user_id, wait_secs) for queued scans waiting longer
        than STALE_SCAN_SECS. The sweeper uses this to re-trigger starts.
        """
        now = time.monotonic()
        result = []
        for user_id, q in self._queues.items():
            for scan_id, _, _, t in q:
                wait = now - t
                if wait >= STALE_SCAN_SECS:
                    result.append((scan_id, user_id, wait))
        return result

    def running_count(self) -> int:
        """Total live scan tasks (for health / monitoring)."""
        return self._count_running_globally()

    def queue_depth(self) -> Dict[str, int]:
        """Per-user queue depth (for health / monitoring)."""
        return {uid: len(q) for uid, q in self._queues.items() if q}

    # ── Internals ─────────────────────────────────────────────────────────────

    async def _do_start_next(
        self,
        user_id: str,
        runner: Callable[[str, str, str], Awaitable[None]],
    ) -> None:
        q = self._queues.get(user_id, [])

        while q:
            user_slots   = self._count_running_for(user_id)
            global_slots = self._count_running_globally()

            if user_slots >= MAX_CONCURRENT_SCANS_PER_USER:
                logger.info(
                    f"[QUEUE] SCAN_SKIPPED_USER_ACTIVE user={user_id} at capacity "
                    f"({user_slots}/{MAX_CONCURRENT_SCANS_PER_USER} slots) — will retry later"
                )
                break

            if global_slots >= MAX_NETWORK_WORKERS:
                logger.info(
                    f"[QUEUE] SCAN_SKIPPED_GLOBAL_CAP user={user_id} global worker limit reached "
                    f"({global_slots}/{MAX_NETWORK_WORKERS}) — will retry later"
                )
                break

            scan_id, target, profile, enqueue_t = q.pop(0)

            # Skip stale entries (scan was cancelled while waiting)
            status = self._scans.get(scan_id, {}).get("status")
            if status != "queued":
                logger.info(
                    f"[QUEUE] SCAN_SKIPPED_NOT_QUEUED scan={scan_id} status={status}"
                )
                continue

            wait_secs = int(time.monotonic() - enqueue_t)
            logger.info(
                f"[WORKER] SCAN_CLAIMED scan={scan_id} user={user_id} after {wait_secs}s wait | "
                f"user slots: {user_slots+1}/{MAX_CONCURRENT_SCANS_PER_USER} | "
                f"global: {global_slots+1}/{MAX_NETWORK_WORKERS}"
            )

            task = asyncio.create_task(
                self._run_and_release(scan_id, target, profile, user_id, runner)
            )
            self._tasks[scan_id] = task
            # Continue loop — may start more scans if capacity allows
            # (with MAX_CONCURRENT_SCANS_PER_USER=2, we'd loop and start another)

    def _count_running_for(self, user_id: str) -> int:
        """
        Count live worker tasks for this user.

        Uses _tasks membership, NOT status strings.
        A scan is "running" iff its scan_id is in _tasks (we delete on completion).
        Queued scans have no task → they correctly don't occupy a slot.
        """
        return sum(
            1
            for scan_id in list(self._tasks.keys())
            if self._scans.get(scan_id, {}).get("userId") == user_id
        )

    def _count_running_globally(self) -> int:
        """Count all live worker tasks across all users."""
        return len(self._tasks)

    async def _run_and_release(
        self,
        scan_id: str,
        target: str,
        profile: str,
        user_id: str,
        runner: Callable[[str, str, str], Awaitable[None]],
    ) -> None:
        logger.info(f"[WORKER] Worker started for scan {scan_id} (user={user_id})")
        try:
            await runner(scan_id, target, profile)
        except Exception as exc:
            logger.error(
                f"[WORKER] Unhandled exception in scan {scan_id}: {exc}", exc_info=True
            )
        finally:
            # Remove from live task registry BEFORE triggering try_start_next,
            # so the freed slot is visible to the next _count_running_* call.
            self._tasks.pop(scan_id, None)
            logger.info(
                f"[WORKER] SCAN_SLOT_RELEASED scan={scan_id} user={user_id} "
                f"status={self._scans.get(scan_id, {}).get('status')} | "
                f"global running: {self._count_running_globally()}/{MAX_NETWORK_WORKERS}"
            )
            asyncio.create_task(self.wake(user_id, runner))
