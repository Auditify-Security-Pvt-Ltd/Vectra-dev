"""
Per-user scan queue.

Each authenticated user gets their own FIFO queue and concurrency slot.
Users are completely independent — User A's scan never delays User B.

Tunable via environment variables (set in backend/.env):
  MAX_CONCURRENT_SCANS_PER_USER   default: 1
  QUICK_SCAN_TIMEOUT_SECS         default: 900  (15 min)
  FULL_SCAN_TIMEOUT_SECS          default: 1800 (30 min)
"""
from __future__ import annotations

import asyncio
import os
from typing import Awaitable, Callable, Dict, List, Tuple

# ── Configurable defaults (override via environment) ─────────────────────────
MAX_CONCURRENT_SCANS_PER_USER = int(os.getenv("MAX_CONCURRENT_SCANS_PER_USER", "1"))
QUICK_SCAN_TIMEOUT_SECS       = int(os.getenv("QUICK_SCAN_TIMEOUT_SECS",        str(15 * 60)))
FULL_SCAN_TIMEOUT_SECS        = int(os.getenv("FULL_SCAN_TIMEOUT_SECS",         str(30 * 60)))


class UserScanQueue:
    """
    Independent FIFO queue per user_id.

    API:
      enqueue(user_id, scan_id, target, profile)   — add to user's queue
      remove(scan_id)                               — pull a scan from all queues (cancel)
      try_start_next(user_id, runner)               — start next if user has capacity
    """

    def __init__(
        self,
        scans: Dict[str, dict],
        tasks: Dict[str, asyncio.Task],
        active_statuses: frozenset,
    ) -> None:
        self._scans  = scans
        self._tasks  = tasks
        self._active = active_statuses
        # user_id → [(scan_id, target, profile), ...]
        self._queues: Dict[str, List[Tuple[str, str, str]]] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def enqueue(self, user_id: str, scan_id: str, target: str, profile: str) -> None:
        self._queues.setdefault(user_id, []).append((scan_id, target, profile))

    def remove(self, scan_id: str) -> None:
        """Remove a scan from whichever user's queue it lives in."""
        for queue in self._queues.values():
            # Iterate backwards so removal doesn't skip entries
            for entry in list(queue):
                if entry[0] == scan_id:
                    queue.remove(entry)
                    return

    async def try_start_next(
        self,
        user_id: str,
        runner: Callable[[str, str, str], Awaitable[None]],
    ) -> None:
        """
        If the user has a free slot, pop the next pending scan and launch it.
        Called both when a scan is enqueued AND when a running scan finishes.
        """
        queue = self._queues.get(user_id, [])
        while queue and self._count_active_for(user_id) < MAX_CONCURRENT_SCANS_PER_USER:
            scan_id, target, profile = queue.pop(0)
            # Skip stale entries (scan was cancelled while queued)
            if self._scans.get(scan_id, {}).get("status") != "queued":
                continue
            task = asyncio.create_task(
                self._run_and_release(scan_id, target, profile, user_id, runner)
            )
            self._tasks[scan_id] = task
            break

    # ── Internals ─────────────────────────────────────────────────────────────

    def _count_active_for(self, user_id: str) -> int:
        return sum(
            1
            for s in self._scans.values()
            if s.get("userId") == user_id and s["status"] in self._active
        )

    async def _run_and_release(
        self,
        scan_id: str,
        target: str,
        profile: str,
        user_id: str,
        runner: Callable[[str, str, str], Awaitable[None]],
    ) -> None:
        try:
            await runner(scan_id, target, profile)
        finally:
            # Always attempt to start the next scan for this user, even on error/cancel
            asyncio.create_task(self.try_start_next(user_id, runner))
