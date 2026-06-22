from __future__ import annotations

"""
CVE Correlation Orchestrator
─────────────────────────────
Receives a list of technologies (from httpx-toolkit asset detection),
queries the NVD for each one with a version, and streams CVE documents.

In-memory state mirrors the asset_discovery.py pattern:
  CORRELATIONS  → metadata per correlation run
  CVE_RESULTS   → accumulated CVE docs per correlation run
  CORR_TASKS    → asyncio Task handles
"""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from intelligence.nvd_client import get_cves_for_technology, parse_tech
from utils.logger import get_logger

logger = get_logger(__name__)

# ── Shared in-memory state ────────────────────────────────────────────
CORRELATIONS: Dict[str, dict] = {}
CVE_RESULTS:  Dict[str, List[dict]] = {}
CORR_TASKS:   Dict[str, asyncio.Task] = {}

ACTIVE_STATUSES = {"running"}


# ── Helpers ───────────────────────────────────────────────────────────

def make_correlation_id() -> str:
    return f"corr_{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(corr_id: str, message: str) -> None:
    c = CORRELATIONS.get(corr_id)
    if c is not None:
        c["logs"].append({
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "message": message,
        })


# ── Correlation task ──────────────────────────────────────────────────

async def execute_correlation(
    corr_id: str,
    asset_id: str,
    asset_url: str,
    technologies: List[str],
    discovery_id: str,
) -> None:
    """
    For each technology with a version, query NVD and append results.
    CVE docs are appended to CVE_RESULTS as they arrive.
    """
    corr = CORRELATIONS[corr_id]
    CVE_RESULTS[corr_id] = []

    try:
        corr["status"] = "running"
        _log(corr_id, f"Starting CVE correlation for {asset_url}")

        # Parse and filter technologies that have a version
        versioned = []
        for tech_str in technologies:
            name, version = parse_tech(tech_str)
            if version:
                versioned.append((name, version))
            else:
                _log(corr_id, f"Skipping {name!r} — no version detected")

        if not versioned:
            _log(corr_id, "No versioned technologies to correlate")
            corr["status"] = "completed"
            corr["currentStep"] = "Completed"
            corr["completedAt"] = _now_iso()
            return

        _log(corr_id, f"Correlating {len(versioned)} versioned technolog{'ies' if len(versioned) != 1 else 'y'}")
        corr["currentStep"] = f"Querying NVD ({len(versioned)} technologies)"

        for idx, (name, version) in enumerate(versioned, 1):
            if corr.get("status") not in ("running",):
                break

            corr["currentStep"] = f"[{idx}/{len(versioned)}] Querying NVD for {name} {version}"
            _log(corr_id, f"Querying NVD: {name} {version}")

            cves = await get_cves_for_technology(name, version)

            for raw in cves:
                doc_id = f"{raw['cveId']}_{asset_id}"
                cve_doc = {
                    **raw,
                    "id":          doc_id,
                    "assetId":     asset_id,
                    "assetUrl":    asset_url,
                    "discoveryId": discovery_id,
                    "createdAt":   _now_iso(),
                }
                CVE_RESULTS[corr_id].append(cve_doc)

            found = len(cves)
            _log(corr_id, f"{name} {version} → {found} CVE{'s' if found != 1 else ''}")
            corr["totalFound"] = len(CVE_RESULTS[corr_id])

        total = len(CVE_RESULTS[corr_id])
        corr["status"]      = "completed"
        corr["currentStep"] = "Completed"
        corr["completedAt"] = _now_iso()
        corr["totalFound"]  = total
        _log(corr_id, f"Correlation complete — {total} CVEs found")
        logger.info(f"[{corr_id}] Completed — {total} CVEs for asset {asset_id}")

    except asyncio.CancelledError:
        corr["status"]      = "cancelled"
        corr["currentStep"] = "Cancelled"
        _log(corr_id, "Correlation cancelled")

    except Exception as exc:
        logger.error(f"[{corr_id}] Error: {exc}")
        corr["status"]      = "failed"
        corr["currentStep"] = "Failed"
        corr["error"]       = str(exc)
        _log(corr_id, f"Error: {exc}")

    finally:
        CORR_TASKS.pop(corr_id, None)
