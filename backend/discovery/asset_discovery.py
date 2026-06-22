from __future__ import annotations

"""
Asset Discovery Orchestrator
────────────────────────────
Owns the in-memory state for discoveries/assets and the async background
task that runs Subfinder → httpx-toolkit.

Imported by api/assets.py which only handles HTTP request/response.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from discovery.subfinder import is_subfinder_available, stream_subdomains
from discovery.httpx_toolkit import is_httpx_toolkit_available, stream_probe_hosts
from utils.logger import get_logger

logger = get_logger(__name__)

# ── Shared in-memory state ────────────────────────────────────────────
DISCOVERIES: Dict[str, dict] = {}
ASSETS:      Dict[str, List[dict]] = {}   # discoveryId → [asset, ...]
DISC_TASKS:  Dict[str, asyncio.Task] = {}

ACTIVE_STATUSES = {"queued", "running"}


# ── ID / timestamp helpers ────────────────────────────────────────────

def make_discovery_id() -> str:
    return f"disc_{uuid.uuid4().hex[:12]}"


def make_asset_id() -> str:
    return f"asset_{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_hms() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _log(discovery_id: str, message: str) -> None:
    disc = DISCOVERIES.get(discovery_id)
    if disc is not None:
        disc["logs"].append({"timestamp": _now_hms(), "message": message})


# ── Background task ───────────────────────────────────────────────────

async def execute_discovery(discovery_id: str, domain: str) -> None:
    """
    Full discovery pipeline:
      1. Check tools (subfinder, httpx-toolkit)
      2. Run subfinder — yield subdomains in real-time
      3. Stream all subdomains through httpx-toolkit in one batch
         (httpx-toolkit uses -threads 200 internally and outputs results immediately)
      4. Write each asset as soon as httpx-toolkit emits it
    """
    disc = DISCOVERIES[discovery_id]
    ASSETS[discovery_id] = []

    try:
        disc["status"] = "running"
        disc["currentStep"] = "Starting"
        _log(discovery_id, f"Discovery started for {domain}")

        # ── Tool availability ─────────────────────────────────────────
        if not await is_subfinder_available():
            raise RuntimeError(
                "subfinder not found in PATH. "
                "Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            )
        if not await is_httpx_toolkit_available():
            raise RuntimeError(
                "httpx-toolkit not found in PATH. "
                "On Kali: sudo apt install httpx-toolkit"
            )

        # ── Step 1: Subfinder ─────────────────────────────────────────
        disc["currentStep"] = "Running Subfinder"
        _log(discovery_id, f"Running Subfinder on {domain}")

        subdomains: List[str] = []
        async for sub in stream_subdomains(domain):
            subdomains.append(sub)
            disc["subdomainsFound"] = len(subdomains)
            _log(discovery_id, f"Found: {sub}")

        _log(discovery_id, f"Subfinder complete — {len(subdomains)} subdomains found")

        # Always probe the root domain itself
        if domain not in subdomains:
            subdomains.insert(0, domain)

        # ── Step 2: httpx-toolkit (batch streaming) ───────────────────
        disc["currentStep"] = "Running httpx-toolkit"
        _log(discovery_id, f"Running httpx-toolkit on {len(subdomains)} hosts (-threads 200)")

        # Track which subdomains were probed (for offline records)
        probed: set[str] = set()

        async for result in stream_probe_hosts(subdomains):
            if disc.get("status") not in ACTIVE_STATUSES:
                break

            # httpx-toolkit `input` field = original subdomain from stdin
            sub = result.get("input") or result.get("url", "")
            # Strip protocol/path from input if present
            if sub.startswith("http"):
                from urllib.parse import urlparse
                sub = urlparse(sub).hostname or sub
            probed.add(sub)

            asset: dict = {
                "assetId":      make_asset_id(),
                "discoveryId":  discovery_id,
                "domain":       domain,
                "subdomain":    sub,
                "url":          result.get("url") or f"https://{sub}",
                "alive":        True,
                "statusCode":   result.get("statusCode"),
                "title":        result.get("title"),
                "server":       result.get("server"),
                "ip":           result.get("ip"),
                "contentType":  result.get("contentType"),
                "technologies": result.get("technologies") or [],
                "createdAt":    _now_iso(),
            }
            ASSETS[discovery_id].append(asset)
            disc["liveAssets"] = disc.get("liveAssets", 0) + 1

            code = result.get("statusCode", "?")
            _log(discovery_id, f"{sub} → {code}")

        # Record offline subdomains (those subfinder found but httpx-toolkit didn't return)
        for sub in subdomains:
            if sub not in probed:
                asset = {
                    "assetId":      make_asset_id(),
                    "discoveryId":  discovery_id,
                    "domain":       domain,
                    "subdomain":    sub,
                    "url":          f"http://{sub}",
                    "alive":        False,
                    "statusCode":   None,
                    "title":        None,
                    "server":       None,
                    "ip":           None,
                    "contentType":  None,
                    "technologies": [],
                    "createdAt":    _now_iso(),
                }
                ASSETS[discovery_id].append(asset)
                _log(discovery_id, f"{sub} → offline")

        # ── Complete ──────────────────────────────────────────────────
        disc["status"] = "completed"
        disc["currentStep"] = "Completed"
        disc["completedAt"] = _now_iso()
        live  = disc.get("liveAssets", 0)
        total = len(subdomains)
        _log(discovery_id, f"Discovery complete — {live}/{total} live assets")

    except asyncio.CancelledError:
        disc["status"] = "cancelled"
        disc["currentStep"] = "Cancelled"
        _log(discovery_id, "Discovery cancelled by user")

    except Exception as exc:
        logger.error(f"Discovery {discovery_id} failed: {exc}")
        disc["status"] = "failed"
        disc["error"] = str(exc)
        disc["currentStep"] = "Failed"
        _log(discovery_id, f"Error: {exc}")

    finally:
        DISC_TASKS.pop(discovery_id, None)
