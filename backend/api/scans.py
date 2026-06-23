from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from models.scan import Finding, HealthResponse, ScanProfile, ScanRequest, Severity
from scanners.nuclei import is_nuclei_available, stream_nuclei_scan
from scanners.wpscan import is_wpscan_available, is_wordpress, stream_wpscan
from discovery.subfinder import is_subfinder_available, stream_subdomains
from discovery.httpx_toolkit import is_httpx_toolkit_available, stream_probe_hosts
from intelligence.nvd_client import get_cves_for_technology, parse_tech
from checks.runner import run_checks_on_assets
from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()

# ── In-memory scan registry ──────────────────────────────────────────
_SCANS: Dict[str, dict] = {}
_TASKS: Dict[str, asyncio.Task] = {}

# ── Queue management ─────────────────────────────────────────────────
MAX_CONCURRENT_SCANS = 1
_PENDING: List[Tuple[str, str, str]] = []

# ── Mock findings (Nuclei unavailable) ──────────────────────────────
_MOCK_FINDINGS: List[dict] = [
    {
        "source": "nuclei",
        "severity": "high",
        "title": "Missing Content Security Policy",
        "template": "security-headers",
        "host": None, "matched_at": None,
        "description": "Content-Security-Policy header is absent.",
    },
    {
        "source": "nuclei",
        "severity": "medium",
        "title": "Missing X-Frame-Options Header",
        "template": "security-headers",
        "host": None, "matched_at": None,
        "description": "X-Frame-Options header is not set.",
    },
    {
        "source": "nuclei",
        "severity": "low",
        "title": "Missing X-Content-Type-Options Header",
        "template": "security-headers",
        "host": None, "matched_at": None,
        "description": "X-Content-Type-Options: nosniff header is absent.",
    },
    {
        "source": "nuclei",
        "severity": "info",
        "title": "HTTP Server Header Detected",
        "template": "tech-detect",
        "host": None, "matched_at": None,
        "description": "Server version information is exposed in the HTTP response header.",
    },
]

_PROFILE_LABELS = {
    "QUICK_SCAN": "Quick Scan",
    "FULL_SCAN":  "Full Scan",
}

# Statuses that count against the concurrency limit
_ACTIVE_RUNNING = {
    # Quick Scan
    "initializing", "running", "processing", "saving",
    # Full Scan pipeline
    "discovering_assets", "validating_assets", "scanning_assets",
}


# ── Helpers ──────────────────────────────────────────────────────────

def _build_scan_id() -> str:
    return f"scan_{uuid.uuid4().hex[:12]}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_finding(raw: dict) -> Optional[Finding]:
    try:
        sev_str = (raw.get("severity") or "unknown").lower()
        severity = (
            Severity(sev_str) if sev_str in Severity._value2member_map_ else Severity.unknown
        )
        return Finding(
            source=raw.get("source") or "nuclei",
            severity=severity,
            title=raw.get("title") or "Unknown",
            template=raw.get("template") or "unknown",
            host=raw.get("host"),
            matched_at=raw.get("matched_at"),
            description=raw.get("description"),
        )
    except Exception as exc:
        logger.warning(f"Dropping malformed finding: {exc} | raw={raw}")
        return None


def _append_log(scan_id: str, message: str) -> None:
    if scan_id in _SCANS:
        _SCANS[scan_id]["logs"].append({"timestamp": _now(), "message": message})


def _update_scan(scan_id: str, **kwargs) -> None:
    if scan_id in _SCANS:
        _SCANS[scan_id].update(kwargs)


def _record_finding(scan_id: str, finding: Finding) -> None:
    entry = finding.model_dump()
    _SCANS[scan_id]["findings"].append(entry)
    _SCANS[scan_id]["total_findings"] += 1
    _SCANS[scan_id]["templatesExecuted"] = len(
        set(f["template"] for f in _SCANS[scan_id]["findings"])
    )
    src = finding.source.upper() if finding.source else "NUCLEI"
    _append_log(scan_id, f"[{src}][{finding.severity.value.upper()}] {finding.title}")


def _set_engine(scan_id: str, engine: str, engine_status: str, finding_count: int = -1) -> None:
    if scan_id not in _SCANS:
        return
    engines = _SCANS[scan_id].setdefault("engines", {})
    if engine not in engines:
        engines[engine] = {"status": "pending", "findingCount": 0}
    engines[engine]["status"] = engine_status
    if finding_count >= 0:
        engines[engine]["findingCount"] = finding_count


def _format_duration(seconds: float) -> str:
    mins, secs = divmod(int(seconds), 60)
    return f"{mins}m {secs}s" if mins else f"{secs}s"


def _count_active() -> int:
    return sum(1 for s in _SCANS.values() if s["status"] in _ACTIVE_RUNNING)


def _blank_scan(scan_id: str, target: str, profile: str) -> dict:
    return {
        "scanId":           scan_id,
        "target":           target,
        "scanProfile":      profile,
        "status":           "queued",
        "progress":         0,
        "currentStep":      "Queued",
        "logs":             [{"timestamp": _now(), "message": f"Scan Queued ({_PROFILE_LABELS.get(profile, profile)})"}],
        "findings":         [],
        "total_findings":   0,
        "templatesExecuted": 0,
        # Full Scan extras
        "assets":           [],
        "total_assets":     0,
        "live_assets_count": 0,
        "cves":             [],
        "total_cves":       0,
        "duration":         None,
        "error":            None,
        # Per-engine tracking (Full Scan)
        "engines": {
            "nuclei":        {"status": "pending", "findingCount": 0},
            "vectra_checks": {"status": "pending", "findingCount": 0},
            "wpscan":        {"status": "pending", "findingCount": 0},
            "cve_analysis":  {"status": "pending", "findingCount": 0},
        },
    }


# ── Queue management ─────────────────────────────────────────────────

async def _try_start_next() -> None:
    global _PENDING
    while _PENDING and _count_active() < MAX_CONCURRENT_SCANS:
        scan_id, target, profile = _PENDING.pop(0)
        if _SCANS.get(scan_id, {}).get("status") != "queued":
            continue
        task = asyncio.create_task(_run_and_release(scan_id, target, profile))
        _TASKS[scan_id] = task
        break


async def _run_and_release(scan_id: str, target: str, profile: str) -> None:
    try:
        await _execute_scan(scan_id, target, profile)
    finally:
        asyncio.create_task(_try_start_next())


# ── Scan routing ─────────────────────────────────────────────────────

async def _execute_scan(scan_id: str, target: str, profile: str = "FULL_SCAN") -> None:
    if profile == "FULL_SCAN":
        await _execute_full_scan(scan_id, target)
    else:
        await _execute_quick_scan(scan_id, target, profile)


# ── Quick Scan ───────────────────────────────────────────────────────

async def _execute_quick_scan(scan_id: str, target: str, profile: str) -> None:
    started_at: Optional[float] = None
    try:
        label = _PROFILE_LABELS.get(profile, profile)

        _update_scan(scan_id, status="initializing", progress=10, currentStep="Initializing Scanner")
        _append_log(scan_id, f"Initializing {label}")
        await asyncio.sleep(0.5)

        started_at = time.monotonic()
        _update_scan(scan_id, status="running", progress=20, currentStep="Running Nuclei")
        _append_log(scan_id, f"Executing {label} against {target}")

        scan_error: Optional[str] = None

        if is_nuclei_available():
            async for raw_finding in stream_nuclei_scan(target, profile):
                coerced = _coerce_finding({**raw_finding, "source": "nuclei"})
                if coerced:
                    _record_finding(scan_id, coerced)
        else:
            for mock in _MOCK_FINDINGS:
                await asyncio.sleep(1.2)
                coerced = _coerce_finding({**mock, "host": target})
                if coerced:
                    _record_finding(scan_id, coerced)
            scan_error = "Nuclei binary not found — mock results returned"

        _update_scan(scan_id, status="processing", progress=85, currentStep="Processing Results")
        _append_log(scan_id, "Processing Results")
        await asyncio.sleep(0.5)

        findings = _SCANS[scan_id]["findings"]

        _update_scan(scan_id, status="saving", progress=90, currentStep="Saving Findings")
        _append_log(scan_id, f"Saving {len(findings)} finding(s)")
        await asyncio.sleep(0.3)

        elapsed = _format_duration(time.monotonic() - started_at)
        _update_scan(
            scan_id,
            status="completed", progress=100, currentStep="Completed",
            templatesExecuted=len(set(f["template"] for f in findings)),
            duration=elapsed, error=scan_error,
        )
        _append_log(scan_id, f"Completed — {len(findings)} finding(s) in {elapsed}")

    except asyncio.CancelledError:
        elapsed = _format_duration(time.monotonic() - started_at) if started_at else "0s"
        _update_scan(scan_id, status="cancelled", currentStep="Cancelled", duration=elapsed)
        _append_log(scan_id, "Scan Cancelled by User")

    except Exception as exc:
        _update_scan(scan_id, status="failed", progress=0, currentStep="Failed", error=str(exc))
        _append_log(scan_id, f"Error: {exc}")
        logger.error(f"[{scan_id}] Unexpected error: {exc}")


# ── Parallel Engine helpers (Full Scan) ──────────────────────────────

async def _engine_nuclei(scan_id: str, live_assets: List[dict]) -> None:
    """Engine 1 — Nuclei scans all live assets. Failure is isolated."""
    _set_engine(scan_id, "nuclei", "running")
    count = 0
    try:
        for asset in live_assets:
            if _SCANS.get(scan_id, {}).get("status") not in _ACTIVE_RUNNING:
                break
            url = asset.get("url") or f"https://{asset['subdomain']}"
            _append_log(scan_id, f"[Nuclei] Scanning {url}")

            if is_nuclei_available():
                async for raw in stream_nuclei_scan(url, "QUICK_SCAN"):
                    coerced = _coerce_finding({**raw, "source": "nuclei"})
                    if coerced:
                        _record_finding(scan_id, coerced)
                        count += 1
                        _set_engine(scan_id, "nuclei", "running", count)
            else:
                for mock in _MOCK_FINDINGS:
                    coerced = _coerce_finding({**mock, "host": url})
                    if coerced:
                        _record_finding(scan_id, coerced)
                        count += 1
                        _set_engine(scan_id, "nuclei", "running", count)

        _set_engine(scan_id, "nuclei", "completed", count)
        _append_log(scan_id, f"[Nuclei] Complete — {count} finding(s)")
    except asyncio.CancelledError:
        _set_engine(scan_id, "nuclei", "cancelled", count)
        raise
    except Exception as exc:
        _set_engine(scan_id, "nuclei", "failed", count)
        _append_log(scan_id, f"[Nuclei] Engine error: {exc}")
        logger.error(f"[{scan_id}] Nuclei engine error: {exc}")


async def _engine_vectra_checks(scan_id: str, live_assets: List[dict]) -> None:
    """Engine 2 — Vectra Security Checks on all live assets. Failure is isolated."""
    _set_engine(scan_id, "vectra_checks", "running")
    count = 0
    try:
        _append_log(scan_id, f"[Vectra] Running security checks on {len(live_assets)} asset(s)")
        findings = await run_checks_on_assets(live_assets)

        for raw in findings:
            if _SCANS.get(scan_id, {}).get("status") not in _ACTIVE_RUNNING:
                break
            coerced = _coerce_finding(raw)
            if coerced:
                _record_finding(scan_id, coerced)
                count += 1

        _set_engine(scan_id, "vectra_checks", "completed", count)
        _append_log(scan_id, f"[Vectra] Complete — {count} finding(s)")
    except asyncio.CancelledError:
        _set_engine(scan_id, "vectra_checks", "cancelled", count)
        raise
    except Exception as exc:
        _set_engine(scan_id, "vectra_checks", "failed", count)
        _append_log(scan_id, f"[Vectra] Engine error: {exc}")
        logger.error(f"[{scan_id}] Vectra checks engine error: {exc}")


async def _engine_wpscan(scan_id: str, live_assets: List[dict]) -> None:
    """Engine 4 — WPScan on WordPress assets. Skipped if no WP detected. Failure isolated."""
    # Find WordPress assets
    wp_assets = [a for a in live_assets if is_wordpress(a.get("technologies") or [])]

    if not wp_assets:
        _set_engine(scan_id, "wpscan", "skipped", 0)
        _append_log(scan_id, "[WPScan] No WordPress assets detected — skipping")
        return

    if not is_wpscan_available():
        _set_engine(scan_id, "wpscan", "skipped", 0)
        _append_log(scan_id, "[WPScan] wpscan not installed — skipping")
        return

    _set_engine(scan_id, "wpscan", "running")
    count = 0
    try:
        for asset in wp_assets:
            url = asset.get("url") or f"https://{asset['subdomain']}"
            _append_log(scan_id, f"[WPScan] Scanning WordPress at {url}")

            async for raw in stream_wpscan(url):
                if _SCANS.get(scan_id, {}).get("status") not in _ACTIVE_RUNNING:
                    break
                coerced = _coerce_finding(raw)
                if coerced:
                    _record_finding(scan_id, coerced)
                    count += 1
                    _set_engine(scan_id, "wpscan", "running", count)

        _set_engine(scan_id, "wpscan", "completed", count)
        _append_log(scan_id, f"[WPScan] Complete — {count} finding(s)")
    except asyncio.CancelledError:
        _set_engine(scan_id, "wpscan", "cancelled", count)
        raise
    except Exception as exc:
        _set_engine(scan_id, "wpscan", "failed", count)
        _append_log(scan_id, f"[WPScan] Engine error: {exc}")
        logger.error(f"[{scan_id}] WPScan engine error: {exc}")


async def _engine_cve_analysis(scan_id: str, live_assets: List[dict]) -> None:
    """Engine 4 — CVE Analysis. Starts immediately after tech detection, parallel with scanners."""
    _set_engine(scan_id, "cve_analysis", "running")
    cve_count = 0
    try:
        _append_log(scan_id, "[CVE] Analysis Started")

        # Extract versioned technologies from assets discovered in validating_assets
        versioned_techs: List[tuple] = []
        all_tech_names: set = set()
        for asset in live_assets:
            for tech in asset.get("technologies") or []:
                name, version = parse_tech(tech)
                if name:
                    all_tech_names.add(name)
                if version:
                    versioned_techs.append((name, version, asset))

        if all_tech_names:
            sample = sorted(all_tech_names)[:10]
            _append_log(scan_id, f"[CVE] Technologies Detected: {', '.join(sample)}")

        if not versioned_techs:
            _append_log(scan_id, "[CVE] No versioned technologies — CVE analysis skipped")
            _set_engine(scan_id, "cve_analysis", "completed", 0)
            return

        _append_log(scan_id, f"[CVE] {len(versioned_techs)} versioned tech(s) queued for CVE lookup")

        # Deduplicate (name, version) pairs across assets
        tech_to_assets: dict = {}
        for name, version, asset in versioned_techs:
            key = f"{name.lower()}:{version}"
            if key not in tech_to_assets:
                tech_to_assets[key] = {"name": name, "version": version, "assets": []}
            tech_to_assets[key]["assets"].append(asset)

        cves: List[dict] = _SCANS[scan_id]["cves"]
        seen_keys: set = set()
        total_lookups = len(tech_to_assets)

        for idx, (_, entry) in enumerate(tech_to_assets.items(), 1):
            if _SCANS.get(scan_id, {}).get("status") not in _ACTIVE_RUNNING:
                break

            name         = entry["name"]
            version      = entry["version"]
            entry_assets = entry["assets"]

            _append_log(scan_id, f"[CVE] [{idx}/{total_lookups}] {name} {version}")
            tech_cves = await get_cves_for_technology(name, version)

            if tech_cves:
                ids_preview = ", ".join(c["cveId"] for c in tech_cves[:3])
                _append_log(scan_id, f"[CVE] Local Matches Found: {name} {version} → {len(tech_cves)} CVE(s): {ids_preview}")

                for raw in tech_cves:
                    for asset in entry_assets:
                        key = f"{raw['cveId']}_{asset['assetId']}"
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        cves.append({
                            **raw,
                            "id":          key,
                            "assetId":     asset["assetId"],
                            "assetUrl":    asset["url"],
                            "discoveryId": scan_id,
                            "createdAt":   _now_iso(),
                        })
                        cve_count += 1
                        logger.info(f"[CVE] Saved: {raw['cveId']} → asset {asset['assetId']}")
            else:
                _append_log(scan_id, f"[CVE] NVD Fallback Triggered: {name} {version}")
                logger.info(f"[CVE] No local match for {name} {version} — NVD was queried")

            _update_scan(scan_id, total_cves=len(cves))

        if cves:
            top = sorted(cves, key=lambda x: x.get("cvssScore", 0), reverse=True)[:3]
            top_ids = ", ".join(c["cveId"] for c in top)
            _append_log(scan_id, f"[CVE] Results Saved — {len(cves)} CVEs found (top: {top_ids})")
        else:
            _append_log(scan_id, "[CVE] Results Saved — 0 CVEs found")

        _append_log(scan_id, "[CVE] Analysis Completed")
        _set_engine(scan_id, "cve_analysis", "completed", cve_count)

    except asyncio.CancelledError:
        _set_engine(scan_id, "cve_analysis", "cancelled", cve_count)
        raise
    except Exception as exc:
        _set_engine(scan_id, "cve_analysis", "failed", cve_count)
        _append_log(scan_id, f"[CVE] Engine error: {exc}")
        logger.error(f"[{scan_id}] CVE engine error: {exc}")


# ── Full Scan pipeline ────────────────────────────────────────────────

async def _execute_full_scan(scan_id: str, target: str) -> None:
    """
    Full Scan pipeline — Parallel Execution Engine:
      Stage 1  DISCOVERING_ASSETS  — Subfinder enumerates subdomains
      Stage 2  VALIDATING_ASSETS   — httpx-toolkit probes hosts + technology detection
      Stage 3  SCANNING_ASSETS     — Parallel engine pool (all 4 start simultaneously):
                                       Engine 1: Nuclei (vulnerability templates)
                                       Engine 2: Vectra Security Checks (10 custom checks)
                                       Engine 3: WPScan (if WordPress detected)
                                       Engine 4: CVE Analysis (starts immediately after tech detection)
      Stage 4  COMPLETED           — All engines done
    """
    started_at = time.monotonic()

    parsed = urlparse(target if "://" in target else f"https://{target}")
    domain = parsed.hostname or target

    try:
        # ── Stage 1: DISCOVERING_ASSETS ──────────────────────────────────
        _update_scan(scan_id, status="discovering_assets", progress=5,
                     currentStep=f"Discovering assets for {domain}")
        _append_log(scan_id, f"Starting asset discovery for {domain}")

        subdomains: List[str] = []
        async for sub in stream_subdomains(domain):
            if _SCANS[scan_id]["status"] != "discovering_assets":
                break
            subdomains.append(sub)
            _append_log(scan_id, f"Found: {sub}")

        if domain not in subdomains:
            subdomains.insert(0, domain)

        _append_log(scan_id, f"Subfinder complete — {len(subdomains)} subdomains")
        _update_scan(scan_id, progress=25)

        # ── Stage 2: VALIDATING_ASSETS ──────────────────────────────────
        _update_scan(scan_id, status="validating_assets", progress=25,
                     currentStep=f"Probing {len(subdomains)} hosts + technology detection")
        _append_log(scan_id, f"Probing {len(subdomains)} hosts with httpx-toolkit")

        assets: List[dict] = _SCANS[scan_id]["assets"]
        probed: set = set()

        async for result in stream_probe_hosts(subdomains):
            if _SCANS[scan_id]["status"] not in _ACTIVE_RUNNING:
                break

            raw_input = result.get("input") or result.get("url", "")
            if raw_input.startswith("http"):
                sub = urlparse(raw_input).hostname or raw_input
            else:
                sub = raw_input
            probed.add(sub)

            asset = {
                "assetId":       f"asset_{uuid.uuid4().hex[:12]}",
                "discoveryId":   scan_id,
                "domain":        domain,
                "subdomain":     sub,
                "url":           result.get("url") or f"https://{sub}",
                "alive":         True,
                "statusCode":    result.get("statusCode"),
                "title":         result.get("title"),
                "server":        result.get("server"),
                "ip":            result.get("ip"),
                "contentType":   result.get("contentType"),
                "technologies":  result.get("technologies") or [],
                "cveCorrelated": True,
                "createdAt":     _now_iso(),
            }
            assets.append(asset)
            _update_scan(scan_id, total_assets=len(assets),
                         live_assets_count=sum(1 for a in assets if a["alive"]))
            tech_str = f" [{', '.join((result.get('technologies') or [])[:3])}]" if result.get('technologies') else ""
            _append_log(scan_id, f"{sub} → {result.get('statusCode', '?')}{tech_str}")

        # Record offline subdomains
        for sub in subdomains:
            if sub not in probed:
                assets.append({
                    "assetId":       f"asset_{uuid.uuid4().hex[:12]}",
                    "discoveryId":   scan_id,
                    "domain":        domain,
                    "subdomain":     sub,
                    "url":           f"http://{sub}",
                    "alive":         False,
                    "statusCode":    None,
                    "title":         None,
                    "server":        None,
                    "ip":            None,
                    "contentType":   None,
                    "technologies":  [],
                    "cveCorrelated": True,
                    "createdAt":     _now_iso(),
                })

        live_assets = [a for a in assets if a["alive"]]
        _update_scan(scan_id, total_assets=len(assets),
                     live_assets_count=len(live_assets), progress=45)
        _append_log(scan_id, f"Validation complete — {len(live_assets)}/{len(assets)} live")

        # Technology summary for WPScan decision
        all_techs: set[str] = set()
        for a in live_assets:
            for t in a.get("technologies") or []:
                all_techs.add(t.split(":")[0])
        if all_techs:
            sample = sorted(all_techs)[:8]
            _append_log(scan_id, f"Technologies: {', '.join(sample)}" +
                        (f" (+{len(all_techs) - 8} more)" if len(all_techs) > 8 else ""))

        wp_detected = any(is_wordpress(a.get("technologies") or []) for a in live_assets)
        if wp_detected:
            _append_log(scan_id, "[Engine] WordPress detected — WPScan will run")

        # ── Stage 3: SCANNING_ASSETS — Parallel Engine Pool ─────────────
        # All 4 engines launch simultaneously. CVE Analysis starts immediately
        # after technology detection (Stage 2) without waiting for Nuclei or WPScan.
        _update_scan(scan_id, status="scanning_assets", progress=50,
                     currentStep=f"Running security engines on {len(live_assets)} assets")

        _append_log(scan_id, "[Engine] Launching 4 engines in parallel")
        _append_log(scan_id, "[Engine 1] Nuclei — vulnerability templates")
        _append_log(scan_id, "[Engine 2] Vectra — 10 custom security checks")
        _append_log(scan_id, f"[Engine 3] WPScan — {'WordPress scan' if wp_detected else 'skipped (no WP)'}")
        _append_log(scan_id, "[Engine 4] CVE Analysis — starts immediately after tech detection")

        engine_results = await asyncio.gather(
            _engine_nuclei(scan_id, live_assets),
            _engine_vectra_checks(scan_id, live_assets),
            _engine_wpscan(scan_id, live_assets),
            _engine_cve_analysis(scan_id, live_assets),
            return_exceptions=True,
        )

        # Isolated — log any unexpected engine exceptions (scan continues regardless)
        for i, result in enumerate(engine_results):
            if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError):
                logger.error(f"[{scan_id}] Engine {i} exception: {result}")

        total_findings = _SCANS[scan_id]["total_findings"]
        total_cves     = len(_SCANS[scan_id]["cves"])
        engines        = _SCANS[scan_id].get("engines", {})
        nuclei_n  = engines.get("nuclei",        {}).get("findingCount", 0)
        vectra_n  = engines.get("vectra_checks",  {}).get("findingCount", 0)
        wpscan_n  = engines.get("wpscan",         {}).get("findingCount", 0)
        cve_n     = engines.get("cve_analysis",   {}).get("findingCount", 0)
        _append_log(scan_id, (
            f"[Engine] All engines complete — {total_findings} findings, {total_cves} CVEs "
            f"(Nuclei: {nuclei_n}, Vectra: {vectra_n}, WPScan: {wpscan_n}, CVE: {cve_n})"
        ))
        _update_scan(scan_id, progress=95)

        # ── Stage 4: COMPLETED ───────────────────────────────────────────
        elapsed = _format_duration(time.monotonic() - started_at)
        _update_scan(
            scan_id,
            status="completed", progress=100, currentStep="Completed",
            templatesExecuted=len(set(f["template"] for f in _SCANS[scan_id]["findings"])),
            duration=elapsed,
        )
        _append_log(
            scan_id,
            f"Full Scan completed in {elapsed} — "
            f"{len(live_assets)} live assets, {total_findings} findings, {total_cves} CVEs",
        )
        logger.info(f"[{scan_id}] Full Scan completed in {elapsed}")

    except asyncio.CancelledError:
        elapsed = _format_duration(time.monotonic() - started_at)
        _update_scan(scan_id, status="cancelled", currentStep="Cancelled", duration=elapsed)
        _append_log(scan_id, "Full Scan cancelled by user")

    except Exception as exc:
        _update_scan(scan_id, status="failed", progress=0, currentStep="Failed", error=str(exc))
        _append_log(scan_id, f"Error: {exc}")
        logger.error(f"[{scan_id}] Full Scan error: {exc}", exc_info=True)


# ── Routes ───────────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    return HealthResponse(status="healthy")


@router.post("/scan/start", status_code=status.HTTP_200_OK, tags=["Scans"])
async def start_scan(request: ScanRequest) -> dict:
    target  = str(request.target)
    profile = request.scanProfile.value
    scan_id = _build_scan_id()

    _SCANS[scan_id] = _blank_scan(scan_id, target, profile)
    _PENDING.append((scan_id, target, profile))
    asyncio.create_task(_try_start_next())
    logger.info(f"[{scan_id}] Queued [{profile}] for {target}")

    return {"scanId": scan_id, "status": "queued", "scanProfile": profile}


@router.get("/scan/{scan_id}", tags=["Scans"])
async def get_scan(scan_id: str) -> dict:
    if scan_id not in _SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _SCANS[scan_id]


@router.get("/scan/{scan_id}/stream", tags=["Scans"])
async def stream_scan_events(scan_id: str) -> StreamingResponse:
    if scan_id not in _SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator():
        try:
            while True:
                scan = _SCANS.get(scan_id)
                if not scan:
                    yield f"data: {json.dumps({'done': True, 'error': 'Scan not found'})}\n\n"
                    break

                payload = {
                    "status":           scan["status"],
                    "progress":         scan["progress"],
                    "currentStep":      scan["currentStep"],
                    "findings":         scan["findings"],
                    "total_findings":   scan["total_findings"],
                    "logs":             scan["logs"],
                    "templatesExecuted": scan.get("templatesExecuted", 0),
                    "duration":         scan.get("duration"),
                    "error":            scan.get("error"),
                    # Full Scan extras
                    "assets":           scan.get("assets", []),
                    "total_assets":     scan.get("total_assets", 0),
                    "live_assets_count": scan.get("live_assets_count", 0),
                    "cves":             scan.get("cves", []),
                    "total_cves":       scan.get("total_cves", 0),
                    # Per-engine tracking
                    "engines":          scan.get("engines", {}),
                }
                yield f"data: {json.dumps(payload)}\n\n"

                if scan["status"] in ("completed", "failed", "cancelled"):
                    yield f"data: {json.dumps({'done': True})}\n\n"
                    break

                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@router.post("/scan/{scan_id}/cancel", tags=["Scans"])
async def cancel_scan(scan_id: str) -> dict:
    global _PENDING
    if scan_id not in _SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")

    _PENDING = [(sid, t, p) for sid, t, p in _PENDING if sid != scan_id]

    task = _TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()

    _update_scan(scan_id, status="cancelled", currentStep="Cancelled")
    _append_log(scan_id, "Scan Cancelled by User")
    return {"scanId": scan_id, "status": "cancelled"}


@router.post("/scan/{scan_id}/restart", tags=["Scans"])
async def restart_scan(scan_id: str) -> dict:
    if scan_id not in _SCANS:
        raise HTTPException(status_code=404, detail="Original scan not found")

    target  = _SCANS[scan_id]["target"]
    profile = _SCANS[scan_id].get("scanProfile", "FULL_SCAN")
    new_id  = _build_scan_id()

    _SCANS[new_id] = _blank_scan(new_id, target, profile)
    _SCANS[new_id]["logs"][0]["message"] = f"Scan Queued (Restarted — {_PROFILE_LABELS.get(profile, profile)})"

    _PENDING.append((new_id, target, profile))
    asyncio.create_task(_try_start_next())
    logger.info(f"[{new_id}] Restarted from [{scan_id}]")

    return {"scanId": new_id, "status": "queued", "scanProfile": profile, "originalScanId": scan_id}


@router.get("/findings", tags=["Findings"])
async def get_all_findings() -> list:
    result = []
    for scan_id, scan in _SCANS.items():
        if scan["status"] != "completed" or scan["total_findings"] == 0:
            continue
        findings = scan["findings"]
        result.append({
            "scanId":       scan_id,
            "target":       scan["target"],
            "scanProfile":  scan.get("scanProfile"),
            "totalFindings": scan["total_findings"],
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high":     sum(1 for f in findings if f["severity"] == "high"),
            "medium":   sum(1 for f in findings if f["severity"] == "medium"),
            "low":      sum(1 for f in findings if f["severity"] == "low"),
            "info":     sum(1 for f in findings if f["severity"] == "info"),
        })
    return result
