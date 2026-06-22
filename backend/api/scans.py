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
from discovery.subfinder import is_subfinder_available, stream_subdomains
from discovery.httpx_toolkit import is_httpx_toolkit_available, stream_probe_hosts
from intelligence.nvd_client import get_cves_for_technology, parse_tech
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
        "severity": "high",
        "title": "Missing Content Security Policy",
        "template": "security-headers",
        "host": None, "matched_at": None,
        "description": "Content-Security-Policy header is absent.",
    },
    {
        "severity": "medium",
        "title": "Missing X-Frame-Options Header",
        "template": "security-headers",
        "host": None, "matched_at": None,
        "description": "X-Frame-Options header is not set.",
    },
    {
        "severity": "low",
        "title": "Missing X-Content-Type-Options Header",
        "template": "security-headers",
        "host": None, "matched_at": None,
        "description": "X-Content-Type-Options: nosniff header is absent.",
    },
    {
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
    "detecting_technologies", "cve_analysis",
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
    _append_log(scan_id, f"[{finding.severity.value.upper()}] {finding.title}")


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
                coerced = _coerce_finding(raw_finding)
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


# ── Full Scan pipeline ────────────────────────────────────────────────

async def _execute_full_scan(scan_id: str, target: str) -> None:
    """
    Full Scan pipeline:
      DISCOVERING_ASSETS  → Subfinder enumerates subdomains
      VALIDATING_ASSETS   → httpx-toolkit probes hosts, detects technologies
      SCANNING_ASSETS     → Nuclei scans all live assets
      DETECTING_TECHNOLOGIES → Summarise tech stack (already done in stage 2)
      CVE_ANALYSIS        → NVD CVE lookup per versioned technology
      COMPLETED
    """
    started_at = time.monotonic()

    # Extract bare domain from target URL
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

        # Always include the root domain
        if domain not in subdomains:
            subdomains.insert(0, domain)

        _append_log(scan_id, f"Subfinder complete — {len(subdomains)} subdomains")
        _update_scan(scan_id, progress=25)

        # ── Stage 2: VALIDATING_ASSETS ──────────────────────────────────
        _update_scan(scan_id, status="validating_assets", progress=25,
                     currentStep=f"Probing {len(subdomains)} hosts")
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
                "cveCorrelated": True,   # Full Scan handles CVE correlation internally
                "createdAt":     _now_iso(),
            }
            assets.append(asset)
            _update_scan(scan_id, total_assets=len(assets),
                         live_assets_count=sum(1 for a in assets if a["alive"]))
            _append_log(scan_id, f"{sub} → {result.get('statusCode', '?')}")

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

        # ── Stage 3: SCANNING_ASSETS ─────────────────────────────────────
        _update_scan(scan_id, status="scanning_assets", progress=45,
                     currentStep=f"Scanning {len(live_assets)} live assets")
        _append_log(scan_id, f"Running Nuclei against {len(live_assets)} live assets")

        for idx, asset in enumerate(live_assets):
            if _SCANS[scan_id]["status"] not in _ACTIVE_RUNNING:
                break

            url = asset["url"] or f"https://{asset['subdomain']}"
            _append_log(scan_id, f"[{idx + 1}/{len(live_assets)}] Scanning {url}")

            if is_nuclei_available():
                async for raw_finding in stream_nuclei_scan(url, "QUICK_SCAN"):
                    coerced = _coerce_finding(raw_finding)
                    if coerced:
                        _record_finding(scan_id, coerced)
            else:
                for mock in _MOCK_FINDINGS:
                    coerced = _coerce_finding({**mock, "host": url})
                    if coerced:
                        _record_finding(scan_id, coerced)

            # Proportional progress through scanning stage (45 → 70)
            pct = 45 + int((idx + 1) / max(len(live_assets), 1) * 25)
            _update_scan(scan_id, progress=pct)

        total_findings = _SCANS[scan_id]["total_findings"]
        _append_log(scan_id, f"Scanning complete — {total_findings} findings")

        # ── Stage 4: DETECTING_TECHNOLOGIES ─────────────────────────────
        _update_scan(scan_id, status="detecting_technologies", progress=72,
                     currentStep="Technology Detection")

        # Separate versioned (name:version) from unversioned techs
        all_tech_names: set = set()
        versioned_techs: List[tuple] = []  # (name, version, asset)

        for asset in live_assets:
            for tech in asset.get("technologies") or []:
                name, version = parse_tech(tech)
                if name:
                    all_tech_names.add(name)
                if version:
                    versioned_techs.append((name, version, asset))
                    logger.info(f"[CVE] Version detected: {name} {version} on {asset.get('subdomain', asset.get('url'))}")
                    _append_log(scan_id, f"[CVE] Version: {name} {version} on {asset.get('subdomain', asset.get('url', ''))}")
                else:
                    logger.debug(f"[CVE] No version for: {name}")

        if all_tech_names:
            _append_log(scan_id, f"[CVE] Detected {len(all_tech_names)} technologies across {len(live_assets)} live assets")
            sample = sorted(all_tech_names)[:10]
            _append_log(scan_id, f"[CVE] Tech stack: {', '.join(sample)}" +
                        (f" (+{len(all_tech_names) - 10} more)" if len(all_tech_names) > 10 else ""))
        else:
            _append_log(scan_id, "[CVE] No technologies detected on live assets")

        if versioned_techs:
            _append_log(scan_id, f"[CVE] {len(versioned_techs)} versioned technologies ready for CVE lookup")
        else:
            _append_log(scan_id, "[CVE] No versioned technologies found — CVE correlation will be skipped")

        await asyncio.sleep(0.3)

        # ── Stage 5: CVE_ANALYSIS ────────────────────────────────────────
        _update_scan(scan_id, status="cve_analysis", progress=80,
                     currentStep="CVE Correlation")
        _append_log(scan_id, "[CVE] Starting CVE correlation via NVD API")
        logger.info(f"[CVE] Starting CVE analysis for scan {scan_id} — {len(versioned_techs)} versioned technologies")

        cves: List[dict] = _SCANS[scan_id]["cves"]
        seen_keys: set = set()  # deduplicate (cveId, assetId) pairs

        # Deduplicate (name, version) pairs across assets to minimise NVD API calls
        seen_lookups: set = set()
        # Map (name, version) → list of assets that have this tech
        tech_to_assets: dict = {}
        for name, version, asset in versioned_techs:
            key = f"{name.lower()}:{version}"
            if key not in tech_to_assets:
                tech_to_assets[key] = {"name": name, "version": version, "assets": []}
            tech_to_assets[key]["assets"].append(asset)

        total_lookups = len(tech_to_assets)
        for idx, (lookup_key, entry) in enumerate(tech_to_assets.items(), 1):
            if _SCANS[scan_id]["status"] not in _ACTIVE_RUNNING:
                break

            name    = entry["name"]
            version = entry["version"]
            assets  = entry["assets"]

            _append_log(scan_id, f"[CVE] [{idx}/{total_lookups}] Searching NVD: {name} {version}")
            logger.info(f"[CVE] [{idx}/{total_lookups}] NVD lookup: {name} {version}")

            tech_cves = await get_cves_for_technology(name, version)

            if tech_cves:
                ids_preview = ", ".join(c["cveId"] for c in tech_cves[:3])
                _append_log(scan_id, f"[CVE] {name} {version} → {len(tech_cves)} CVE(s): {ids_preview}{'...' if len(tech_cves) > 3 else ''}")
                logger.info(f"[CVE] Matched {len(tech_cves)} CVEs for {name} {version}")

                # Create one CVE document per (cveId, asset) pair
                for raw in tech_cves:
                    for asset in assets:
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
                        logger.info(f"[CVE] Saved: {raw['cveId']} → asset {asset['assetId']}")
            else:
                _append_log(scan_id, f"[CVE] {name} {version} → no CVEs found")

            _update_scan(scan_id, total_cves=len(cves))

        _update_scan(scan_id, total_cves=len(cves), progress=95)
        if cves:
            top = sorted(cves, key=lambda x: x.get("cvssScore", 0), reverse=True)[:3]
            top_ids = ", ".join(c["cveId"] for c in top)
            _append_log(scan_id, f"[CVE] Correlation complete — {len(cves)} CVEs (top: {top_ids})")
        else:
            _append_log(scan_id, "[CVE] Correlation complete — 0 CVEs found")
        logger.info(f"[CVE] Correlation complete for scan {scan_id}: {len(cves)} CVE documents")

        # ── Stage 6: COMPLETED ───────────────────────────────────────────
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
            f"{len(live_assets)} live assets, {total_findings} findings, {len(cves)} CVEs",
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


@router.get("/findings/{scan_id}", tags=["Findings"])
async def get_findings_by_scan(scan_id: str) -> dict:
    if scan_id not in _SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = _SCANS[scan_id]
    return {
        "scanId":           scan_id,
        "target":           scan["target"],
        "scanProfile":      scan.get("scanProfile"),
        "status":           scan["status"],
        "findings":         scan["findings"],
        "totalFindings":    scan["total_findings"],
        "templatesExecuted": scan.get("templatesExecuted", 0),
        "duration":         scan.get("duration"),
    }


@router.get("/queue", tags=["Scans"])
async def get_queue() -> dict:
    active = [
        {"scanId": s["scanId"], "target": s["target"], "status": s["status"]}
        for s in _SCANS.values() if s["status"] in _ACTIVE_RUNNING
    ]
    pending = [
        {"scanId": sid, "target": t, "profile": p, "position": i + 1}
        for i, (sid, t, p) in enumerate(_PENDING)
    ]
    return {"maxConcurrent": MAX_CONCURRENT_SCANS, "active": active, "pending": pending}
