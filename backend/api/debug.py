from __future__ import annotations

"""
CVE Pipeline Debug API
───────────────────────
Provides diagnostic endpoints for auditing and testing the CVE Intelligence pipeline.

GET  /debug/cve-pipeline          — full pipeline status snapshot
POST /debug/cve-test              — run synthetic NVD test for a given tech+version
GET  /debug/tech-detection        — test httpx-toolkit tech detection on a URL
"""

import asyncio
import re
import time
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel

from discovery.httpx_toolkit import is_httpx_toolkit_available, stream_probe_hosts, _extract_server_version, _parse_tech
from discovery.subfinder import is_subfinder_available
from intelligence.nvd_client import (
    get_cves_for_technology,
    parse_tech,
    _CVE_CACHE,
    _norm_name,
    _CPE_MAP,
    _TECH_KEYWORDS,
    _sync_nvd_request,
    NVD_BASE,
)
from scanners.nuclei import is_nuclei_available
from api.scans import _SCANS
from utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/debug", tags=["Debug"])


class CveTestRequest(BaseModel):
    technology: str = "Apache"
    version: str    = "2.4.49"


class TechTestRequest(BaseModel):
    url: str = "https://nginx.org"


# ── Endpoints ─────────────────────────────────────────────────────────


@router.get("/cve-pipeline")
async def cve_pipeline_status() -> dict:
    """
    Full snapshot of the CVE pipeline:
    - Tool availability
    - CVE cache contents
    - Active scan asset/CVE counts
    """
    # Tool checks
    tools = {
        "subfinder":     await is_subfinder_available(),
        "httpx_toolkit": await is_httpx_toolkit_available(),
        "nuclei":        is_nuclei_available(),
        "nvd_reachable": None,  # filled below
    }

    # Quick NVD connectivity check (keyword search, 0 results ok)
    from urllib.parse import urlencode
    nvd_ok = False
    nvd_error = None
    try:
        from intelligence.nvd_client import _sync_nvd_request, NVD_BASE
        url = f"{NVD_BASE}?{urlencode({'keywordSearch': 'test', 'resultsPerPage': 1})}"
        result = await asyncio.to_thread(_sync_nvd_request, url)
        nvd_ok = result is not None and "vulnerabilities" in result
        if not nvd_ok and result is not None:
            nvd_error = str(result)
    except Exception as exc:
        nvd_error = str(exc)
    tools["nvd_reachable"] = nvd_ok

    # Cache summary
    cache_entries = []
    for key, cves in _CVE_CACHE.items():
        tech, _, ver = key.partition(":")
        cache_entries.append({
            "technology": tech,
            "version":    ver,
            "cveCount":   len(cves),
            "topCves":    [c["cveId"] for c in cves[:3]],
        })

    # Active scan summaries
    scan_summaries = []
    for scan_id, scan in _SCANS.items():
        if scan["scanProfile"] != "FULL_SCAN":
            continue
        assets = scan.get("assets", [])
        cves   = scan.get("cves", [])
        live   = [a for a in assets if a.get("alive")]

        # Gather all detected technologies per asset
        all_techs = []
        for a in live:
            for t in a.get("technologies") or []:
                name, ver = parse_tech(t)
                all_techs.append({"technology": name, "version": ver, "assetUrl": a.get("url")})

        scan_summaries.append({
            "scanId":           scan_id,
            "target":           scan["target"],
            "status":           scan["status"],
            "totalAssets":      len(assets),
            "liveAssets":       len(live),
            "totalCves":        len(cves),
            "detectedTechs":    all_techs,
            "cveDocuments":     cves[:10],  # first 10
        })

    return {
        "tools":          tools,
        "nvdError":       nvd_error,
        "cveCache":       cache_entries,
        "activeScans":    scan_summaries,
        "pipelineStages": [
            "1. DISCOVERING_ASSETS  — subfinder enumerates subdomains",
            "2. VALIDATING_ASSETS   — httpx-toolkit probes + detects technologies + extracts version from Server header",
            "3. SCANNING_ASSETS     — nuclei scans all live assets",
            "4. DETECTING_TECHNOLOGIES — version extraction + [CVE] logging",
            "5. CVE_ANALYSIS        — NVD API lookup per versioned technology",
            "6. COMPLETED",
        ],
    }


@router.post("/cve-test")
async def cve_test(req: CveTestRequest) -> dict:
    """
    Run a live NVD CVE lookup for a given technology and version.
    Useful to verify the NVD client works end-to-end.

    Example: POST { "technology": "Apache", "version": "2.4.49" }
    Expected CVEs: CVE-2021-41773, CVE-2021-42013
    """
    tech    = req.technology.strip()
    version = req.version.strip()
    norm    = _norm_name(tech)

    stages: list[dict] = []

    # Stage 1: Parse
    parsed_name, parsed_version = parse_tech(f"{tech}:{version}")
    stages.append({
        "stage":  "1. parse_tech",
        "input":  f"{tech}:{version}",
        "result": {"name": parsed_name, "version": parsed_version},
        "pass":   parsed_version is not None,
    })

    # Stage 2: CPE map lookup
    cpe_product = _CPE_MAP.get(norm)
    stages.append({
        "stage":  "2. CPE map lookup",
        "input":  norm,
        "result": {"cpe_product": cpe_product},
        "pass":   cpe_product is not None,
    })

    # Stage 3: Keyword map lookup
    keyword_name = _TECH_KEYWORDS.get(norm, tech)
    stages.append({
        "stage":  "3. keyword map lookup",
        "input":  norm,
        "result": {"keyword": f"{keyword_name} {version}"},
        "pass":   True,
    })

    # Stage 4: NVD connectivity test
    from urllib.parse import urlencode
    nvd_url  = f"{NVD_BASE}?{urlencode({'keywordSearch': f'{keyword_name} {version}', 'resultsPerPage': 5})}"
    t0       = time.monotonic()
    nvd_raw  = await asyncio.to_thread(_sync_nvd_request, nvd_url)
    elapsed  = round(time.monotonic() - t0, 2)
    nvd_ok   = nvd_raw is not None and "vulnerabilities" in nvd_raw
    stages.append({
        "stage":      "4. NVD API connectivity",
        "url":        nvd_url,
        "elapsedSec": elapsed,
        "rawCount":   len(nvd_raw.get("vulnerabilities", [])) if nvd_ok else 0,
        "pass":       nvd_ok,
        "error":      None if nvd_ok else "NVD returned no valid response",
    })

    # Stage 5: Full CVE lookup via cache-aware client
    t0       = time.monotonic()
    cves     = await get_cves_for_technology(tech, version)
    elapsed  = round(time.monotonic() - t0, 2)
    stages.append({
        "stage":      "5. get_cves_for_technology",
        "elapsedSec": elapsed,
        "cveCount":   len(cves),
        "pass":       len(cves) > 0,
        "cves":       [
            {
                "cveId":    c["cveId"],
                "severity": c["severity"],
                "cvss":     c["cvssScore"],
                "exploit":  c["exploitAvailable"],
            }
            for c in cves[:10]
        ],
    })

    all_pass = all(s["pass"] for s in stages)
    return {
        "technology": tech,
        "version":    version,
        "allPass":    all_pass,
        "stages":     stages,
        "summary":    f"✓ {len(cves)} CVEs found for {tech} {version}" if cves else f"✗ No CVEs found for {tech} {version}",
    }


@router.post("/tech-detection")
async def tech_detection_test(req: TechTestRequest) -> dict:
    """
    Run httpx-toolkit tech detection on a URL and show exactly what technologies
    and versions are detected — what the CVE pipeline will see.
    """
    url = req.url
    if not url.startswith("http"):
        url = f"https://{url}"

    host  = urlparse(url).hostname or url
    found = None
    error = None

    try:
        async for result in stream_probe_hosts([host]):
            found = result
            break
    except Exception as exc:
        error = str(exc)

    if not found:
        return {
            "url":    url,
            "alive":  False,
            "error":  error or "httpx-toolkit returned no result",
            "technologies": [],
            "versioned":    [],
        }

    techs    = found.get("technologies") or []
    versioned = []
    for t in techs:
        name, ver = parse_tech(t)
        if ver:
            versioned.append({"name": name, "version": ver, "raw": t})

    return {
        "url":         url,
        "alive":       True,
        "statusCode":  found.get("statusCode"),
        "server":      found.get("server"),
        "title":       found.get("title"),
        "ip":          found.get("ip"),
        "technologies": techs,
        "versioned":   versioned,
        "versionedCount": len(versioned),
        "note":        "Only 'versioned' technologies trigger NVD CVE lookups" if versioned
                       else "No versioned technologies detected — Server header must expose a version (e.g. nginx/1.18.0)",
    }
