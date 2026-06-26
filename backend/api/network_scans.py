from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from models.network_scan import NetworkHealthResponse, NetworkScanRequest
from scanners.nmap_scanner import (
    build_web_urls,
    discover_live_hosts,
    extract_technologies,
    get_mock_hosts_for_target,
    get_mock_ports_for_ip,
    get_web_ports,
    is_nmap_available,
    scan_ports_and_services,
)
from scanners.nuclei import is_nuclei_available, stream_nuclei_scan
from intelligence.nvd_client import get_cves_for_technology
from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/network")

# ── In-memory registry ────────────────────────────────────────────────
_SCANS: Dict[str, dict]         = {}
_TASKS: Dict[str, asyncio.Task] = {}

# Per-engine Nuclei timeout (applies within each host / total quick scan)
NUCLEI_TIMEOUT_SECS = 900   # 15 min — unchanged from original

# Statuses that count as "active" for per-user concurrency
_ACTIVE = frozenset({"queued", "host_discovery", "port_scan", "parallel_analysis"})

# Terminal statuses (SSE stream closes)
_TERMINAL = frozenset({"completed", "completed_timeout", "failed", "cancelled"})

from utils.scan_queue import UserScanQueue, QUICK_SCAN_TIMEOUT_SECS, FULL_SCAN_TIMEOUT_SECS
_QUEUE = UserScanQueue(_SCANS, _TASKS, _ACTIVE)

# ── Port-based network security check rules ───────────────────────────
_NET_CHECK_RULES: List[Tuple[int, str, str, str]] = [
    (23,    "Telnet Service Exposed",
             "high",
             "Telnet transmits credentials in cleartext. Replace with SSH."),
    (21,    "FTP Service Detected",
             "medium",
             "FTP sends credentials in cleartext. Use SFTP or SCP instead."),
    (6379,  "Redis Service Exposed",
             "high",
             "Redis is reachable without authentication — full data read/write possible."),
    (27017, "MongoDB Service Exposed",
             "high",
             "MongoDB port is reachable. Unauthenticated instances allow full data access."),
    (9200,  "Elasticsearch Exposed",
             "high",
             "Elasticsearch REST API is reachable without authentication."),
    (2375,  "Docker API Exposed",
             "critical",
             "Docker daemon API is exposed — unauthenticated remote code execution risk."),
    (2376,  "Docker TLS API Exposed",
             "high",
             "Docker daemon TLS API is reachable from the network."),
    (8500,  "Consul API Exposed",
             "medium",
             "HashiCorp Consul API is reachable and may allow unauthenticated access."),
    (5900,  "VNC Service Exposed",
             "high",
             "VNC remote desktop service is exposed on the network."),
    (11211, "Memcached Service Exposed",
             "high",
             "Memcached is accessible without authentication — amplification and data leakage risk."),
    (5432,  "PostgreSQL Reachable",
             "low",
             "PostgreSQL database port is reachable from the network."),
    (3306,  "MySQL Reachable",
             "low",
             "MySQL database port is reachable from the network."),
    (1433,  "MSSQL Reachable",
             "low",
             "Microsoft SQL Server port is reachable from the network."),
    (445,   "SMB Service Exposed",
             "medium",
             "SMB/CIFS is reachable — ensure it is patched against known exploits (e.g. EternalBlue)."),
    (135,   "RPC Endpoint Mapper Exposed",
             "medium",
             "Windows RPC endpoint mapper is reachable from the network."),
]
_NET_CHECK_PORT_MAP = {rule[0]: rule for rule in _NET_CHECK_RULES}

_SSH_VER_RE          = re.compile(r"openssh[\s_]+(\d+\.\d+)", re.IGNORECASE)
_HTTP_ONLY_PORTS     = frozenset({80, 8080, 8000, 8888})
_TLS_PORTS           = frozenset({443, 8443, 4443})

# Mock nuclei findings used when Nuclei binary is unavailable
_MOCK_NET_FINDINGS = [
    {"source": "nuclei", "severity": "medium",
     "title": "Missing Content-Security-Policy",
     "template": "vectra-missing-csp",
     "description": "Content-Security-Policy header is not set."},
    {"source": "nuclei", "severity": "low",
     "title": "Missing X-Frame-Options",
     "template": "vectra-missing-xfo",
     "description": "X-Frame-Options header is absent — clickjacking risk."},
    {"source": "nuclei", "severity": "info",
     "title": "HTTP Server Header Exposed",
     "template": "tech-detect",
     "description": "Server version information is exposed in HTTP headers."},
]


# ── Helpers ───────────────────────────────────────────────────────────

def _build_scan_id() -> str:
    return f"nscan_{uuid.uuid4().hex[:12]}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(scan_id: str, message: str) -> None:
    if scan_id in _SCANS:
        _SCANS[scan_id]["logs"].append({"timestamp": _now(), "message": message})


def _update(scan_id: str, **kwargs) -> None:
    if scan_id in _SCANS:
        _SCANS[scan_id].update(kwargs)


def _fmt(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s" if m else f"{s}s"




def _set_engine(scan_id: str, engine: str, eng_status: str, count: int = -1) -> None:
    engines = _SCANS[scan_id].setdefault("engines", {})
    if engine not in engines:
        engines[engine] = {"status": "pending", "count": 0}
    engines[engine]["status"] = eng_status
    if count >= 0:
        engines[engine]["count"] = count


def _blank_scan(scan_id: str, target: str, profile: str, user_id: str = "anonymous") -> dict:
    return {
        "scanId":         scan_id,
        "target":         target,
        "scanProfile":    profile,
        "userId":         user_id,
        "status":         "queued",
        "progress":       0,
        "currentStep":    "Queued",
        "logs":           [{"timestamp": _now(), "message": f"Network scan queued ({profile})"}],
        "hosts":          [],
        "total_hosts":    0,
        "live_hosts":     0,
        "findings":       [],
        "total_findings": 0,
        "cves":           [],
        "total_cves":     0,
        "duration":       None,
        "error":          None,
        "engines": {
            "host_discovery": {"status": "pending", "count": 0},
            "port_scan":      {"status": "pending", "count": 0},
            "cve_analysis":   {"status": "pending", "count": 0},
            "nuclei":         {"status": "pending", "count": 0},
            "network_checks": {"status": "pending", "count": 0},
        },
    }




# Regex to extract tech name and version from nmap 'version' field.
# nmap version strings: "nginx 1.18.0", "OpenSSH 8.4p1", "Apache httpd 2.4.50"
# Captures: group(1)=tech_name, group(2)=version_number
_NMAP_VER_RE = re.compile(r"^(.+?)\s+(\d+(?:\.\d+)+)")


# ── Parallel Engine 1: CVE Correlation ───────────────────────────────

async def _engine_cve(scan_id: str, hosts: List[dict]) -> None:
    """
    Query NVD for every detected service/version as soon as service detection
    completes. Results stream into _SCANS immediately.

    nmap 'version' field format: "nginx 1.18.0", "OpenSSH 8.4p1"
    We parse directly from the version field using _NMAP_VER_RE — NOT via
    parse_tech(), which expects colon-separated "tech:version" format.
    """
    cves: List[dict] = _SCANS[scan_id]["cves"]
    seen: set = set()
    _set_engine(scan_id, "cve_analysis", "running")
    _log(scan_id, "[CVE] Starting CVE correlation against detected service versions")

    cve_count = 0
    for host in hosts:
        ip = host["ip"]
        for port_info in host.get("ports", []):
            # Use the nmap 'version' field directly: "nginx 1.18.0", "Apache httpd 2.4.50"
            ver_field = port_info.get("version", "").strip()
            if not ver_field:
                continue
            m = _NMAP_VER_RE.match(ver_field)
            if not m:
                continue
            name    = m.group(1).strip()
            version = m.group(2)

            _log(scan_id, f"[CVE] Querying: {name} {version} (port {port_info['port']})")
            try:
                tech_cves = await get_cves_for_technology(name, version)
            except Exception as exc:
                _log(scan_id, f"[CVE] Error querying {name} {version}: {exc}")
                continue

            for raw in tech_cves:
                key = f"{raw['cveId']}_{host['hostId']}_{port_info['port']}"
                if key in seen:
                    continue
                seen.add(key)
                cves.append({
                    **raw,
                    "id":        key,
                    "hostId":    host["hostId"],
                    "ip":        ip,
                    "port":      port_info["port"],
                    "scanId":    scan_id,
                    "createdAt": _now_iso(),
                })
                cve_count += 1
                _SCANS[scan_id]["total_cves"] = len(cves)
                _log(scan_id, f"[CVE] {raw['cveId']} — {name} {version} @ {ip}:{port_info['port']}")

    _set_engine(scan_id, "cve_analysis", "completed", cve_count)
    _log(scan_id, f"[CVE] Complete — {cve_count} CVE(s) found")


# ── Parallel Engine 2: Nuclei ─────────────────────────────────────────

async def _nuclei_scan_host(scan_id: str, host: dict) -> int:
    """Scan one host with Nuclei. Returns the number of findings added."""
    findings: List[dict] = _SCANS[scan_id]["findings"]
    ip    = host["ip"]
    urls  = build_web_urls(ip, host["webPorts"])
    count = 0

    for url in urls:
        if is_nuclei_available():
            async for raw in stream_nuclei_scan(url, "QUICK_SCAN"):
                findings.append({
                    "findingId":   f"nf_{uuid.uuid4().hex[:12]}",
                    "scanId":      scan_id,
                    "hostId":      host["hostId"],
                    "ip":          ip,
                    "source":      "nuclei",
                    "severity":    raw.get("severity", "info"),
                    "title":       raw.get("title", "Unknown"),
                    "template":    raw.get("template", "unknown"),
                    "host":        raw.get("host"),
                    "matched_at":  raw.get("matched_at"),
                    "description": raw.get("description"),
                    "port":        None,
                    "createdAt":   _now_iso(),
                })
                count += 1
                _SCANS[scan_id]["total_findings"] = len(findings)
                _log(scan_id, f"[Nuclei] [{raw.get('severity','info').upper()}] {raw.get('title')} — {url}")
        else:
            for mock in _MOCK_NET_FINDINGS:
                findings.append({
                    "findingId":   f"nf_{uuid.uuid4().hex[:12]}",
                    "scanId":      scan_id,
                    "hostId":      host["hostId"],
                    "ip":          ip,
                    "source":      "nuclei",
                    "severity":    mock["severity"],
                    "title":       mock["title"],
                    "template":    mock["template"],
                    "host":        url,
                    "matched_at":  url,
                    "description": mock["description"],
                    "port":        None,
                    "createdAt":   _now_iso(),
                })
                count += 1
            _SCANS[scan_id]["total_findings"] = len(findings)
            await asyncio.sleep(0.05)  # simulate async work

    return count


async def _engine_nuclei(scan_id: str, hosts: List[dict], full_scan: bool) -> None:
    """
    Nuclei engine — only scans web-port hosts.
    Quick scan: 15-min total timeout across all hosts.
    Full scan : 15-min timeout PER host; timeout on one host never stops others.
    """
    web_hosts = [h for h in hosts if h["isWebService"]]

    if not web_hosts:
        _set_engine(scan_id, "nuclei", "skipped", 0)
        _log(scan_id, "[Nuclei] No web services detected — engine skipped")
        return

    _set_engine(scan_id, "nuclei", "running")
    _log(scan_id, f"[Nuclei] Scanning {len(web_hosts)} web service(s) "
                  f"({'15 min/host' if full_scan else '15 min total'})")

    nuc_count = 0

    if full_scan:
        # Per-host 15-min timeout — one timeout never kills other hosts
        for host in web_hosts:
            ip = host["ip"]
            _log(scan_id, f"[Nuclei] → {ip} (timeout: 15 min)")
            try:
                count = await asyncio.wait_for(
                    _nuclei_scan_host(scan_id, host),
                    timeout=NUCLEI_TIMEOUT_SECS,
                )
                nuc_count += count
                _log(scan_id, f"[Nuclei] {ip} done — {count} finding(s)")
            except asyncio.TimeoutError:
                _log(scan_id, f"[Nuclei] Timeout on {ip} — partial findings saved, continuing")
    else:
        # Quick scan: 15-min total for all hosts combined
        async def _scan_all() -> None:
            nonlocal nuc_count
            for host in web_hosts:
                _log(scan_id, f"[Nuclei] → {host['ip']}")
                count = await _nuclei_scan_host(scan_id, host)
                nuc_count += count

        try:
            await asyncio.wait_for(_scan_all(), timeout=NUCLEI_TIMEOUT_SECS)
        except asyncio.TimeoutError:
            _log(scan_id, "[Nuclei] 15-minute global timeout — partial findings saved")
            _set_engine(scan_id, "nuclei", "completed_partial", nuc_count)
            return

    _set_engine(scan_id, "nuclei", "completed", nuc_count)
    _log(scan_id, f"[Nuclei] Complete — {nuc_count} finding(s)")


# ── Parallel Engine 3: Network Security Checks ────────────────────────

async def _engine_network_checks(scan_id: str, hosts: List[dict]) -> None:
    """
    Fast port-based security heuristics — completes in seconds.
    Checks dangerous exposed services, cleartext protocols, outdated versions.
    """
    findings: List[dict] = _SCANS[scan_id]["findings"]
    _set_engine(scan_id, "network_checks", "running")
    _log(scan_id, "[NetChecks] Running network security heuristics")

    check_count = 0

    for host in hosts:
        ip = host["ip"]
        host_ports: Dict[int, dict] = {p["port"]: p for p in host.get("ports", [])}
        open_port_set = set(host_ports)

        # ── Dangerous-service checks (port map) ──────────────────────
        for port_num, (_, title, severity, description) in _NET_CHECK_PORT_MAP.items():
            if port_num in host_ports:
                findings.append({
                    "findingId":   f"nc_{uuid.uuid4().hex[:12]}",
                    "scanId":      scan_id,
                    "hostId":      host["hostId"],
                    "ip":          ip,
                    "source":      "network-checks",
                    "severity":    severity,
                    "title":       title,
                    "template":    f"network-check-port-{port_num}",
                    "host":        ip,
                    "matched_at":  f"{ip}:{port_num}",
                    "description": description,
                    "port":        port_num,
                    "createdAt":   _now_iso(),
                })
                check_count += 1
                _SCANS[scan_id]["total_findings"] = len(findings)
                _log(scan_id, f"[NetChecks] [{severity.upper()}] {title} — {ip}:{port_num}")

        # ── Outdated SSH version ──────────────────────────────────────
        if 22 in host_ports:
            ver_str = host_ports[22].get("version", "")
            m = _SSH_VER_RE.search(ver_str)
            if m:
                try:
                    minor = float(m.group(1))
                    if minor < 8.0:
                        findings.append({
                            "findingId":   f"nc_{uuid.uuid4().hex[:12]}",
                            "scanId":      scan_id,
                            "hostId":      host["hostId"],
                            "ip":          ip,
                            "source":      "network-checks",
                            "severity":    "medium",
                            "title":       f"Outdated SSH Version ({ver_str})",
                            "template":    "network-check-ssh-version",
                            "host":        ip,
                            "matched_at":  f"{ip}:22",
                            "description": (
                                f"SSH server is running {ver_str}. "
                                "Upgrade to OpenSSH 8.0+ for current security patches."
                            ),
                            "port":        22,
                            "createdAt":   _now_iso(),
                        })
                        check_count += 1
                        _SCANS[scan_id]["total_findings"] = len(findings)
                        _log(scan_id, f"[NetChecks] [MEDIUM] Outdated SSH {ver_str} on {ip}:22")
                except ValueError:
                    pass

        # ── HTTP-only (no TLS) ────────────────────────────────────────
        http_only = _HTTP_ONLY_PORTS & open_port_set
        has_tls   = bool(_TLS_PORTS & open_port_set)
        if http_only and not has_tls:
            for port_num in sorted(http_only):
                url = f"http://{ip}" if port_num == 80 else f"http://{ip}:{port_num}"
                findings.append({
                    "findingId":   f"nc_{uuid.uuid4().hex[:12]}",
                    "scanId":      scan_id,
                    "hostId":      host["hostId"],
                    "ip":          ip,
                    "source":      "network-checks",
                    "severity":    "low",
                    "title":       f"Unencrypted HTTP Service (port {port_num})",
                    "template":    "network-check-http-no-tls",
                    "host":        ip,
                    "matched_at":  url,
                    "description": (
                        "HTTP service is running without HTTPS. "
                        "Enable TLS to protect data and credentials in transit."
                    ),
                    "port":        port_num,
                    "createdAt":   _now_iso(),
                })
                check_count += 1
                _SCANS[scan_id]["total_findings"] = len(findings)

        # Yield to event loop so other engines can stream concurrently
        await asyncio.sleep(0)

    _set_engine(scan_id, "network_checks", "completed", check_count)
    _log(scan_id, f"[NetChecks] Complete — {check_count} issue(s) found")


# ── Main pipeline ─────────────────────────────────────────────────────

async def _execute_network_scan(scan_id: str, target: str, profile: str) -> None:
    """
    Pipeline:
      Stage 1  HOST_DISCOVERY    — nmap -sn (ping sweep)
      Stage 2  PORT_SCAN         — nmap -Pn -sV per live host
      Stage 3  PARALLEL_ANALYSIS — CVE + Nuclei + Network Checks simultaneously
      Stage 4  COMPLETED (or COMPLETED_TIMEOUT if 15/30 min exceeded)
    """
    started_at = time.monotonic()
    full_scan  = (profile == "FULL_SCAN")
    timeout    = FULL_SCAN_TIMEOUT_SECS if full_scan else QUICK_SCAN_TIMEOUT_SECS

    async def _pipeline() -> None:
        # ── Stage 1: HOST DISCOVERY ───────────────────────────────────────
        _update(scan_id, status="host_discovery", progress=5,
                currentStep=f"Discovering live hosts in {target}")
        _log(scan_id, f"[Host Discovery] Starting nmap -sn scan on {target}")
        _set_engine(scan_id, "host_discovery", "running")

        if is_nmap_available():
            live_hosts = await discover_live_hosts(target)
        else:
            _log(scan_id, "[Host Discovery] nmap not available — using mock data")
            live_hosts = get_mock_hosts_for_target(target)

        hosts: List[dict] = []
        for h in live_hosts:
            host_id = f"host_{uuid.uuid4().hex[:10]}"
            entry = {
                "hostId":       host_id,
                "scanId":       scan_id,
                "ip":           h["ip"],
                "hostname":     h.get("hostname"),
                "status":       "up",
                "ports":        [],
                "isWebService": False,
                "webPorts":     [],
                "technologies": [],
                "createdAt":    _now_iso(),
            }
            hosts.append(entry)
            _log(scan_id, f"[Host Discovery] Live host: {h['ip']}"
                          + (f" ({h['hostname']})" if h.get("hostname") else ""))

        _SCANS[scan_id]["hosts"] = hosts
        _update(scan_id, total_hosts=len(hosts), live_hosts=len(hosts), progress=20)
        _set_engine(scan_id, "host_discovery", "completed", len(hosts))
        _log(scan_id, f"[Host Discovery] Complete — {len(hosts)} live host(s)")

        if not hosts:
            elapsed = _fmt(time.monotonic() - started_at)
            _update(scan_id, status="completed", progress=100,
                    currentStep="Completed — no live hosts found", duration=elapsed)
            _log(scan_id, "No live hosts found. Scan complete.")
            return

        # ── Stage 2: PORT SCAN + SERVICE DETECTION ────────────────────────
        _update(scan_id, status="port_scan", progress=25,
                currentStep=f"Scanning ports on {len(hosts)} host(s)")
        _log(scan_id, f"[Port Scan] Starting {'full' if full_scan else 'top-1000'} scan on {len(hosts)} host(s)")
        _set_engine(scan_id, "port_scan", "running")

        total_ports = 0
        for idx, host in enumerate(hosts):
            ip = host["ip"]
            _log(scan_id, f"[Port Scan] Scanning {ip}")

            ports = (
                await scan_ports_and_services(ip, full_scan=full_scan)
                if is_nmap_available()
                else get_mock_ports_for_ip(ip)
            )

            web_ports  = get_web_ports(ports)
            techs      = extract_technologies(ports)
            host["ports"]        = ports
            host["isWebService"] = bool(web_ports)
            host["webPorts"]     = web_ports
            host["technologies"] = techs
            total_ports += len(ports)

            pct = 25 + int(30 * (idx + 1) / len(hosts))
            _update(scan_id, progress=pct)

            port_summary = ", ".join(str(p["port"]) for p in ports[:8])
            _log(scan_id, f"[Port Scan] {ip} — {len(ports)} port(s): {port_summary}"
                          + (f" +{len(ports)-8} more" if len(ports) > 8 else ""))
            if techs:
                _log(scan_id, f"[Port Scan] {ip} — Services: {', '.join(techs[:5])}")

        _set_engine(scan_id, "port_scan", "completed", total_ports)
        _log(scan_id, f"[Port Scan] Complete — {total_ports} open port(s) across {len(hosts)} host(s)")
        _update(scan_id, progress=55)

        # ── Stage 3: PARALLEL ANALYSIS ────────────────────────────────────
        _update(scan_id, status="parallel_analysis", progress=58,
                currentStep="Running CVE, Nuclei & Network Checks in parallel")
        _log(scan_id, "[Parallel] CVE Correlation + Nuclei + Network Checks starting simultaneously")

        results = await asyncio.gather(
            _engine_cve(scan_id, hosts),
            _engine_nuclei(scan_id, hosts, full_scan),
            _engine_network_checks(scan_id, hosts),
            return_exceptions=True,
        )

        engine_names = ["CVE", "Nuclei", "Network Checks"]
        for name, res in zip(engine_names, results):
            if isinstance(res, Exception) and not isinstance(res, asyncio.CancelledError):
                _log(scan_id, f"[Parallel] {name} engine error: {res}")
                logger.error(f"[{scan_id}] {name} engine error", exc_info=res)

        _update(scan_id, progress=90)

        # ── Stage 4: COMPLETED ────────────────────────────────────────────
        elapsed        = _fmt(time.monotonic() - started_at)
        total_findings = _SCANS[scan_id]["total_findings"]
        total_cves     = len(_SCANS[scan_id]["cves"])
        total_ports_f  = sum(len(h["ports"]) for h in hosts)

        _update(scan_id, status="completed", progress=100,
                currentStep="Completed", duration=elapsed)
        _log(
            scan_id,
            f"Network scan complete in {elapsed} — "
            f"{len(hosts)} host(s), {total_ports_f} port(s), "
            f"{total_findings} finding(s), {total_cves} CVE(s)",
        )
        logger.info(f"[{scan_id}] Network scan complete in {elapsed}")

    # ── Wrap pipeline with scan-type timeout ─────────────────────────
    try:
        await asyncio.wait_for(_pipeline(), timeout=timeout)

    except asyncio.TimeoutError:
        elapsed        = _fmt(time.monotonic() - started_at)
        total_findings = _SCANS[scan_id]["total_findings"]
        total_cves     = len(_SCANS[scan_id]["cves"])
        _log(
            scan_id,
            f"[Timeout] {timeout // 60}-minute limit reached — "
            f"{total_findings} finding(s), {total_cves} CVE(s) preserved",
        )
        _update(scan_id, status="completed_timeout", progress=100,
                currentStep="Completed (Timeout Reached)", duration=elapsed)
        logger.info(f"[{scan_id}] Network scan timed out after {elapsed}")

    except asyncio.CancelledError:
        elapsed = _fmt(time.monotonic() - started_at)
        _update(scan_id, status="cancelled", currentStep="Cancelled", duration=elapsed)
        _log(scan_id, "Network scan cancelled")

    except Exception as exc:
        _update(scan_id, status="failed", progress=0, currentStep="Failed", error=str(exc))
        _log(scan_id, f"Error: {exc}")
        logger.error(f"[{scan_id}] Network scan error: {exc}", exc_info=True)


# ── Routes ────────────────────────────────────────────────────────────

@router.get("/health", response_model=NetworkHealthResponse, tags=["Network"])
async def network_health() -> NetworkHealthResponse:
    return NetworkHealthResponse(
        status="healthy",
        nmap=is_nmap_available(),
        nuclei=is_nuclei_available(),
    )


@router.post("/scan/start", status_code=status.HTTP_200_OK, tags=["Network"])
async def start_network_scan(request: NetworkScanRequest) -> dict:
    target   = request.target
    profile  = request.scanProfile.value
    user_id  = request.userId
    scan_id  = _build_scan_id()

    _SCANS[scan_id] = _blank_scan(scan_id, target, profile, user_id)
    _QUEUE.enqueue(user_id, scan_id, target, profile)
    asyncio.create_task(_QUEUE.try_start_next(user_id, _execute_network_scan))
    logger.info(f"[{scan_id}] Network scan queued [{profile}] for {target} (user={user_id})")

    return {"scanId": scan_id, "status": "queued", "scanProfile": profile}


@router.get("/scan/{scan_id}", tags=["Network"])
async def get_network_scan(scan_id: str) -> dict:
    if scan_id not in _SCANS:
        raise HTTPException(status_code=404, detail="Network scan not found")
    return _SCANS[scan_id]


@router.get("/scan/{scan_id}/stream", tags=["Network"])
async def stream_network_scan(scan_id: str) -> StreamingResponse:
    if scan_id not in _SCANS:
        raise HTTPException(status_code=404, detail="Network scan not found")

    async def event_generator():
        try:
            while True:
                scan = _SCANS.get(scan_id)
                if not scan:
                    yield f"data: {json.dumps({'done': True, 'error': 'Scan not found'})}\n\n"
                    break

                payload = {
                    "status":         scan["status"],
                    "progress":       scan["progress"],
                    "currentStep":    scan["currentStep"],
                    "logs":           scan["logs"],
                    "hosts":          scan["hosts"],
                    "total_hosts":    scan["total_hosts"],
                    "live_hosts":     scan["live_hosts"],
                    "findings":       scan["findings"],
                    "total_findings": scan["total_findings"],
                    "cves":           scan["cves"],
                    "total_cves":     scan["total_cves"],
                    "duration":       scan.get("duration"),
                    "error":          scan.get("error"),
                    "engines":        scan.get("engines", {}),
                }
                yield f"data: {json.dumps(payload)}\n\n"

                if scan["status"] in _TERMINAL:
                    yield f"data: {json.dumps({'done': True})}\n\n"
                    break

                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


@router.post("/scan/{scan_id}/cancel", tags=["Network"])
async def cancel_network_scan(scan_id: str) -> dict:
    if scan_id not in _SCANS:
        return {"success": False, "reason": "Scan not found"}

    current_status = _SCANS[scan_id]["status"]
    if current_status in _TERMINAL:
        return {"success": False, "reason": f"Scan already {current_status.replace('_', ' ')}"}

    _QUEUE.remove(scan_id)
    task = _TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()

    _update(scan_id, status="cancelled", currentStep="Cancelled")
    _log(scan_id, "Scan cancelled by user")
    return {"success": True, "scanId": scan_id, "status": "cancelled"}


@router.get("/scans", tags=["Network"])
async def list_network_scans() -> list:
    return [
        {
            "scanId":         s["scanId"],
            "target":         s["target"],
            "scanProfile":    s["scanProfile"],
            "status":         s["status"],
            "progress":       s["progress"],
            "live_hosts":     s["live_hosts"],
            "total_findings": s["total_findings"],
            "total_cves":     s["total_cves"],
            "duration":       s.get("duration"),
        }
        for s in _SCANS.values()
    ]
