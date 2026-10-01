from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Request, status, Depends
from fastapi.responses import StreamingResponse

from models.network_scan import NetworkHealthResponse, NetworkScanRequest
from scanners.ssl_scanner import analyze_ssl, is_ssl_port, generate_ssl_findings
from scanners.nmap_scanner import (
    build_web_urls,
    discover_live_hosts,
    extract_technologies,
    get_mock_hosts_for_target,
    get_mock_scan_result_for_ip,
    get_web_ports,
    is_nmap_available,
    scan_ports_and_services,
)
from intelligence.nvd_client import get_cves_for_technology
from utils.os_classifier import classify_os
from services.auth import Identity, require_user
from services.scan_guard import enforce_scan_quota, request_id_from
from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/network")

# ── In-memory registry ────────────────────────────────────────────────
_SCANS: Dict[str, dict]         = {}
_TASKS: Dict[str, asyncio.Task] = {}

# Statuses that count as "active" for per-user concurrency
_ACTIVE = frozenset({"queued", "host_discovery", "port_scan", "parallel_analysis"})

# Terminal statuses (SSE stream closes)
_TERMINAL = frozenset({"completed", "completed_timeout", "failed", "cancelled"})

from utils.scan_queue import (
    UserScanQueue,
    QUICK_SCAN_TIMEOUT_SECS,
    FULL_SCAN_TIMEOUT_SECS,
    MAX_NETWORK_WORKERS,
    MAX_CONCURRENT_SCANS_PER_USER,
)
# NOTE: _ACTIVE is passed for API compatibility but the queue no longer uses it
# for slot counting. Slots are tracked by live _TASKS entries instead.
_QUEUE = UserScanQueue(_SCANS, _TASKS, _ACTIVE)

# ── Stale-scan sweeper ────────────────────────────────────────────────

_SWEEPER_TASK: "asyncio.Task | None" = None


async def _scan_sweeper_loop() -> None:
    """
    Background task that runs every 60 s and detects stuck scans.
    Handles two cases:
      1. Scan stuck 'queued' > STALE_SCAN_SECS → re-trigger try_start_next
      2. Scan in active status but worker task is gone → mark failed
    """
    await asyncio.sleep(15)  # let startup settle
    while True:
        try:
            await _sweep()
        except Exception as exc:
            logger.error(f"[SWEEPER] Unexpected error: {exc}", exc_info=True)
        await asyncio.sleep(60)


async def _sweep() -> None:
    # 1. Re-trigger scans stuck in queue
    for scan_id, user_id, wait_secs in _QUEUE.stale_scans():
        logger.warning(
            f"[SWEEPER] Scan {scan_id} (user={user_id}) has been queued "
            f"for {wait_secs:.0f}s — re-triggering try_start_next"
        )
        asyncio.create_task(_QUEUE.try_start_next(user_id, _execute_network_scan))

    # 2. Detect scans stuck in a running status with no live task
    for scan_id, scan in list(_SCANS.items()):
        if scan["status"] in _TERMINAL:
            continue
        if scan["status"] == "queued":
            continue  # handled above via stale_scans()
        if scan_id not in _TASKS:
            elapsed = scan.get("_started_at", 0)
            logger.error(
                f"[SWEEPER] Scan {scan_id} is '{scan['status']}' but has no live worker task "
                f"— marking as failed (possible worker crash)"
            )
            _update(scan_id, status="failed", error="Worker task lost unexpectedly — scan marked failed")
            _log(scan_id, "[SWEEPER] Worker task not found — scan marked as failed for recovery")

    # 3. Log current queue health
    running = _QUEUE.running_count()
    depths  = _QUEUE.queue_depth()
    if running > 0 or depths:
        logger.info(
            f"[SWEEPER] Health — running={running}/{MAX_NETWORK_WORKERS} "
            f"queued={sum(depths.values())} users={list(depths.keys())}"
        )


def start_scan_sweeper() -> None:
    """Start the background stale-scan sweeper. Called from FastAPI startup."""
    global _SWEEPER_TASK
    if _SWEEPER_TASK is None or _SWEEPER_TASK.done():
        _SWEEPER_TASK = asyncio.create_task(_scan_sweeper_loop())
        logger.info(
            f"[SWEEPER] Stale scan sweeper started — "
            f"max_workers={MAX_NETWORK_WORKERS} max_per_user={MAX_CONCURRENT_SCANS_PER_USER}"
        )

# ── Port-based network security check rules ───────────────────────────
# Tuple: (port, title, severity, description, recommendation)
_NET_CHECK_RULES: List[Tuple[int, str, str, str, str]] = [
    (23,    "Telnet Service Exposed",
             "high",
             "Telnet transmits all data including credentials in cleartext over the network.",
             "Disable Telnet immediately and replace with SSH (port 22). "
             "Telnet has no encryption and poses a critical credential exposure risk."),
    (21,    "FTP Service Detected",
             "medium",
             "FTP sends credentials and file data in cleartext over the network.",
             "Replace FTP with SFTP (SSH File Transfer Protocol) or SCP. "
             "If FTP must remain, enforce TLS (FTPS) and disable anonymous access."),
    (3389,  "RDP Service Exposed",
             "high",
             "Remote Desktop Protocol (RDP) is exposed on the network. "
             "RDP is a frequent target for brute-force, credential stuffing, and exploitation attacks.",
             "Restrict RDP access to a VPN or bastion host. Enable Network Level Authentication (NLA), "
             "use strong passwords, and apply all Microsoft security patches."),
    (6379,  "Redis Service Exposed",
             "high",
             "Redis is reachable without authentication — full data read/write/delete is possible remotely.",
             "Bind Redis to 127.0.0.1 or restrict with firewall rules. "
             "Enable Redis AUTH with a strong password and disable CONFIG command in production."),
    (27017, "MongoDB Service Exposed",
             "high",
             "MongoDB port is reachable from the network. "
             "Unauthenticated instances expose all databases to read/write access.",
             "Enable MongoDB authentication, bind to localhost or private interface, "
             "and restrict network access with firewall rules."),
    (9200,  "Elasticsearch Exposed",
             "high",
             "Elasticsearch REST API is reachable without authentication. "
             "All indexed data can be read, modified, or deleted remotely.",
             "Enable Elasticsearch Security (X-Pack), require authentication, "
             "and restrict network access to trusted hosts only."),
    (2375,  "Docker API Exposed (Unauthenticated)",
             "critical",
             "Docker daemon API is exposed on the network without TLS. "
             "This allows unauthenticated remote code execution as root on the host.",
             "Immediately close port 2375. Use the TLS-authenticated API on port 2376, "
             "or restrict Docker socket access to localhost only."),
    (2376,  "Docker TLS API Exposed",
             "high",
             "Docker daemon TLS API is reachable from the network. "
             "Compromised client certificates grant full container and host control.",
             "Restrict access to port 2376 via firewall to authorised IPs only. "
             "Rotate client certificates regularly."),
    (8500,  "Consul API Exposed",
             "medium",
             "HashiCorp Consul API is reachable and may allow unauthenticated access to "
             "service catalog, KV store, and health checks.",
             "Enable Consul ACL system, use TLS for all Consul communications, "
             "and restrict access to the Consul API to trusted networks."),
    (5900,  "VNC Remote Desktop Exposed",
             "high",
             "VNC remote desktop service is exposed on the network. "
             "VNC passwords are weak by default and the protocol has known vulnerabilities.",
             "Restrict VNC access to localhost and tunnel through SSH. "
             "Use strong VNC authentication and consider replacing with a more secure remote access solution."),
    (11211, "Memcached Service Exposed",
             "high",
             "Memcached is accessible without authentication. "
             "This allows cache poisoning, data leakage, and amplification DDoS attacks.",
             "Bind Memcached to 127.0.0.1 only. Use firewall rules to block external access to port 11211. "
             "Consider enabling SASL authentication if external access is required."),
    (5432,  "PostgreSQL Port Reachable",
             "low",
             "PostgreSQL database port is reachable from the network. "
             "Ensure authentication is properly configured.",
             "Restrict PostgreSQL access to application servers only via firewall rules. "
             "Use strong password authentication and consider certificate-based auth."),
    (3306,  "MySQL Port Reachable",
             "low",
             "MySQL database port is reachable from the network. "
             "Ensure authentication is properly configured and remote root login is disabled.",
             "Restrict MySQL access to application servers only. "
             "Disable remote root login and use dedicated database users with minimum required privileges."),
    (1433,  "MSSQL Port Reachable",
             "low",
             "Microsoft SQL Server port is reachable from the network.",
             "Restrict access to MSSQL to application servers only. "
             "Disable sa account, use Windows Authentication where possible, and audit login attempts."),
    (445,   "SMB Service Exposed",
             "medium",
             "SMB/CIFS is reachable from the network. "
             "Ensure it is fully patched against known exploits including EternalBlue (MS17-010).",
             "Apply all Windows security patches. Disable SMBv1 if still enabled. "
             "Restrict SMB access to authorised internal hosts only via firewall rules."),
    (135,   "RPC Endpoint Mapper Exposed",
             "medium",
             "Windows RPC endpoint mapper is reachable from the network. "
             "This can expose DCOM services to remote attack.",
             "Restrict access to port 135 via firewall to internal hosts only. "
             "Ensure Windows is fully patched against known RPC vulnerabilities."),
    (5985,  "WinRM HTTP Exposed",
             "medium",
             "Windows Remote Management (WinRM) HTTP service is reachable on the network. "
             "Allows remote PowerShell execution.",
             "Restrict WinRM access to authorised management hosts only. "
             "Use HTTPS (port 5986) instead of HTTP for encrypted management traffic."),
    (5986,  "WinRM HTTPS Exposed",
             "low",
             "Windows Remote Management (WinRM) HTTPS service is reachable on the network.",
             "Restrict WinRM HTTPS access to authorised management hosts only via firewall rules."),
    (8161,  "ActiveMQ Admin Console Exposed",
             "high",
             "Apache ActiveMQ admin web console is reachable. "
             "Default credentials are often unchanged and remote code execution vulnerabilities exist.",
             "Restrict access to port 8161 to localhost only. "
             "Change default credentials immediately and apply all ActiveMQ security patches."),
    (61616, "ActiveMQ Broker Exposed",
             "medium",
             "Apache ActiveMQ message broker port is reachable from the network.",
             "Restrict access to the ActiveMQ broker to authorised application servers only. "
             "Enable authentication on the broker and apply security patches."),
    (161,   "SNMP Service Exposed",
             "medium",
             "SNMP is exposed on the network. SNMPv1/v2c transmit community strings in cleartext, "
             "allowing an attacker to query network device configurations, routing tables, and ARP caches.",
             "Upgrade to SNMPv3 with authentication and encryption. "
             "Restrict SNMP access to authorised management hosts via ACL. "
             "Change default community strings (public/private) immediately."),
    (6443,  "Kubernetes API Server Exposed",
             "high",
             "The Kubernetes API server is reachable from the network. "
             "Misconfigured RBAC or anonymous access allows container orchestration control "
             "including deploying malicious workloads and accessing secrets.",
             "Restrict Kubernetes API access to authorised admin IPs via firewall. "
             "Enable RBAC, audit logging, and mutual TLS. "
             "Disable anonymous authentication (--anonymous-auth=false)."),
    (8001,  "Kubernetes Dashboard Exposed",
             "high",
             "The Kubernetes Dashboard web UI is reachable from the network. "
             "Exposed dashboards are a common cluster takeover vector and may allow "
             "unauthenticated access in misconfigured deployments.",
             "Disable the Dashboard if not required. If needed, access only via 'kubectl proxy' "
             "and never expose it externally. Enforce minimal RBAC permissions."),
    (3000,  "Grafana Dashboard Exposed",
             "medium",
             "Grafana monitoring dashboard is reachable on the network. "
             "Default admin:admin credentials or public access exposes sensitive metrics "
             "and internal infrastructure topology.",
             "Restrict Grafana to authorised internal networks. "
             "Change default admin credentials, enable authentication with SSO, "
             "and place Grafana behind a reverse proxy."),
    (9090,  "Prometheus Metrics Endpoint Exposed",
             "medium",
             "Prometheus metrics endpoint is reachable from the network. "
             "Prometheus exposes detailed system and application metrics including internal "
             "endpoints, credentials, and infrastructure data useful for reconnaissance.",
             "Restrict Prometheus to trusted monitoring networks. "
             "Enable authentication via a reverse proxy (nginx/traefik) with basic auth or OAuth2."),
    (5672,  "RabbitMQ AMQP Broker Exposed",
             "high",
             "RabbitMQ AMQP message broker is reachable from the network. "
             "Unauthenticated or weakly authenticated access allows reading/injecting "
             "messages in all queues — potential for data theft and message poisoning.",
             "Bind RabbitMQ to internal interfaces only. "
             "Enable strong credentials and TLS for all broker connections. "
             "Restrict access via firewall to authorised application servers."),
    (15672, "RabbitMQ Management API Exposed",
             "high",
             "RabbitMQ Management HTTP API and console is reachable. "
             "Default credentials (guest/guest) are commonly unchanged and allow "
             "full queue management, vhost configuration, and user creation.",
             "Change default credentials immediately and disable guest user for remote access. "
             "Restrict Management API to localhost or an internal management VLAN."),
    (9092,  "Apache Kafka Broker Exposed",
             "high",
             "Apache Kafka message broker is reachable from the network without authentication. "
             "Unauthenticated access allows reading sensitive event streams and injecting "
             "malicious messages into production topics.",
             "Enable SASL authentication (SCRAM-SHA-512 recommended) and TLS encryption. "
             "Restrict broker access via firewall to authorised producer/consumer hosts."),
    (5984,  "CouchDB HTTP API Exposed",
             "high",
             "Apache CouchDB HTTP API is reachable from the network. "
             "CouchDB is known for critical vulnerabilities (CVE-2017-12635) and often runs "
             "in 'admin party' mode with no authentication required.",
             "Enable CouchDB authentication and disable admin party mode. "
             "Bind CouchDB to localhost or internal interfaces and apply all security patches."),
    (5601,  "Kibana Analytics Dashboard Exposed",
             "medium",
             "Kibana analytics dashboard is reachable from the network. "
             "Exposed Kibana instances reveal sensitive log data, Elasticsearch indices, "
             "and internal application behaviour.",
             "Enable Elasticsearch Security (X-Pack) to secure both Elasticsearch and Kibana. "
             "Restrict Kibana access to trusted networks and require authentication."),
    (10000, "Webmin Admin Interface Exposed",
             "high",
             "Webmin web-based system administration is reachable. "
             "Webmin has a history of critical RCE vulnerabilities (CVE-2019-15107: Backdoor RCE) "
             "and remote code execution via default or weak credentials.",
             "Restrict Webmin to localhost and access only via SSH tunnel. "
             "Keep Webmin fully patched, use strong unique credentials, "
             "and enable two-factor authentication."),
    (4848,  "GlassFish Admin Console Exposed",
             "high",
             "GlassFish application server admin console is reachable on the network. "
             "Known critical vulnerabilities allow unauthenticated remote code execution.",
             "Restrict GlassFish admin console to localhost only. "
             "Change default admin credentials and keep GlassFish fully patched."),
]
_NET_CHECK_PORT_MAP = {rule[0]: rule for rule in _NET_CHECK_RULES}

_SSH_VER_RE      = re.compile(r"openssh[\s_]+(\d+\.\d+)", re.IGNORECASE)
_HTTP_ONLY_PORTS = frozenset({80, 8080, 8000, 8888})
_TLS_PORTS       = frozenset({443, 8443, 4443})


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
            "host_discovery":    {"status": "pending", "count": 0},
            "port_scan":         {"status": "pending", "count": 0},
            "service_detection": {"status": "pending", "count": 0},
            "cve_analysis":      {"status": "pending", "count": 0},
            "network_checks":    {"status": "pending", "count": 0},
            "ssl_analysis":      {"status": "pending", "count": 0},
        },
    }


# Regex to extract tech name and version from nmap 'version' field.
# nmap version strings: "nginx 1.18.0", "OpenSSH 8.4p1", "Apache httpd 2.4.50"
# Captures: group(1)=tech_name, group(2)=version_number
_NMAP_VER_RE = re.compile(r"^(.+?)\s+(\d+(?:\.\d+)+)")


# ── Parallel Engine 1: Service Detection ─────────────────────────────

async def _engine_service_detection(scan_id: str, hosts: List[dict]) -> None:
    """
    Indexes service and banner data already collected during the port scan stage.
    nmap -sV captures service versions — this engine summarises those results for
    the UI and feeds into CVE correlation.
    """
    _set_engine(scan_id, "service_detection", "running")
    _log(scan_id, "[Services] Indexing detected services and banners")

    service_count = 0
    service_names: List[str] = []
    for host in hosts:
        for port_info in host.get("ports", []):
            version = port_info.get("version", "").strip()
            service = port_info.get("service", "").strip()
            if version:
                service_count += 1
                if service and service != "unknown":
                    service_names.append(f"{service} {version}".strip())

    await asyncio.sleep(0)  # yield to event loop
    _set_engine(scan_id, "service_detection", "completed", service_count)
    _log(scan_id, f"[Services] {service_count} versioned service(s) fingerprinted")
    if service_names:
        _log(scan_id, f"[Services] Detected: {', '.join(service_names[:8])}"
                      + (f" +{len(service_names)-8} more" if len(service_names) > 8 else ""))


# ── Parallel Engine 2: CVE Correlation ───────────────────────────────

async def _engine_cve(scan_id: str, hosts: List[dict]) -> None:
    """
    Query NVD for every detected service/version as soon as service detection
    completes. Results stream into _SCANS immediately.

    nmap 'version' field format: "nginx 1.18.0", "OpenSSH 8.4p1"
    We parse directly from the version field using _NMAP_VER_RE.
    """
    cves: List[dict] = _SCANS[scan_id]["cves"]
    seen: set = set()
    _set_engine(scan_id, "cve_analysis", "running")
    _log(scan_id, "[CVE] Starting CVE correlation against detected service versions")

    cve_count = 0
    for host in hosts:
        ip = host["ip"]
        for port_info in host.get("ports", []):
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


# ── Parallel Engine 3: Network Security Checks ────────────────────────

async def _engine_network_checks(scan_id: str, hosts: List[dict]) -> None:
    """
    Port-based security heuristics — completes in seconds.
    Checks dangerous exposed services, cleartext protocols, and outdated versions.
    Each finding includes title, description, recommendation, evidence, and port.
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
        for port_num, (_, title, severity, description, recommendation) in _NET_CHECK_PORT_MAP.items():
            if port_num in host_ports:
                port_info = host_ports[port_num]
                protocol  = port_info.get("protocol", "tcp")
                version   = port_info.get("version", "").strip()
                service   = port_info.get("service", "").strip()
                evidence  = version or service or f"Port {port_num}/{protocol} open"

                findings.append({
                    "findingId":      f"nc_{uuid.uuid4().hex[:12]}",
                    "scanId":         scan_id,
                    "hostId":         host["hostId"],
                    "ip":             ip,
                    "source":         "port-scan",
                    "severity":       severity,
                    "title":          title,
                    "template":       f"network-check-port-{port_num}",
                    "host":           ip,
                    "matched_at":     f"{ip}:{port_num}",
                    "description":    description,
                    "recommendation": recommendation,
                    "port":           port_num,
                    "protocol":       protocol,
                    "evidence":       evidence,
                    "createdAt":      _now_iso(),
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
                            "findingId":      f"nc_{uuid.uuid4().hex[:12]}",
                            "scanId":         scan_id,
                            "hostId":         host["hostId"],
                            "ip":             ip,
                            "source":         "port-scan",
                            "severity":       "medium",
                            "title":          f"Outdated SSH Version ({ver_str})",
                            "template":       "network-check-ssh-version",
                            "host":           ip,
                            "matched_at":     f"{ip}:22",
                            "description":    (
                                f"SSH server is running {ver_str}, which is below the recommended "
                                "minimum of OpenSSH 8.0. Older versions may be vulnerable to known exploits."
                            ),
                            "recommendation": (
                                "Upgrade OpenSSH to the latest stable release (8.0+). "
                                "Review CVE advisories for the installed version and apply patches."
                            ),
                            "port":           22,
                            "protocol":       "tcp",
                            "evidence":       ver_str,
                            "createdAt":      _now_iso(),
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
                url      = f"http://{ip}" if port_num == 80 else f"http://{ip}:{port_num}"
                ver_str  = host_ports[port_num].get("version", "").strip()
                findings.append({
                    "findingId":      f"nc_{uuid.uuid4().hex[:12]}",
                    "scanId":         scan_id,
                    "hostId":         host["hostId"],
                    "ip":             ip,
                    "source":         "port-scan",
                    "severity":       "low",
                    "title":          f"Unencrypted HTTP Service (port {port_num})",
                    "template":       "network-check-http-no-tls",
                    "host":           ip,
                    "matched_at":     url,
                    "description":    (
                        "HTTP service is running without HTTPS. "
                        "All traffic including credentials and session tokens is sent in cleartext."
                    ),
                    "recommendation": (
                        "Configure TLS (HTTPS) and redirect all HTTP traffic to HTTPS. "
                        "Obtain a certificate from Let's Encrypt or your CA. "
                        "Set HSTS headers once HTTPS is in place."
                    ),
                    "port":           port_num,
                    "protocol":       "tcp",
                    "evidence":       ver_str or f"HTTP on port {port_num}",
                    "createdAt":      _now_iso(),
                })
                check_count += 1
                _SCANS[scan_id]["total_findings"] = len(findings)

        # Yield to event loop so other engines can stream concurrently
        await asyncio.sleep(0)

    _set_engine(scan_id, "network_checks", "completed", check_count)
    _log(scan_id, f"[NetChecks] Complete — {check_count} issue(s) found")


# ── Parallel Engine 4: SSL/TLS Analysis ──────────────────────────────

async def _engine_ssl_analysis(scan_id: str, hosts: List[dict]) -> None:
    """
    TLS handshake on every detected HTTPS/SSL port.
    Collects certificate metadata, TLS version, and cipher suite.
    Generates findings for expired/self-signed certs, weak TLS, and weak ciphers.
    """
    _set_engine(scan_id, "ssl_analysis", "running")
    _log(scan_id, "[SSL] Starting SSL/TLS analysis on detected TLS endpoints")

    ssl_count = 0
    for host in hosts:
        ip       = host["ip"]
        host_ssl: List[dict] = []

        for port_info in host.get("ports", []):
            port    = port_info["port"]
            service = port_info.get("service", "")
            if not is_ssl_port(port, service):
                continue

            ssl_info = await analyze_ssl(ip, port)
            if not ssl_info:
                continue

            host_ssl.append(ssl_info)
            ssl_count += 1

            new_finds = generate_ssl_findings(scan_id, host, ssl_info, _now_iso())
            findings  = _SCANS[scan_id]["findings"]
            findings.extend(new_finds)
            _SCANS[scan_id]["total_findings"] = len(findings)

            # Log a one-line summary per endpoint
            if ssl_info.get("isExpired"):
                _log(scan_id, f"[SSL] CRITICAL: Expired cert on {ip}:{port} — {ssl_info['subject']}")
            elif ssl_info.get("expiringSoon"):
                _log(scan_id, f"[SSL] WARNING: Cert expires in {ssl_info['daysUntilExpiry']}d on {ip}:{port}")
            elif ssl_info.get("isSelfSigned"):
                _log(scan_id, f"[SSL] WARNING: Self-signed cert on {ip}:{port} — {ssl_info['subject']}")
            elif ssl_info.get("isWeakTls"):
                _log(scan_id, f"[SSL] HIGH: Weak TLS ({ssl_info['tlsVersion']}) on {ip}:{port}")
            else:
                _log(scan_id, f"[SSL] OK: {ssl_info['tlsVersion']} on {ip}:{port} — {ssl_info['subject']}")

        if host_ssl:
            host["ssl"] = host_ssl

        await asyncio.sleep(0)  # yield between hosts

    _set_engine(scan_id, "ssl_analysis", "completed", ssl_count)
    _log(scan_id, f"[SSL] Complete — {ssl_count} TLS endpoint(s) analyzed")


# ── Risk scoring ──────────────────────────────────────────────────────

def _risk_level(score: int) -> str:
    if score <= 20: return "low"
    if score <= 40: return "medium"
    if score <= 70: return "high"
    return "critical"


async def _compute_risk_scores(scan_id: str, hosts: List[dict]) -> None:
    """
    Compute a 0-100 risk score for every host using CVEs, findings, and SSL issues.
    Weights: Critical CVE=15, High CVE=8, Med CVE=3, Low CVE=1;
             Critical finding=20, High=10, Med=5, Low=2;
             Expired SSL=20, Self-signed=12, Weak TLS=10, Expiring=8, Weak cipher=8.
    """
    _log(scan_id, "[Risk] Computing host risk scores")
    all_cves     = _SCANS[scan_id]["cves"]
    all_findings = _SCANS[scan_id]["findings"]
    sev_w = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}

    for host in hosts:
        hid    = host["hostId"]
        hcves  = [c for c in all_cves     if c.get("hostId") == hid]
        hfinds = [f for f in all_findings if f.get("hostId") == hid]

        score = 0
        for cve in hcves:
            cvss = float(cve.get("cvssScore") or 0)
            if cvss >= 9.0:   score += 15
            elif cvss >= 7.0: score += 8
            elif cvss >= 4.0: score += 3
            else:             score += 1

        for f in hfinds:
            score += sev_w.get(f.get("severity", "info"), 0)

        for ssl_info in host.get("ssl", []):
            if ssl_info.get("isExpired"):    score += 20
            if ssl_info.get("isSelfSigned"): score += 12
            if ssl_info.get("isWeakTls"):    score += 10
            if ssl_info.get("expiringSoon"): score += 8
            if ssl_info.get("isWeakCipher"): score += 8

        host["riskScore"] = min(100, score)
        host["riskLevel"] = _risk_level(host["riskScore"])
        _log(scan_id, f"[Risk] {host['ip']} — {host['riskScore']}/100 ({host['riskLevel'].upper()})")

    scores = [h["riskScore"] for h in hosts if "riskScore" in h]
    if scores:
        avg = sum(scores) // len(scores)
        _log(scan_id, f"[Risk] Network avg risk score: {avg}/100")


# ── Main pipeline ─────────────────────────────────────────────────────

async def _execute_network_scan(scan_id: str, target: str, profile: str) -> None:
    """
    Pipeline:
      Stage 1  HOST_DISCOVERY    — nmap -sn (ping sweep)
      Stage 2  PORT_SCAN         — nmap -Pn -sV -O per live host (ports, services, OS, MAC)
      Stage 3  PARALLEL_ANALYSIS — Service Detection + CVE Correlation + Network Checks simultaneously
      Stage 4  COMPLETED (or COMPLETED_TIMEOUT if timeout exceeded)
    """
    logger.info(f"[WORKER] Pipeline starting | scan={scan_id} target={target} profile={profile}")
    _log(scan_id, f"[WORKER] Worker picked up scan — starting pipeline ({profile})")
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
                "os":           "",
                "mac":          "",
                "vendor":       "",
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

        # ── Stage 2: PORT SCAN + SERVICE DETECTION + OS DETECTION ────────
        _update(scan_id, status="port_scan", progress=25,
                currentStep=f"Scanning ports on {len(hosts)} host(s)")
        _log(scan_id, f"[Port Scan] Starting {'full' if full_scan else 'top-1000'} port scan on {len(hosts)} host(s)")
        _set_engine(scan_id, "port_scan", "running")

        total_ports = 0
        for idx, host in enumerate(hosts):
            ip = host["ip"]
            _log(scan_id, f"[Port Scan] Scanning {ip} — ports, services, OS detection")

            if is_nmap_available():
                scan_result = await scan_ports_and_services(ip, full_scan=full_scan)
            else:
                scan_result = get_mock_scan_result_for_ip(ip)

            ports  = scan_result["ports"]
            web_ports = get_web_ports(ports)
            techs     = extract_technologies(ports)

            _os_raw = scan_result.get("os", "")
            os_info = classify_os(_os_raw)

            host["ports"]        = ports
            host["isWebService"] = bool(web_ports)
            host["webPorts"]     = web_ports
            host["technologies"] = techs
            host["os"]           = os_info["normalized"]
            host["osRaw"]        = _os_raw
            host["osFamily"]     = os_info["family"]
            host["osConfidence"] = os_info["confidence"]
            host["mac"]          = scan_result.get("mac", "")
            host["vendor"]       = scan_result.get("vendor", "")
            total_ports += len(ports)

            pct = 25 + int(30 * (idx + 1) / len(hosts))
            _update(scan_id, progress=pct)

            port_summary = ", ".join(str(p["port"]) for p in ports[:8])
            _log(scan_id, f"[Port Scan] {ip} — {len(ports)} port(s): {port_summary}"
                          + (f" +{len(ports)-8} more" if len(ports) > 8 else ""))
            if techs:
                _log(scan_id, f"[Port Scan] {ip} — Services: {', '.join(techs[:5])}")
            if host["os"]:
                conf = host.get("osConfidence", 0)
                _log(scan_id, f"[Port Scan] {ip} — OS: {host['os']} (confidence: {conf}%)")

        _set_engine(scan_id, "port_scan", "completed", total_ports)
        _log(scan_id, f"[Port Scan] Complete — {total_ports} open port(s) across {len(hosts)} host(s)")
        _update(scan_id, progress=55)

        # ── Stage 3: PARALLEL ANALYSIS ────────────────────────────────────
        _update(scan_id, status="parallel_analysis", progress=58,
                currentStep="Running Service Analysis, CVE Correlation, Network Checks & SSL Analysis")
        _log(scan_id, "[Parallel] Service Detection + CVE Correlation + Network Checks + SSL Analysis starting simultaneously")

        results = await asyncio.gather(
            _engine_service_detection(scan_id, hosts),
            _engine_cve(scan_id, hosts),
            _engine_network_checks(scan_id, hosts),
            _engine_ssl_analysis(scan_id, hosts),
            return_exceptions=True,
        )

        engine_names = ["Service Detection", "CVE Correlation", "Network Checks", "SSL Analysis"]
        for name, res in zip(engine_names, results):
            if isinstance(res, Exception) and not isinstance(res, asyncio.CancelledError):
                _log(scan_id, f"[Parallel] {name} engine error: {res}")
                logger.error(f"[{scan_id}] {name} engine error", exc_info=res)

        # ── Stage 3b: RISK SCORING ────────────────────────────────────
        await _compute_risk_scores(scan_id, hosts)
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
            f"[COMPLETE] Scan finished in {elapsed} — "
            f"{len(hosts)} host(s), {total_ports_f} port(s), "
            f"{total_findings} finding(s), {total_cves} CVE(s)",
        )
        logger.info(
            f"[COMPLETE] Scan {scan_id} done in {elapsed} | "
            f"hosts={len(hosts)} ports={total_ports_f} "
            f"findings={total_findings} cves={total_cves}"
        )

    # ── Wrap pipeline with scan-type timeout ─────────────────────────
    try:
        await asyncio.wait_for(_pipeline(), timeout=timeout)

    except asyncio.TimeoutError:
        elapsed        = _fmt(time.monotonic() - started_at)
        total_findings = _SCANS[scan_id]["total_findings"]
        total_cves     = len(_SCANS[scan_id]["cves"])
        _log(scan_id, f"[Timeout] {timeout // 60}-minute limit reached — "
                      f"{total_findings} finding(s), {total_cves} CVE(s) preserved")
        _update(scan_id, status="completed_timeout", progress=100,
                currentStep="Completed (Timeout Reached)", duration=elapsed)
        logger.warning(
            f"[TIMEOUT] Scan {scan_id} timed out after {elapsed} "
            f"({timeout//60}-min limit) | findings={total_findings} cves={total_cves}"
        )

    except asyncio.CancelledError:
        elapsed = _fmt(time.monotonic() - started_at)
        _update(scan_id, status="cancelled", currentStep="Cancelled", duration=elapsed)
        _log(scan_id, "[WORKER] Scan cancelled by user")
        logger.info(f"[CANCEL] Scan {scan_id} cancelled after {elapsed}")

    except Exception as exc:
        elapsed = _fmt(time.monotonic() - started_at)
        _update(scan_id, status="failed", progress=0, currentStep="Failed", error=str(exc))
        _log(scan_id, f"[ERROR] Pipeline error: {exc}")
        logger.error(f"[FAILED] Scan {scan_id} failed after {elapsed}: {exc}", exc_info=True)


# ── Routes ────────────────────────────────────────────────────────────

@router.get("/health", response_model=NetworkHealthResponse, tags=["Network"])
async def network_health() -> NetworkHealthResponse:
    return NetworkHealthResponse(
        status="healthy",
        nmap=is_nmap_available(),
    )


@router.get("/queue/status", tags=["Network"])
async def network_queue_status() -> dict:
    """Live queue and worker status — useful for debugging stuck scans."""
    running_scans = [
        {
            "scanId":   s["scanId"],
            "target":   s["target"],
            "status":   s["status"],
            "progress": s["progress"],
            "userId":   s.get("userId"),
        }
        for s in _SCANS.values()
        if s["status"] not in _TERMINAL
    ]
    return {
        "running":     _QUEUE.running_count(),
        "max_workers": MAX_NETWORK_WORKERS,
        "queue_depth": _QUEUE.queue_depth(),
        "stale_scans": [
            {"scanId": sid, "userId": uid, "wait_secs": int(w)}
            for sid, uid, w in _QUEUE.stale_scans()
        ],
        "active_scans": running_scans,
        "total_scans_in_memory": len(_SCANS),
    }


@router.post("/scan/start", status_code=status.HTTP_200_OK, tags=["Network"])
async def start_network_scan(
    request: NetworkScanRequest,
    http_request: Request,
    identity: Identity = Depends(require_user),
) -> dict:
    target   = request.target
    profile  = request.scanProfile.value
    claim    = enforce_scan_quota(identity, request.userId, "network", _build_scan_id(),
                                  request_id_from(http_request))
    scan_id  = claim.scanId
    user_id  = claim.uid
    if claim.duplicate:
        return {"scanId": scan_id, "status": _SCANS.get(scan_id, {}).get("status", "queued"),
                "scanProfile": profile, "duplicate": True}

    _SCANS[scan_id] = _blank_scan(scan_id, target, profile, user_id)
    logger.info(
        f"[QUEUE] Scan {scan_id} created | target={target} profile={profile} user={user_id} | "
        f"global running={_QUEUE.running_count()}/{MAX_NETWORK_WORKERS}"
    )
    _QUEUE.enqueue(user_id, scan_id, target, profile)
    asyncio.create_task(_QUEUE.try_start_next(user_id, _execute_network_scan))

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
            "Cache-Control":     "no-cache, no-transform",
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
