from __future__ import annotations

import asyncio
import os
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)

# Ports that indicate a web-accessible service
WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 4443})


def is_nmap_available() -> bool:
    return shutil.which("nmap") is not None


# Hosts without raw-socket capabilities (e.g. Cloud Run) make nmap abort on -O
# instead of skipping it, so unprivileged mode drops OS detection and forces
# TCP-connect scans.
NMAP_UNPRIVILEGED = os.getenv("NMAP_UNPRIVILEGED", "false").strip().lower() in {"1", "true", "yes"}


# ── Grepable-output parsers ───────────────────────────────────────────

_HOST_RE    = re.compile(r"^Host:\s+(\S+)\s+\(([^)]*)\)\s+Status:\s+(\w+)", re.MULTILINE)
_PORTS_LINE = re.compile(r"^Host:\s+(\S+)[^\t]*\tPorts:\s+([^\t\n]+)", re.MULTILINE)
_PORT_ENTRY = re.compile(r"(\d+)/open/(\w+)//([^/]*)//([^/]*)/")

# Extracted from the same host line that contains Ports:
_OS_RE  = re.compile(r"\tOS:\s+([^\t\n]+)")
_MAC_RE = re.compile(r"\tMAC Address:\s+([0-9A-Fa-f:]{17})\s+\(([^)]*)\)")


def _parse_hosts(output: str) -> List[Dict[str, Any]]:
    hosts = []
    for m in _HOST_RE.finditer(output):
        ip, hostname, state = m.group(1), m.group(2).strip(), m.group(3)
        hosts.append({
            "ip":       ip,
            "hostname": hostname or None,
            "status":   "up" if state.lower() == "up" else "down",
        })
    return hosts


def _parse_ports(output: str) -> Dict[str, List[Dict[str, Any]]]:
    """Return {ip: [{port, protocol, service, version, state}]}"""
    result: Dict[str, List[Dict[str, Any]]] = {}
    for m in _PORTS_LINE.finditer(output):
        ip, ports_str = m.group(1), m.group(2)
        result[ip] = []
        for pe in _PORT_ENTRY.finditer(ports_str):
            result[ip].append({
                "port":     int(pe.group(1)),
                "protocol": pe.group(2),
                "service":  pe.group(3).strip() or "unknown",
                "version":  pe.group(4).strip(),
                "state":    "open",
            })
    return result


def _parse_os_mac(output: str, ip: str) -> Tuple[str, str, str]:
    """
    Extract (os_string, mac_address, vendor) for a given IP from grepable nmap output.
    OS and MAC appear as tab-separated fields on the same line as Ports.
    Returns ("", "", "") if not found.
    """
    for line in output.splitlines():
        if not line.startswith(f"Host: {ip}"):
            continue
        os_str = ""
        mac    = ""
        vendor = ""

        m_os = _OS_RE.search(line)
        if m_os:
            # Strip confidence percentages: "Linux 4.15 - 5.6 (97%)" → "Linux 4.15 - 5.6"
            os_str = re.sub(r"\s*\(\d+%\)", "", m_os.group(1)).strip()

        m_mac = _MAC_RE.search(line)
        if m_mac:
            mac    = m_mac.group(1).upper()
            vendor = m_mac.group(2).strip()

        if os_str or mac:
            return os_str, mac, vendor

    return "", "", ""


# ── Low-level runner ──────────────────────────────────────────────────

async def _nmap(*args: str) -> str:
    if NMAP_UNPRIVILEGED:
        args = ("--unprivileged",) + tuple(a for a in args if a != "-O")
    cmd = ["nmap"] + list(args)
    logger.info(f"[nmap] {' '.join(cmd)}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await proc.communicate()
        return stdout.decode("utf-8", errors="replace")
    except asyncio.CancelledError:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise


# ── High-level helpers ────────────────────────────────────────────────

async def discover_live_hosts(target: str) -> List[Dict[str, Any]]:
    """Ping scan — returns list of live host dicts."""
    output = await _nmap("-sn", target, "-oG", "-")
    return [h for h in _parse_hosts(output) if h["status"] == "up"]


async def scan_ports_and_services(
    ip: str,
    full_scan: bool = False,
) -> Dict[str, Any]:
    """
    Port + service version + OS detection scan for a single host.
    Returns {"ports": [...], "os": str, "mac": str, "vendor": str}.
    OS detection (-O) requires root; if unavailable nmap omits it silently.
    """
    port_arg = "-p-" if full_scan else "--top-ports=1000"
    output = await _nmap(
        "-Pn", "-sV", "-O", "--open",
        port_arg, "--version-intensity=5",
        ip, "-oG", "-",
    )
    ports          = _parse_ports(output).get(ip, [])
    os_str, mac, vendor = _parse_os_mac(output, ip)
    return {"ports": ports, "os": os_str, "mac": mac, "vendor": vendor}


def extract_technologies(ports: List[Dict[str, Any]]) -> List[str]:
    """Build 'service version' strings for CVE correlation."""
    techs = []
    seen: set[str] = set()
    for p in ports:
        svc = (p.get("service") or "").strip()
        ver = (p.get("version") or "").strip()
        if svc and svc != "unknown":
            label = f"{svc} {ver}".strip() if ver else svc
            if label not in seen:
                seen.add(label)
                techs.append(label)
    return techs


def get_web_ports(ports: List[Dict[str, Any]]) -> List[int]:
    return [p["port"] for p in ports if p["port"] in WEB_PORTS]


def build_web_urls(ip: str, web_ports: List[int]) -> List[str]:
    urls = []
    for port in web_ports:
        scheme = "https" if port in {443, 8443, 4443} else "http"
        if port in {80, 443}:
            urls.append(f"{scheme}://{ip}")
        else:
            urls.append(f"{scheme}://{ip}:{port}")
    return urls


# ── Mock data (nmap unavailable) ──────────────────────────────────────

_MOCK_HOSTS = [
    {"ip": "192.168.1.1",   "hostname": "gateway.local",  "status": "up"},
    {"ip": "192.168.1.5",   "hostname": "server01.local", "status": "up"},
    {"ip": "192.168.1.20",  "hostname": "dev.local",      "status": "up"},
]

_MOCK_SCAN_RESULTS: Dict[str, Dict[str, Any]] = {
    "192.168.1.1": {
        "ports": [
            {"port": 22,  "protocol": "tcp", "service": "ssh",   "version": "OpenSSH 8.4p1", "state": "open"},
            {"port": 80,  "protocol": "tcp", "service": "http",  "version": "nginx 1.18.0",   "state": "open"},
            {"port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.18.0",   "state": "open"},
        ],
        "os":     "Linux 4.15 - 5.6",
        "mac":    "00:50:56:00:00:01",
        "vendor": "VMware",
    },
    "192.168.1.5": {
        "ports": [
            {"port": 22,   "protocol": "tcp", "service": "ssh",   "version": "OpenSSH 7.9",         "state": "open"},
            {"port": 23,   "protocol": "tcp", "service": "telnet","version": "",                     "state": "open"},
            {"port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 5.7.32",         "state": "open"},
            {"port": 8080, "protocol": "tcp", "service": "http",  "version": "Apache Tomcat 9.0.4",  "state": "open"},
        ],
        "os":     "Linux 3.x|4.x",
        "mac":    "00:0C:29:AB:CD:EF",
        "vendor": "VMware",
    },
    "192.168.1.20": {
        "ports": [
            {"port": 22,   "protocol": "tcp", "service": "ssh",   "version": "OpenSSH 8.9",        "state": "open"},
            {"port": 80,   "protocol": "tcp", "service": "http",  "version": "Apache httpd 2.4.50","state": "open"},
            {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "version": "",            "state": "open"},
            {"port": 6379, "protocol": "tcp", "service": "redis", "version": "Redis 6.2.6",         "state": "open"},
        ],
        "os":     "Windows Server 2019",
        "mac":    "00:0C:29:12:34:56",
        "vendor": "VMware",
    },
}


def get_mock_hosts_for_target(target: str) -> List[Dict[str, Any]]:
    """Return mock hosts derived from the target string."""
    return _MOCK_HOSTS[:]


def get_mock_scan_result_for_ip(ip: str) -> Dict[str, Any]:
    """Return mock scan result (ports + OS + MAC) for a given IP."""
    return _MOCK_SCAN_RESULTS.get(ip, _MOCK_SCAN_RESULTS["192.168.1.1"])
