from __future__ import annotations

import asyncio
import re
import shutil
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# Ports that indicate a web-accessible service
WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 4443})


def is_nmap_available() -> bool:
    return shutil.which("nmap") is not None


# ── Grepable-output parsers ───────────────────────────────────────────

_HOST_RE    = re.compile(r"^Host:\s+(\S+)\s+\(([^)]*)\)\s+Status:\s+(\w+)", re.MULTILINE)
_PORTS_LINE = re.compile(r"^Host:\s+(\S+)[^\t]*\tPorts:\s+([^\t\n]+)", re.MULTILINE)
_PORT_ENTRY = re.compile(r"(\d+)/open/(\w+)//([^/]*)//([^/]*)/")


def _parse_hosts(output: str) -> List[Dict[str, Any]]:
    hosts = []
    for m in _HOST_RE.finditer(output):
        ip, hostname, status = m.group(1), m.group(2).strip(), m.group(3)
        hosts.append({
            "ip":       ip,
            "hostname": hostname or None,
            "status":   "up" if status.lower() == "up" else "down",
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


# ── Low-level runner ──────────────────────────────────────────────────

async def _nmap(*args: str) -> str:
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
) -> List[Dict[str, Any]]:
    """Port + service version scan for a single host."""
    port_arg = "-p-" if full_scan else "--top-ports=1000"
    output = await _nmap(
        "-Pn", "-sV", "--open",
        port_arg, "--version-intensity=5",
        ip, "-oG", "-",
    )
    by_ip = _parse_ports(output)
    return by_ip.get(ip, [])


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

_MOCK_PORTS: Dict[str, List[Dict[str, Any]]] = {
    "192.168.1.1": [
        {"port": 22,  "protocol": "tcp", "service": "ssh",   "version": "OpenSSH 8.4p1", "state": "open"},
        {"port": 80,  "protocol": "tcp", "service": "http",  "version": "nginx 1.18.0",   "state": "open"},
        {"port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.18.0",   "state": "open"},
    ],
    "192.168.1.5": [
        {"port": 22,   "protocol": "tcp", "service": "ssh",   "version": "OpenSSH 7.9",        "state": "open"},
        {"port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 5.7.32",        "state": "open"},
        {"port": 8080, "protocol": "tcp", "service": "http",  "version": "Apache Tomcat 9.0.4", "state": "open"},
    ],
    "192.168.1.20": [
        {"port": 22,  "protocol": "tcp", "service": "ssh",   "version": "OpenSSH 8.9",       "state": "open"},
        {"port": 80,  "protocol": "tcp", "service": "http",  "version": "Apache httpd 2.4.50","state": "open"},
        {"port": 6379,"protocol": "tcp", "service": "redis", "version": "Redis 6.2.6",        "state": "open"},
    ],
}


def get_mock_hosts_for_target(target: str) -> List[Dict[str, Any]]:
    """Return mock hosts derived from the target string."""
    return _MOCK_HOSTS[:]


def get_mock_ports_for_ip(ip: str) -> List[Dict[str, Any]]:
    return _MOCK_PORTS.get(ip, _MOCK_PORTS.get("192.168.1.1", []))
