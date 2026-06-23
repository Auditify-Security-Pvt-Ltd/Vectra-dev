from __future__ import annotations

"""Detect exposed debug and diagnostic endpoints."""

import aiohttp
from .base import finding, get

_PROBES: list[tuple[str, list[str], str]] = [
    ("/.env",            ["APP_KEY", "DB_PASSWORD", "SECRET_KEY", "DATABASE_URL", "AWS_SECRET"],
     "Exposed .env File"),
    ("/phpinfo.php",     ["phpinfo()", "PHP Version", "php.ini", "Server API"],
     "Exposed PHPInfo Page"),
    ("/test.php",        ["phpinfo()", "PHP Version", "echo"],
     "Exposed Test PHP Script"),
    ("/info.php",        ["phpinfo()", "PHP Version"],
     "Exposed PHPInfo Page"),
    ("/_profiler",       ["sf-toolbar", "Symfony Profiler", "Time"],
     "Exposed Symfony Profiler"),
    ("/_profiler/latest", ["sf-toolbar", "Symfony", "Time"],
     "Exposed Symfony Profiler"),
    ("/actuator",        ["_links", "health", "info", "beans"],
     "Exposed Spring Boot Actuator"),
    ("/actuator/env",    ["activeProfiles", "propertySources", "systemProperties"],
     "Exposed Spring Boot Actuator /env"),
    ("/actuator/health", ["status", "UP", "DOWN"],
     "Exposed Spring Boot Actuator /health"),
    ("/actuator/beans",  ["beans", "scope", "singleton"],
     "Exposed Spring Boot Actuator /beans"),
    ("/debug/",          ["debug", "trace", "stacktrace"],
     "Exposed Debug Endpoint"),
    ("/__debug__",       ["DebugToolbar", "django-debug-toolbar"],
     "Exposed Django Debug Toolbar"),
    ("/console",         ["REPL", "console", "eval", "Werkzeug"],
     "Exposed Debug Console"),
    ("/server-status",   ["Apache Server Status", "Total Accesses", "Uptime"],
     "Exposed Apache Server Status"),
    ("/nginx_status",    ["Active connections:", "server accepts"],
     "Exposed Nginx Status Page"),
    ("/server-info",     ["Apache Server Information", "Module Name"],
     "Exposed Apache Server Information"),
    ("/trace",           ["TRACE", "X-Custom-Header"],
     "HTTP TRACE Method Enabled"),
]

_SEVERITY_MAP = {
    "Exposed .env File": "critical",
    "Exposed PHPInfo Page": "high",
    "Exposed Test PHP Script": "medium",
    "Exposed Symfony Profiler": "high",
    "Exposed Spring Boot Actuator /env": "critical",
    "Exposed Spring Boot Actuator": "high",
    "Exposed Spring Boot Actuator /health": "medium",
    "Exposed Spring Boot Actuator /beans": "high",
    "Exposed Django Debug Toolbar": "high",
    "Exposed Debug Console": "critical",
    "Exposed Debug Endpoint": "medium",
    "Exposed Apache Server Status": "medium",
    "Exposed Nginx Status Page": "medium",
    "Exposed Apache Server Information": "medium",
    "HTTP TRACE Method Enabled": "low",
}


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    base = url.rstrip("/")
    findings = []

    for path, markers, label in _PROBES:
        probe_url = base + path
        resp, body = await get(session, probe_url, allow_redirects=False)
        if resp is None or body is None:
            continue
        if resp.status not in (200, 206):
            continue
        if not any(m in body for m in markers):
            continue
        sev = _SEVERITY_MAP.get(label, "medium")
        findings.append(finding(
            title=label,
            severity=sev,
            template="vectra-debug-endpoint",
            url=url,
            matched_at=probe_url,
            description=(
                f"{label} is publicly accessible at {probe_url}. "
                "Debug endpoints can leak sensitive environment data, application internals, and secrets."
            ),
        ))
        if len(findings) >= 4:
            break

    return findings
