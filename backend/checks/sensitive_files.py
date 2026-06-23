from __future__ import annotations

"""Detect publicly accessible sensitive files."""

import aiohttp
from .base import finding, get, head

_PROBES: list[tuple[str, list[str] | None, str, str]] = [
    ("/.env",              ["APP_", "DB_", "SECRET", "KEY=", "PASSWORD"],
     "critical",  "Exposed .env Environment File"),
    ("/wp-config.php",     ["DB_NAME", "DB_PASSWORD", "table_prefix", "AUTH_KEY"],
     "critical",  "Exposed WordPress Configuration (wp-config.php)"),
    ("/config.php",        ["DB_HOST", "DB_USER", "DB_PASS", "database"],
     "critical",  "Exposed PHP Configuration File"),
    ("/database.yml",      ["adapter:", "database:", "password:", "username:"],
     "critical",  "Exposed Rails Database Configuration"),
    ("/config/database.yml", ["adapter:", "database:", "password:"],
     "critical",  "Exposed Rails Database Configuration"),
    ("/.htpasswd",         [":$apr1$", ":{SHA}", "$2y$"],
     "high",      "Exposed .htpasswd Credentials File"),
    ("/.htaccess",         ["RewriteEngine", "AuthType", "Require", "Options"],
     "medium",    "Exposed .htaccess File"),
    ("/web.config",        ["connectionStrings", "appSettings", "password"],
     "high",      "Exposed ASP.NET web.config"),
    ("/robots.txt",        None,
     "info",      "Robots.txt File Detected"),
    ("/sitemap.xml",       None,
     "info",      "Sitemap.xml File Detected"),
    ("/.DS_Store",         ["\x00\x00\x00\x01", "Bud1"],
     "medium",    "Exposed .DS_Store File"),
    ("/phpinfo.php",       ["PHP Version", "phpinfo()"],
     "high",      "Exposed PHPInfo Page"),
    ("/server.key",        ["BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY"],
     "critical",  "Exposed Private Key File"),
    ("/private.key",       ["BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY"],
     "critical",  "Exposed Private Key File"),
    ("/id_rsa",            ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
     "critical",  "Exposed SSH Private Key"),
    ("/.ssh/id_rsa",       ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
     "critical",  "Exposed SSH Private Key"),
    ("/composer.json",     ["require", "name", "version"],
     "info",      "Exposed composer.json"),
    ("/package.json",      ["dependencies", "devDependencies", "scripts"],
     "info",      "Exposed package.json"),
    ("/Dockerfile",        ["FROM ", "RUN ", "EXPOSE ", "ENV "],
     "medium",    "Exposed Dockerfile"),
    ("/docker-compose.yml", ["version:", "services:", "image:", "ports:"],
     "medium",    "Exposed docker-compose.yml"),
]


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    base = url.rstrip("/")
    findings = []

    for path, markers, severity, label in _PROBES:
        probe_url = base + path

        if markers is None:
            # Just check existence
            resp = await head(session, probe_url, allow_redirects=False)
            if resp is None or resp.status != 200:
                continue
            findings.append(finding(
                title=label,
                severity=severity,
                template="vectra-sensitive-file",
                url=url,
                matched_at=probe_url,
                description=f"{label} is accessible at {probe_url}.",
            ))
        else:
            resp, body = await get(session, probe_url, allow_redirects=False)
            if resp is None or body is None or resp.status != 200:
                continue
            if not any(m in body for m in markers):
                continue
            findings.append(finding(
                title=label,
                severity=severity,
                template="vectra-sensitive-file",
                url=url,
                matched_at=probe_url,
                description=(
                    f"{label} is publicly accessible at {probe_url}. "
                    "Sensitive configuration data, credentials, or source code may be exposed."
                ),
            ))

        if len(findings) >= 5:
            break

    return findings
