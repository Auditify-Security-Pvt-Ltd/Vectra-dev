from __future__ import annotations

"""Detect exposed backup files."""

import aiohttp
from .base import finding, head

_BACKUP_PATHS = [
    "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.sql",
    "/backup.gz", "/backup.bak", "/backup/",
    "/db.sql", "/dump.sql", "/database.sql",
    "/www.zip", "/site.zip", "/web.zip", "/html.zip",
    "/index.php.bak", "/index.php.old", "/index.php~",
    "/config.php.bak", "/config.php.old", "/config.bak",
    "/wp-config.php.bak", "/wp-config.php.old",
    "/.env.bak", "/.env.old", "/.env~",
    "/app.zip", "/app.tar.gz",
]


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    base = url.rstrip("/")
    findings = []

    for path in _BACKUP_PATHS:
        probe_url = base + path
        resp = await head(session, probe_url, allow_redirects=False)
        if resp is None:
            continue
        if resp.status in (200, 206):
            findings.append(finding(
                title="Exposed Backup File",
                severity="high",
                template="vectra-backup-exposure",
                url=url,
                matched_at=probe_url,
                description=(
                    f"Backup file accessible at {probe_url}. "
                    "Backup files may contain credentials, source code, and sensitive configuration."
                ),
            ))
            if len(findings) >= 3:
                break  # cap at 3 findings per asset

    return findings
