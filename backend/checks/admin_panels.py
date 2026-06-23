from __future__ import annotations

"""Detect exposed admin panels."""

import aiohttp
from .base import finding, get

_PATHS = [
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin/login.php",
    "/administrator",
    "/administrator/",
    "/wp-admin/",
    "/wp-login.php",
    "/phpmyadmin/",
    "/phpmyadmin",
    "/pma/",
    "/pma",
    "/cpanel",
    "/cpanel/",
    "/panel",
    "/panel/",
    "/controlpanel",
    "/manager/html",
    "/manager/",
    "/admin.php",
    "/admincp/",
    "/admin_area/",
    "/site/admin",
    "/superadmin/",
    "/siteadmin/",
    "/webadmin/",
]

_ADMIN_MARKERS = [
    "admin", "login", "password", "username", "sign in", "log in",
    "phpmyadmin", "cpanel", "control panel", "dashboard",
    "administrator", "管理", "管理員",
]


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    base = url.rstrip("/")
    findings = []
    seen_paths: set[str] = set()

    for path in _PATHS:
        probe_url = base + path
        resp, body = await get(session, probe_url)
        if resp is None or body is None:
            continue
        # 200 → accessible, 401/403 → protected but exists, 302 to login → exists
        if resp.status not in (200, 201, 401, 403):
            continue
        if body and not any(m.lower() in body.lower() for m in _ADMIN_MARKERS):
            continue
        canonical = str(resp.url) if hasattr(resp, "url") else probe_url
        if canonical in seen_paths:
            continue
        seen_paths.add(canonical)

        sev = "high" if resp.status == 200 else "medium"
        access_note = "accessible without authentication" if resp.status == 200 else "exists (protected)"
        findings.append(finding(
            title="Admin Panel Detected",
            severity=sev,
            template="vectra-admin-panel",
            url=url,
            matched_at=probe_url,
            description=(
                f"Admin panel is {access_note} at {probe_url}. "
                "Exposed admin interfaces are high-value targets for brute-force and credential stuffing attacks."
            ),
        ))
        if len(findings) >= 2:
            break

    return findings
