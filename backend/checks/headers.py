from __future__ import annotations

"""Check for missing HTTP security response headers."""

import aiohttp
from .base import finding, head

_CHECKS = [
    (
        "Content-Security-Policy",
        "content-security-policy",
        "medium",
        "vectra-missing-csp",
        "Content-Security-Policy (CSP) header is absent. This allows XSS attacks and data injection.",
    ),
    (
        "Strict-Transport-Security",
        "strict-transport-security",
        "medium",
        "vectra-missing-hsts",
        "HTTP Strict-Transport-Security (HSTS) header is not set. Connections may be downgraded to HTTP.",
    ),
    (
        "X-Frame-Options",
        "x-frame-options",
        "medium",
        "vectra-missing-xfo",
        "X-Frame-Options header is absent. The page may be embeddable in iframes enabling clickjacking.",
    ),
    (
        "X-Content-Type-Options",
        "x-content-type-options",
        "low",
        "vectra-missing-xcto",
        "X-Content-Type-Options: nosniff is not set. Browsers may MIME-sniff responses.",
    ),
    (
        "Referrer-Policy",
        "referrer-policy",
        "low",
        "vectra-missing-referrer-policy",
        "Referrer-Policy header is absent. Referrer information may leak to third-party sites.",
    ),
    (
        "Permissions-Policy",
        "permissions-policy",
        "info",
        "vectra-missing-permissions-policy",
        "Permissions-Policy header is absent. Browser feature access is unrestricted.",
    ),
]


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    resp = await head(session, url)
    if resp is None:
        return []

    findings = []
    for display_name, header_key, severity, template, description in _CHECKS:
        if header_key not in resp.headers:
            # HSTS only makes sense on HTTPS
            if header_key == "strict-transport-security" and not url.startswith("https"):
                continue
            findings.append(finding(
                title=f"Missing {display_name} Header",
                severity=severity,
                template=template,
                url=url,
                description=description,
            ))
    return findings
