from __future__ import annotations

"""Detect clickjacking vulnerability (missing X-Frame-Options + no CSP frame-ancestors)."""

import aiohttp
from .base import finding, head


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    resp = await head(session, url)
    if resp is None:
        return []

    has_xfo = "x-frame-options" in resp.headers
    csp = resp.headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if not has_xfo and not has_frame_ancestors:
        return [finding(
            title="Clickjacking: Missing Frame Protection",
            severity="high",
            template="vectra-clickjacking",
            url=url,
            description=(
                "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                "Attackers can embed this page in an iframe and trick users into unintended actions."
            ),
        )]
    return []
