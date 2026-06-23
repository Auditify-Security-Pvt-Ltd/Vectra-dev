from __future__ import annotations

"""Detect open directory listings."""

import aiohttp
from .base import finding, get

_PATTERNS = ["Index of /", "Directory listing for", "Parent Directory", "[To Parent Directory]"]
_PATHS = ["/", "/images/", "/img/", "/uploads/", "/upload/", "/files/", "/backup/",
          "/assets/", "/static/", "/media/", "/data/", "/docs/", "/downloads/"]


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    base = url.rstrip("/")
    findings = []

    for path in _PATHS:
        probe_url = base + path
        resp, body = await get(session, probe_url)
        if resp is None or body is None:
            continue
        if resp.status not in (200, 206):
            continue
        ct = resp.headers.get("content-type", "")
        if "text/html" not in ct and "text/plain" not in ct:
            continue
        if any(p in body for p in _PATTERNS):
            findings.append(finding(
                title="Open Directory Listing",
                severity="medium",
                template="vectra-directory-listing",
                url=url,
                matched_at=probe_url,
                description=(
                    f"Directory listing is enabled at {probe_url}. "
                    "Exposed file structure can reveal sensitive files and application internals."
                ),
            ))
            break  # one finding per asset is enough

    return findings
