from __future__ import annotations

"""Detect exposed .git repository."""

import aiohttp
from .base import finding, get

_PROBES = [
    ("/.git/HEAD",   "ref:",      "Exposed .git/HEAD"),
    ("/.git/config", "[core]",    "Exposed .git/config"),
    ("/.git/COMMIT_EDITMSG", None, "Exposed .git/COMMIT_EDITMSG"),
]


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    base = url.rstrip("/")
    findings = []

    for path, marker, label in _PROBES:
        probe_url = base + path
        resp, body = await get(session, probe_url, allow_redirects=False)
        if resp is None or resp.status != 200 or body is None:
            continue
        if marker is not None and marker not in body:
            continue
        # Confirmed: git file is accessible
        findings.append(finding(
            title="Exposed .git Repository",
            severity="critical",
            template="vectra-git-exposure",
            url=url,
            matched_at=probe_url,
            description=(
                f"{label} is publicly accessible at {probe_url}. "
                "Attackers can reconstruct the full source code and extract secrets."
            ),
        ))
        break  # one critical finding per asset is enough

    return findings
