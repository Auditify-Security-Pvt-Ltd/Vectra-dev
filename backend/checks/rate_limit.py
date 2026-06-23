from __future__ import annotations

"""Check for missing API rate limiting."""

import asyncio
import aiohttp
from .base import finding

_RATELIMIT_HEADERS = [
    "x-ratelimit-limit", "x-rate-limit-limit",
    "x-ratelimit-remaining", "x-rate-limit-remaining",
    "ratelimit-limit", "ratelimit-remaining",
    "retry-after", "x-retry-after",
]
_BURST = 6


async def run(url: str, session: aiohttp.ClientSession) -> list[dict]:
    statuses: list[int] = []
    has_rl_headers = False

    async def _req() -> None:
        nonlocal has_rl_headers
        try:
            resp = await session.head(url, allow_redirects=True)
            statuses.append(resp.status)
            if any(h in resp.headers for h in _RATELIMIT_HEADERS):
                has_rl_headers = True
        except Exception:
            pass

    # Fire _BURST concurrent requests
    await asyncio.gather(*[_req() for _ in range(_BURST)])

    if has_rl_headers:
        return []  # rate limiting is in place

    successes = sum(1 for s in statuses if s < 400)
    if successes < _BURST - 1:
        return []  # most requests failed — not a rate-limit issue

    # All requests succeeded and no rate-limit headers found
    return [finding(
        title="Missing API Rate Limiting",
        severity="low",
        template="vectra-missing-rate-limit",
        url=url,
        description=(
            f"{successes}/{_BURST} rapid requests returned success with no rate-limit headers. "
            "Without rate limiting, the endpoint is susceptible to brute-force and enumeration attacks."
        ),
    )]
