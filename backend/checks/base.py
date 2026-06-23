from __future__ import annotations

"""Shared types and helpers for Vectra Security Checks."""

import asyncio
from typing import Any, Optional
import aiohttp

TIMEOUT = aiohttp.ClientTimeout(total=12, connect=5)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Vectra/1.5 Security Scanner)",
    "Accept": "*/*",
}


def finding(
    title: str,
    severity: str,
    template: str,
    url: str,
    description: str,
    matched_at: Optional[str] = None,
) -> dict:
    return {
        "source":      "vectra",
        "severity":    severity,
        "title":       title,
        "template":    template,
        "host":        url,
        "matched_at":  matched_at or url,
        "description": description,
    }


async def head(
    session: aiohttp.ClientSession,
    url: str,
    *,
    allow_redirects: bool = True,
) -> Optional[aiohttp.ClientResponse]:
    try:
        r = await session.head(url, allow_redirects=allow_redirects)
        return r
    except Exception:
        return None


async def get(
    session: aiohttp.ClientSession,
    url: str,
    *,
    allow_redirects: bool = True,
    max_size: int = 32_768,
) -> tuple[Optional[aiohttp.ClientResponse], Optional[str]]:
    """Returns (response, body_text). Body capped at max_size bytes."""
    try:
        r = await session.get(url, allow_redirects=allow_redirects)
        raw = await r.content.read(max_size)
        text = raw.decode("utf-8", errors="replace")
        return r, text
    except Exception:
        return None, None
