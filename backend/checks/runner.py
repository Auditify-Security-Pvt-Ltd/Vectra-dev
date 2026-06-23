from __future__ import annotations

"""Run all Vectra Security Checks against a single URL."""

import asyncio
from typing import List

import aiohttp

from .base import TIMEOUT, HEADERS
from . import (
    headers,
    clickjacking,
    directory_listing,
    git_exposure,
    backup_files,
    swagger,
    admin_panels,
    debug_endpoints,
    rate_limit,
    sensitive_files,
)

_CHECKS = [
    headers,
    clickjacking,
    directory_listing,
    git_exposure,
    backup_files,
    swagger,
    admin_panels,
    debug_endpoints,
    rate_limit,
    sensitive_files,
]


async def run_checks(url: str, session: aiohttp.ClientSession) -> List[dict]:
    """Run all 10 checks concurrently against `url`. Never raises."""
    tasks = [m.run(url, session) for m in _CHECKS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings: List[dict] = []
    for r in results:
        if isinstance(r, list):
            findings.extend(r)
    return findings


async def run_checks_on_assets(assets: List[dict]) -> List[dict]:
    """
    Create one shared aiohttp session and run all checks on all live assets.
    Returns the combined finding list.
    """
    connector = aiohttp.TCPConnector(ssl=False, limit=50)
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=TIMEOUT,
        headers=HEADERS,
    ) as session:
        tasks = [run_checks(asset["url"] or f"https://{asset['subdomain']}", session)
                 for asset in assets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: List[dict] = []
    for r in results:
        if isinstance(r, list):
            all_findings.extend(r)
    return all_findings
