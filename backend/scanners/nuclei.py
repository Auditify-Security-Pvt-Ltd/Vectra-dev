from __future__ import annotations

import asyncio
import json
import shutil
from typing import AsyncGenerator, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


def is_nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def _parse_nuclei_line(line: str) -> Optional[dict]:
    """Parse a single JSONL line from nuclei stdout into a finding dict."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        logger.debug(f"Skipping non-JSON line: {line[:120]}")
        return None

    info = data.get("info", {})
    return {
        "severity": info.get("severity", "unknown").lower(),
        "title": info.get("name", "Unknown"),
        "template": data.get("template-id", "unknown"),
        "host": data.get("host"),
        "matched_at": data.get("matched-at"),
        "description": info.get("description"),
    }


async def stream_nuclei_scan(
    target: str,
    profile: str = "FULL_SCAN",
) -> AsyncGenerator[dict, None]:
    """
    Async generator that yields one finding dict per Nuclei match as it arrives.
    No timeout — long-running scans (10m, 30m, 1h) are fully supported.
    The caller cancels the scan by cancelling the enclosing asyncio task.
    """
    if not is_nuclei_available():
        logger.warning("Nuclei binary not found in PATH")
        return

    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-no-color", "-t" ,"/home/kali/Desktop/vectra/backend/Private-Nuclei-Templates" ]
    if profile == "QUICK_SCAN":
        cmd.extend([])
    elif profile == "WEB_SCAN":
        cmd.extend(["-tags", "cves,vulnerabilities"])
    # FULL_SCAN: no tag filter — all templates

    logger.info(f"Streaming [{profile}]: {' '.join(cmd)}")

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            finding = _parse_nuclei_line(line.decode("utf-8", errors="replace"))
            if finding:
                yield finding
    except asyncio.CancelledError:
        process.kill()
        await process.wait()
        raise
    finally:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass


def parse_nuclei_output(output: str) -> list[dict]:
    """Parse a complete nuclei JSONL output string — kept for testing utilities."""
    findings = []
    for line in output.splitlines():
        finding = _parse_nuclei_line(line)
        if finding:
            findings.append(finding)
    return findings
