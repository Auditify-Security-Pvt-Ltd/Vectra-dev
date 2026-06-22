from __future__ import annotations

import asyncio
import json
import shutil
from typing import Optional


async def is_httpx_available() -> bool:
    return shutil.which("httpx") is not None


async def probe_host(subdomain: str, timeout: int = 15) -> Optional[dict]:
    """
    Run httpx on a single subdomain and return parsed metadata if alive.
    Returns None if the host is unreachable or httpx produces no output.
    """
    proc = await asyncio.create_subprocess_exec(
        "httpx",
        "-u", subdomain,
        "-title",
        "-status-code",
        "-ip",
        "-server",
        "-content-type",
        "-json",
        "-silent",
        "-timeout", str(timeout),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return None

    if not stdout:
        return None

    for raw_line in stdout.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            return {
                "alive": True,
                # httpx JSON field names vary by version — try all known variants
                "statusCode": data.get("status_code") or data.get("status-code"),
                "title": data.get("title") or data.get("page-title"),
                "server": (
                    data.get("webserver")
                    or data.get("web-server")
                    or data.get("server")
                ),
                "ip": data.get("ip") or data.get("a"),
                "contentType": _clean_ct(
                    data.get("content_type") or data.get("content-type")
                ),
                "technologies": data.get("technologies") or data.get("tech") or [],
                "url": data.get("url") or data.get("input") or f"http://{subdomain}",
            }
        except json.JSONDecodeError:
            continue

    return None


def _clean_ct(ct: Optional[str]) -> Optional[str]:
    """Strip charset params: 'text/html; charset=utf-8' → 'text/html'."""
    if not ct:
        return None
    return ct.split(";")[0].strip()
