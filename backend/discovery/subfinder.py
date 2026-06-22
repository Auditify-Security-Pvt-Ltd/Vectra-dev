from __future__ import annotations

import asyncio
import shutil
from typing import AsyncGenerator


async def is_subfinder_available() -> bool:
    return shutil.which("subfinder") is not None


async def stream_subdomains(domain: str) -> AsyncGenerator[str, None]:
    """
    Run `subfinder -d <domain> -silent` and yield subdomains line by line.
    No timeout — supports large domains with many results.
    """
    proc = await asyncio.create_subprocess_exec(
        "subfinder", "-d", domain, "-silent",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )

    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            subdomain = line.decode("utf-8", errors="replace").strip()
            if subdomain:
                yield subdomain
    except asyncio.CancelledError:
        try:
            proc.kill()
        except Exception:
            pass
        raise
    finally:
        try:
            await proc.wait()
        except Exception:
            pass
