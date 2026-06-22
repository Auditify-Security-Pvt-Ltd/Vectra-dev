from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import AsyncGenerator, List, Optional


async def is_httpx_toolkit_available() -> bool:
    return shutil.which("httpx-toolkit") is not None


async def stream_probe_hosts(subdomains: List[str]) -> AsyncGenerator[dict, None]:
    """
    Feed all subdomains to httpx-toolkit via stdin and yield parsed results
    as they stream out.  httpx-toolkit processes with -threads 200 and emits
    each result immediately — no need to wait for all hosts to finish.

    Command used:
        httpx-toolkit -silent -title -status-code -tech-detect -ip -server
                      -json -threads 200
    """
    if not subdomains:
        return

    stdin_data = ("\n".join(subdomains) + "\n").encode()

    proc = await asyncio.create_subprocess_exec(
        "httpx-toolkit",
        "-silent",
        "-title",
        "-status-code",
        "-tech-detect",
        "-ip",
        "-server",
        "-json",
        "-threads", "200",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )

    # Write stdin in a background task so stdout reads concurrently
    async def _write_stdin() -> None:
        try:
            proc.stdin.write(stdin_data)
            await proc.stdin.drain()
        except Exception:
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

    write_task = asyncio.create_task(_write_stdin())

    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            raw = line.decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            try:
                data = json.loads(raw)
                yield _parse_result(data)
            except json.JSONDecodeError:
                continue

    except asyncio.CancelledError:
        try:
            proc.kill()
        except Exception:
            pass
        raise

    finally:
        write_task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(write_task), timeout=2.0)
        except Exception:
            pass
        try:
            await proc.wait()
        except Exception:
            pass


# ── Parsers ───────────────────────────────────────────────────────────

def _parse_result(data: dict) -> dict:
    """Normalise httpx-toolkit JSON output — field names vary across versions."""
    webserver_raw = (
        data.get("webserver")
        or data.get("web-server")
        or data.get("server")
    )

    # Base technologies from Wappalyzer (names only, no versions)
    techs = _parse_tech(data.get("tech") or data.get("technologies") or [])

    # Extract version from Server header (e.g. "nginx/1.18.0", "Apache/2.4.49")
    # and inject a versioned entry so the CVE pipeline can match it
    if webserver_raw:
        versioned = _extract_server_version(webserver_raw)
        if versioned:
            techs = _merge_versioned_tech(techs, versioned)

    return {
        "input":       data.get("input", ""),
        "url":         data.get("url") or data.get("input", ""),
        "statusCode":  data.get("status_code") or data.get("status-code"),
        "title":       data.get("title") or data.get("page-title"),
        "server":      webserver_raw,
        "ip":          data.get("ip") or data.get("host"),
        "contentType": _clean_ct(
            data.get("content_type") or data.get("content-type")
        ),
        "technologies": techs,
    }


def _parse_tech(raw) -> List[str]:
    """
    Normalise the tech-detect field.

    httpx-toolkit can return:
      - list of strings:  ["Nginx", "Bootstrap:5.1"]
      - dict with versions: {"nginx": "1.21.6", "react": ""}
      - comma-separated string: "Nginx,Bootstrap"
    """
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if t]
    if isinstance(raw, dict):
        result = []
        for k, v in raw.items():
            if not k:
                continue
            result.append(f"{k}:{v}" if v else k)
        return result
    if isinstance(raw, str):
        return [t.strip() for t in raw.split(",") if t.strip()]
    return []


def _extract_server_version(server_header: str) -> Optional[str]:
    """
    Extract a versioned tech string from the Server header.

    Examples:
      "nginx/1.18.0"          → "nginx:1.18.0"
      "Apache/2.4.49 (Ubuntu)"→ "Apache:2.4.49"
      "Apache-Coyote/1.1"     → "Apache Tomcat:1.1"  (basic heuristic)
      "nginx"                 → None  (no version)
    """
    if not server_header:
        return None
    m = re.match(r"^([A-Za-z0-9_.+\- ]+?)/(\d+(?:\.\d+)+)", server_header.strip())
    if not m:
        return None
    name_raw = m.group(1).strip().lower()
    version  = m.group(2)

    # Map common server header names to normalised names
    _NAME_MAP = {
        "apache":         "Apache",
        "nginx":          "nginx",
        "openssl":        "OpenSSL",
        "microsoft-iis":  "Microsoft-IIS",
        "lighttpd":       "lighttpd",
        "litespeed":      "LiteSpeed",
        "apache-coyote":  "Apache Tomcat",
    }
    name = _NAME_MAP.get(name_raw, m.group(1).strip())
    return f"{name}:{version}"


def _merge_versioned_tech(techs: List[str], versioned: str) -> List[str]:
    """
    Replace the unversioned entry matching `versioned` with the versioned one.

    If "nginx:1.18.0" is to be added, remove bare "Nginx" from the list first
    (case-insensitive) so we don't duplicate.
    """
    base_name = versioned.split(":")[0].lower()
    merged    = [t for t in techs if t.split(":")[0].lower() != base_name]
    merged.append(versioned)
    return merged


def _clean_ct(ct: Optional[str]) -> Optional[str]:
    """Strip charset/params: 'text/html; charset=utf-8' → 'text/html'."""
    if not ct:
        return None
    return ct.split(";")[0].strip()
