from __future__ import annotations

"""WPScan integration — runs when WordPress is detected on a target."""

import asyncio
import json
import shutil
from typing import AsyncGenerator, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

_WP_TECH_NAMES = {"wordpress", "wp", "wordpress.com"}


def is_wpscan_available() -> bool:
    return shutil.which("wpscan") is not None


def is_wordpress(technologies: List[str]) -> bool:
    """Return True if WordPress is in the detected technologies list."""
    for t in technologies:
        name = t.split(":")[0].lower().strip()
        if name in _WP_TECH_NAMES:
            return True
    return False


def _parse_wpscan_line(line: str) -> Optional[dict]:
    """
    Parse a WPScan JSON output line into a finding dict.
    WPScan's --format json outputs one large JSON object at the end,
    not JSONL — this handles both modes.
    """
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    # WPScan summary object — extract top-level vulnerabilities
    if isinstance(data, dict) and "version" in data:
        return _parse_wpscan_summary(data)
    return None


def _parse_wpscan_summary(data: dict) -> Optional[dict]:
    """Not used directly — see stream_wpscan for summary parsing."""
    return None


def _vuln_to_finding(vuln: dict, context: str, url: str) -> dict:
    title = vuln.get("title", "WordPress Vulnerability")
    refs = vuln.get("references", {})
    cve_list = refs.get("cve", [])
    cve_str = ", ".join(f"CVE-{c}" for c in cve_list) if cve_list else ""
    cvss = vuln.get("cvss", {}).get("score")

    sev = "high"
    if cvss is not None:
        score = float(cvss)
        if score >= 9.0:
            sev = "critical"
        elif score >= 7.0:
            sev = "high"
        elif score >= 4.0:
            sev = "medium"
        else:
            sev = "low"

    desc_parts = [f"WordPress {context} vulnerability: {title}"]
    if cve_str:
        desc_parts.append(f"CVEs: {cve_str}")
    if cvss:
        desc_parts.append(f"CVSS: {cvss}")
    fixed = vuln.get("fixed_in")
    if fixed:
        desc_parts.append(f"Fixed in: {fixed}")

    return {
        "source":      "wpscan",
        "severity":    sev,
        "title":       f"WPScan: {title}",
        "template":    "wpscan-vulnerability",
        "host":        url,
        "matched_at":  url,
        "description": " | ".join(desc_parts),
    }


async def stream_wpscan(url: str) -> AsyncGenerator[dict, None]:
    """
    Run WPScan against a WordPress URL and yield findings as they are parsed.
    WPScan is invoked with --format json so we get structured output.
    Gracefully handles WPScan being broken or absent.
    """
    if not is_wpscan_available():
        logger.warning("[WPScan] wpscan binary not found — skipping")
        return

    cmd = [
        "wpscan",
        "--url", url,
        "--format", "json",
        "--no-banner",
        "--disable-tls-checks",
        "--enumerate", "vp,vt,u",   # vulnerable plugins, vulnerable themes, users
        "--plugins-detection", "passive",
    ]

    logger.info(f"[WPScan] Running: {' '.join(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as exc:
        logger.error(f"[WPScan] Failed to start process: {exc}")
        return

    stdout_data = b""
    try:
        stdout_data, stderr_data = await asyncio.wait_for(
            process.communicate(), timeout=180
        )
    except asyncio.TimeoutError:
        logger.warning("[WPScan] Timed out after 180s")
        try:
            process.kill()
        except Exception:
            pass
        return
    except asyncio.CancelledError:
        try:
            process.kill()
        except Exception:
            pass
        raise
    except Exception as exc:
        logger.error(f"[WPScan] Error during scan: {exc}")
        return

    if not stdout_data:
        logger.info("[WPScan] No output produced (may have crashed or be broken)")
        return

    try:
        result = json.loads(stdout_data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        logger.warning("[WPScan] Could not parse JSON output")
        return

    if not isinstance(result, dict):
        return

    # WordPress version vulnerabilities
    wp_version = result.get("version") or {}
    if isinstance(wp_version, dict):
        ver_str = wp_version.get("number", "unknown")
        for vuln in wp_version.get("vulnerabilities", []):
            yield _vuln_to_finding(vuln, f"Core {ver_str}", url)

    # Plugin vulnerabilities
    plugins = result.get("plugins") or {}
    for plugin_slug, plugin_data in plugins.items():
        if not isinstance(plugin_data, dict):
            continue
        for vuln in plugin_data.get("vulnerabilities", []):
            yield _vuln_to_finding(vuln, f"Plugin {plugin_slug}", url)

    # Theme vulnerabilities
    themes = result.get("themes") or {}
    for theme_slug, theme_data in themes.items():
        if not isinstance(theme_data, dict):
            continue
        for vuln in theme_data.get("vulnerabilities", []):
            yield _vuln_to_finding(vuln, f"Theme {theme_slug}", url)

    # Users enumerated → low severity info finding
    users = result.get("users") or {}
    if users:
        user_list = ", ".join(str(u) for u in list(users.keys())[:5])
        yield {
            "source":      "wpscan",
            "severity":    "medium",
            "title":       "WPScan: WordPress User Enumeration",
            "template":    "wpscan-user-enum",
            "host":        url,
            "matched_at":  url,
            "description": (
                f"WordPress user enumeration found {len(users)} user(s): {user_list}. "
                "Exposed usernames can be used in targeted brute-force attacks."
            ),
        }

    logger.info(f"[WPScan] Scan complete for {url}")
