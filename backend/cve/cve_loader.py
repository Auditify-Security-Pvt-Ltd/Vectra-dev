from __future__ import annotations

"""
CVE Loader — loads all local JSON CVE databases at import time.

Indexes built in memory:
  _by_tech_version  : "technology_lower:version" → [cve, ...]
  _by_tech          : "technology_lower"          → [cve, ...]
  _by_id            : "CVE-XXXX-XXXXX"            → cve

Exported API:
  lookup(tech, version) → List[dict]   (nvd_client schema)
  lookup_by_id(cve_id)  → Optional[dict]
  all_cves()            → List[dict]
  stats()               → dict
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────
_DATA_DIR = Path(__file__).parent.parent / "data" / "cves"

_DB_FILES = [
    "apache.json",
    "nginx.json",
    "wordpress.json",
    "wordpress_plugins.json",
    "php.json",
    "laravel.json",
    "openssh.json",
    "jenkins.json",
    "gitlab.json",
    "docker.json",
    "kubernetes.json",
    "mysql.json",
    "redis.json",
    "mongodb.json",
    "spring.json",
]

# ── Tech name normalisation ───────────────────────────────────────────
_ALIASES: dict[str, str] = {
    "apache http server": "apache",
    "apache-http-server": "apache",
    "httpd": "apache",
    "apache httpd": "apache",
    "tomcat": "apache tomcat",
    "apache tomcat": "apache tomcat",
    "wp": "wordpress",
    "woocommerce": "wordpress",
    "spring framework": "spring",
    "spring boot": "spring",
    "spring security": "spring",
    "spring cloud": "spring",
    "nginx": "nginx",
    "openssh-server": "openssh",
    "libssl": "openssl",
    "openssl": "openssl",
    "mysql server": "mysql",
    "mariadb": "mysql",
    "node.js": "nodejs",
    "nodejs": "nodejs",
}


def _norm(name: str) -> str:
    n = name.lower().strip()
    for prefix in ("lib", "mod_"):
        if n.startswith(prefix):
            n = n[len(prefix):]
    return _ALIASES.get(n, n)


# ── Internal schema conversion ────────────────────────────────────────
_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "none":     "NONE",
}


def _to_output(raw: dict, tech_name: str, version: str) -> dict:
    """Convert JSON file schema → nvd_client output schema."""
    sev = _SEVERITY_MAP.get(str(raw.get("severity", "NONE")).lower(), "NONE")
    return {
        "cveId":            raw["cveId"],
        "technology":       tech_name,
        "version":          version,
        "severity":         sev,
        "cvssScore":        float(raw.get("cvss", 0.0)),
        "description":      raw.get("description", ""),
        "references":       raw.get("references", []),
        "exploitAvailable": bool(raw.get("exploitAvailable", False)),
        "published":        raw.get("published", ""),
    }


# ── Indexes ───────────────────────────────────────────────────────────
_by_tech_version: Dict[str, List[dict]] = {}   # "tech_lower:version" → raw CVEs
_by_tech:         Dict[str, List[dict]] = {}   # "tech_lower"         → raw CVEs
_by_id:           Dict[str, dict]       = {}   # "CVE-XXXX-XXXXX"     → raw CVE
_all_raw:         List[dict]            = []


def _load() -> None:
    total = 0
    tech_counts: dict[str, int] = {}

    for fname in _DB_FILES:
        fpath = _DATA_DIR / fname
        if not fpath.exists():
            logger.warning(f"[CVE Loader] Missing file: {fpath}")
            continue

        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                entries = json.load(fh)
        except Exception as exc:
            logger.error(f"[CVE Loader] Failed to parse {fname}: {exc}")
            continue

        for raw in entries:
            if not isinstance(raw, dict):
                continue
            cve_id = raw.get("cveId", "")
            if not cve_id or not cve_id.startswith("CVE-"):
                continue
            tech = str(raw.get("technology", "")).strip()
            if not tech:
                continue

            tech_norm = _norm(tech)
            affected  = raw.get("affectedVersions", [])
            if not isinstance(affected, list):
                affected = []

            # Register in _by_id
            if cve_id not in _by_id:
                _by_id[cve_id] = raw

            # Register in _by_tech
            _by_tech.setdefault(tech_norm, []).append(raw)

            # Register in _by_tech_version for each affected version
            for ver in affected:
                key = f"{tech_norm}:{ver}"
                _by_tech_version.setdefault(key, []).append(raw)

            _all_raw.append(raw)
            total += 1
            tech_counts[tech_norm] = tech_counts.get(tech_norm, 0) + 1

    logger.info(
        f"[CVE Loader] Loaded {total} CVEs across {len(tech_counts)} technologies "
        f"({', '.join(f'{k}:{v}' for k, v in sorted(tech_counts.items()))})"
    )


# Load at import time
_load()


# ── Public API ────────────────────────────────────────────────────────

def lookup(tech_name: str, version: str) -> List[dict]:
    """
    Return CVEs for tech+version.
    Tries:
      1. Exact version match      (e.g. "apache:2.4.49")
      2. Wildcard match           (e.g. "apache:*")
      3. Major.minor match        (e.g. "apache:2.4")
      4. Major match              (e.g. "apache:2")
    All matched CVEs from _by_tech_version are deduplicated by cveId.
    """
    norm = _norm(tech_name)
    ver_parts = version.split(".")

    candidates = [version]                           # exact
    if "*" not in candidates:
        candidates.append("*")                       # wildcard
    if len(ver_parts) >= 2:
        candidates.append(".".join(ver_parts[:2]))   # major.minor
    if len(ver_parts) >= 1 and ver_parts[0] not in candidates:
        candidates.append(ver_parts[0])              # major

    seen: set[str] = set()
    results: list[dict] = []

    for cand in candidates:
        key = f"{norm}:{cand}"
        for raw in _by_tech_version.get(key, []):
            cid = raw.get("cveId", "")
            if cid and cid not in seen:
                seen.add(cid)
                results.append(_to_output(raw, tech_name, version))

    if results:
        results.sort(key=lambda x: x["cvssScore"], reverse=True)
        logger.info(f"[CVE Loader] {tech_name} {version} → {len(results)} CVEs")

    return results


def lookup_by_id(cve_id: str) -> Optional[dict]:
    raw = _by_id.get(cve_id)
    if raw:
        tech = raw.get("technology", "")
        return _to_output(raw, tech, "")
    return None


def all_cves() -> List[dict]:
    return [_to_output(r, r.get("technology", ""), "") for r in _all_raw]


def stats() -> dict:
    by_tech: dict[str, int] = {}
    by_sev:  dict[str, int] = {}
    for raw in _all_raw:
        t = _norm(raw.get("technology", "unknown"))
        s = str(raw.get("severity", "NONE")).upper()
        by_tech[t] = by_tech.get(t, 0) + 1
        by_sev[s]  = by_sev.get(s, 0) + 1
    return {
        "total":         len(_all_raw),
        "by_technology": by_tech,
        "by_severity":   by_sev,
    }
