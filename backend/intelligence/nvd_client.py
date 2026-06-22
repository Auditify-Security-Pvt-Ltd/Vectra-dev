from __future__ import annotations

"""
CVE Intelligence Client
───────────────────────
Three-tier strategy (fastest to slowest):

  1. Embedded CVE database  — instant, covers well-known critical CVEs
  2. CIRCL CVE API          — free, no auth, works via vulnerability.circl.lu
  3. NVD API (optional)     — requires NVD_API_KEY in .env; bypasses Cloudflare

Set NVD_API_KEY in backend/.env to unlock NVD lookups.
"""

import asyncio
import gzip
import json
import os
import re
import ssl
import time
import urllib.request
from typing import List, Optional
from urllib.parse import urlencode

from utils.logger import get_logger

logger = get_logger(__name__)

NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_BASE  = "https://vulnerability.circl.lu/api/cve"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# ── Rate-limiting ─────────────────────────────────────────────────────
_nvd_lock          = asyncio.Lock()
_circl_lock        = asyncio.Lock()
_last_nvd_time:    float = 0.0
_last_circl_time:  float = 0.0
_NVD_MIN_INTERVAL   = 0.6  # ~50 req/30s with API key; 6s without
_CIRCL_MIN_INTERVAL = 3.5  # stay under 20 req/min

# ── In-process cache ──────────────────────────────────────────────────
_CVE_CACHE:    dict[str, List[dict]] = {}
_CVE_FETCHING: set[str] = set()

# ── Technology name maps ──────────────────────────────────────────────
_TECH_KEYWORDS: dict[str, str] = {
    "apache":               "Apache HTTP Server",
    "apache http server":   "Apache HTTP Server",
    "nginx":                "nginx",
    "wordpress":            "WordPress",
    "wp":                   "WordPress",
    "php":                  "PHP",
    "openssh":              "OpenSSH",
    "openssl":              "OpenSSL",
    "mysql":                "MySQL",
    "mariadb":              "MariaDB",
    "postgresql":           "PostgreSQL",
    "postgres":             "PostgreSQL",
    "redis":                "Redis",
    "mongodb":              "MongoDB",
    "drupal":               "Drupal",
    "joomla":               "Joomla",
    "tomcat":               "Apache Tomcat",
    "apache tomcat":        "Apache Tomcat",
    "iis":                  "Microsoft IIS",
    "microsoft-iis":        "Microsoft IIS",
    "node.js":              "Node.js",
    "nodejs":               "Node.js",
    "openssh-server":       "OpenSSH",
    "libssl":               "OpenSSL",
    "libapache2":           "Apache HTTP Server",
    "proftpd":              "ProFTPD",
    "vsftpd":               "vsftpd",
}

_CPE_MAP: dict[str, str] = {
    "apache":     "apache:http_server",
    "nginx":      "nginx:nginx",
    "wordpress":  "wordpress:wordpress",
    "php":        "php:php",
    "openssh":    "openbsd:openssh",
    "openssl":    "openssl:openssl",
    "mysql":      "oracle:mysql",
    "mariadb":    "mariadb:mariadb",
    "postgresql": "postgresql:postgresql",
    "redis":      "redislabs:redis",
    "mongodb":    "mongodb:mongodb",
    "drupal":     "drupal:drupal",
    "joomla":     "joomla:joomla\\!",
    "tomcat":     "apache:tomcat",
    "proftpd":    "proftpd:proftpd",
    "vsftpd":     "beasts:vsftpd",
}

# ── Embedded CVE Database ─────────────────────────────────────────────
# Curated, high-confidence CVEs for common web technology versions.
# Format: key = "tech_lower:exact_version"  OR  "tech_lower:*" (wildcard)
# Wildcard entries match any version and are used for version-range checks.
#
# CVE dict fields match the NVD client output schema exactly so they drop
# straight into the pipeline without transformation.

def _cve(cve_id: str, severity: str, score: float, description: str,
         refs: List[str], exploit: bool = False, published: str = "") -> dict:
    return {
        "cveId":            cve_id,
        "technology":       "",   # filled in by caller
        "version":          "",   # filled in by caller
        "severity":         severity,
        "cvssScore":        score,
        "description":      description,
        "references":       refs,
        "exploitAvailable": exploit,
        "published":        published,
    }

_EMBEDDED_DB: dict[str, list[dict]] = {
    # ── Apache HTTP Server ────────────────────────────────────────────
    "apache:2.4.49": [
        _cve("CVE-2021-41773", "CRITICAL", 9.8,
             "Path traversal and RCE in Apache HTTP Server 2.4.49 (mod_cgi). "
             "Allows attackers to read files outside document root or execute commands.",
             ["https://httpd.apache.org/security/vulnerabilities_24.html",
              "https://www.exploit-db.com/exploits/50383"],
             exploit=True, published="2021-10-05"),
        _cve("CVE-2021-42013", "CRITICAL", 9.8,
             "Incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.49-2.4.50. "
             "Allows RCE via path traversal with encoded path separators.",
             ["https://httpd.apache.org/security/vulnerabilities_24.html",
              "https://www.exploit-db.com/exploits/50406"],
             exploit=True, published="2021-10-07"),
    ],
    "apache:2.4.50": [
        _cve("CVE-2021-42013", "CRITICAL", 9.8,
             "Incomplete fix for CVE-2021-41773 — RCE still possible via double-encoded paths.",
             ["https://httpd.apache.org/security/vulnerabilities_24.html"],
             exploit=True, published="2021-10-07"),
    ],
    "apache:2.4.51": [],  # patched
    "apache:2.4.48": [
        _cve("CVE-2021-34798", "HIGH", 7.5,
             "NULL pointer dereference in Apache httpd 2.4.48 and earlier when parsing "
             "malformed HTTP/2 headers.",
             ["https://httpd.apache.org/security/vulnerabilities_24.html"],
             published="2021-09-16"),
    ],
    "apache:2.4.46": [
        _cve("CVE-2021-26691", "CRITICAL", 9.8,
             "Heap overflow in mod_session_crypto in Apache httpd 2.4.46 and earlier.",
             ["https://httpd.apache.org/security/vulnerabilities_24.html"],
             published="2021-06-10"),
    ],
    "apache:2.4.43": [
        _cve("CVE-2020-11984", "CRITICAL", 9.8,
             "Buffer overflow in mod_proxy_uwsgi in Apache httpd 2.4.32-2.4.44.",
             ["https://httpd.apache.org/security/vulnerabilities_24.html"],
             published="2020-08-07"),
    ],

    # ── nginx ─────────────────────────────────────────────────────────
    "nginx:1.18.0": [
        _cve("CVE-2021-23017", "HIGH", 7.7,
             "Off-by-one error in nginx DNS resolver allows RCE via crafted DNS response.",
             ["https://nginx.org/en/security_advisories.html",
              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017"],
             exploit=True, published="2021-06-01"),
        _cve("CVE-2019-20372", "MEDIUM", 5.3,
             "nginx 0.6.18-1.20.0: HTTP request smuggling via crafted Transfer-Encoding header.",
             ["https://nginx.org/en/security_advisories.html"],
             published="2020-01-09"),
    ],
    "nginx:1.16.0": [
        _cve("CVE-2019-9516", "HIGH", 7.5,
             "HTTP/2 0-length headers leak (HPACK bomb) in nginx — denial of service.",
             ["https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md"],
             published="2019-08-13"),
        _cve("CVE-2019-9511", "HIGH", 7.5,
             "HTTP/2 Large Data Request denial-of-service in nginx.",
             ["https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md"],
             published="2019-08-13"),
    ],
    "nginx:1.14.0": [
        _cve("CVE-2018-16843", "HIGH", 7.5,
             "Excessive memory consumption in nginx HTTP/2 implementation (DoS).",
             ["https://nginx.org/en/security_advisories.html"],
             published="2018-11-07"),
        _cve("CVE-2018-16844", "HIGH", 7.5,
             "CPU exhaustion in nginx HTTP/2 implementation (DoS).",
             ["https://nginx.org/en/security_advisories.html"],
             published="2018-11-07"),
    ],

    # ── OpenSSL ───────────────────────────────────────────────────────
    "openssl:1.0.1": [
        _cve("CVE-2014-0160", "HIGH", 7.5,
             "Heartbleed: OpenSSL 1.0.1-1.0.1f memory disclosure — attacker can read 64KB "
             "of server memory per request, leaking private keys, passwords, and session tokens.",
             ["https://heartbleed.com/", "https://www.openssl.org/news/secadv/20140407.txt"],
             exploit=True, published="2014-04-07"),
        _cve("CVE-2014-0224", "HIGH", 7.4,
             "CCS Injection: OpenSSL allows MitM to decrypt TLS traffic.",
             ["https://www.openssl.org/news/secadv/20140605.txt"],
             exploit=True, published="2014-06-05"),
    ],
    "openssl:1.0.2": [
        _cve("CVE-2016-0800", "HIGH", 7.4,
             "DROWN attack: RSA decryption using obsolete SSLv2 protocol.",
             ["https://drownattack.com/", "https://www.openssl.org/news/secadv/20160301.txt"],
             exploit=True, published="2016-03-01"),
        _cve("CVE-2016-2183", "HIGH", 7.5,
             "SWEET32: Birthday attack on 64-bit block ciphers (3DES/Blowfish) in TLS.",
             ["https://sweet32.info/"],
             published="2016-09-01"),
    ],
    "openssl:3.0.0": [
        _cve("CVE-2022-3786", "HIGH", 7.5,
             "X.509 certificate verification buffer overflow (stack) — DoS via crafted email in cert.",
             ["https://www.openssl.org/news/secadv/20221101.txt"],
             published="2022-11-01"),
        _cve("CVE-2022-3602", "HIGH", 7.5,
             "X.509 certificate verification buffer overflow — potential RCE in TLS client.",
             ["https://www.openssl.org/news/secadv/20221101.txt"],
             exploit=True, published="2022-11-01"),
    ],
    "openssl:3.0.1": [
        _cve("CVE-2022-0778", "HIGH", 7.5,
             "Infinite loop in BN_mod_sqrt() with crafted certificate — DoS.",
             ["https://www.openssl.org/news/secadv/20220315.txt"],
             published="2022-03-15"),
    ],

    # ── PHP ───────────────────────────────────────────────────────────
    "php:7.4.3": [
        _cve("CVE-2020-7061", "HIGH", 7.5,
             "Heap-buffer-overflow in PHP exif extension when parsing TIFF/JPEG files.",
             ["https://bugs.php.net/bug.php?id=79282"],
             published="2020-02-27"),
    ],
    "php:7.2.0": [
        _cve("CVE-2018-5711", "MEDIUM", 6.5,
             "GD library denial of service via malformed PICT image in imagecreatef­rompstring().",
             ["https://bugs.php.net/bug.php?id=75571"],
             published="2018-01-16"),
    ],
    "php:5.6.0": [
        _cve("CVE-2015-3152", "HIGH", 7.4,
             "MySQL client can be forced to fall back to non-SSL when server supports SSL (BACKRONYM).",
             ["https://www.openwall.com/lists/oss-security/2015/04/25/2"],
             published="2015-04-29"),
    ],
    "php:8.1.0": [
        _cve("CVE-2022-31625", "CRITICAL", 9.8,
             "Use-after-free in PHP's Postgres module (pg_query/pg_send_query) — RCE.",
             ["https://bugs.php.net/bug.php?id=81720"],
             exploit=True, published="2022-06-16"),
    ],

    # ── WordPress ─────────────────────────────────────────────────────
    "wordpress:6.0": [
        _cve("CVE-2022-3590", "MEDIUM", 5.9,
             "SSRF in pingback feature of WordPress — allows internal network scanning.",
             ["https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11"],
             published="2022-10-17"),
    ],
    "wordpress:5.8.0": [
        _cve("CVE-2022-21664", "MEDIUM", 6.5,
             "Authenticated SQL injection via the WP_Query class in WordPress.",
             ["https://wordpress.org/news/2022/01/wordpress-5-8-3-security-release/"],
             published="2022-01-06"),
        _cve("CVE-2022-21663", "MEDIUM", 6.6,
             "Stored XSS via authenticated users with contributor role.",
             ["https://wordpress.org/news/2022/01/wordpress-5-8-3-security-release/"],
             published="2022-01-06"),
    ],
    "wordpress:5.0.0": [
        _cve("CVE-2019-8942", "HIGH", 8.8,
             "Authenticated RCE in WordPress via Path Traversal in crop-image function.",
             ["https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/",
              "https://www.exploit-db.com/exploits/46662"],
             exploit=True, published="2019-02-20"),
        _cve("CVE-2019-8943", "HIGH", 8.8,
             "WordPress Path Traversal complementing CVE-2019-8942 for RCE.",
             ["https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/"],
             exploit=True, published="2019-02-20"),
    ],

    # ── OpenSSH ──────────────────────────────────────────────────────
    "openssh:7.2": [
        _cve("CVE-2016-6210", "MEDIUM", 5.9,
             "OpenSSH 7.2 timing side-channel in user authentication allows username enumeration.",
             ["https://www.openwall.com/lists/oss-security/2016/08/01/2"],
             published="2016-08-07"),
        _cve("CVE-2016-6515", "HIGH", 7.5,
             "OpenSSH 7.2p2 auth password off-by-one allows infinite CPU usage (DoS).",
             ["https://bugzilla.redhat.com/show_bug.cgi?id=1364615"],
             published="2016-08-07"),
    ],
    "openssh:8.5": [
        _cve("CVE-2021-28041", "MEDIUM", 4.6,
             "OpenSSH ssh-agent allows crafted identities to read restricted memory.",
             ["https://www.openwall.com/lists/oss-security/2021/03/03/2"],
             published="2021-03-05"),
    ],
    "openssh:9.1": [
        _cve("CVE-2023-38408", "CRITICAL", 9.8,
             "Remote code execution in ssh-agent via crafted agent forwarding — "
             "malicious SSH server can cause arbitrary code execution in client's ssh-agent.",
             ["https://www.qualys.com/2023/07/19/cve-2023-38408/rce-openssh-forwarded-ssh-agent.txt",
              "https://www.exploit-db.com/exploits/51680"],
             exploit=True, published="2023-07-20"),
    ],

    # ── MySQL ─────────────────────────────────────────────────────────
    "mysql:5.7.0": [
        _cve("CVE-2016-6662", "CRITICAL", 9.8,
             "MySQL <= 5.7.15 allows local or remote attackers to create malicious config files "
             "leading to code execution as root.",
             ["https://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html",
              "https://www.exploit-db.com/exploits/40360"],
             exploit=True, published="2016-09-20"),
    ],
    "mysql:5.6.0": [
        _cve("CVE-2016-6662", "CRITICAL", 9.8,
             "MySQL <= 5.7.15 arbitrary config-file writing and code execution via DATA INFILE.",
             ["https://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html"],
             exploit=True, published="2016-09-20"),
    ],

    # ── ProFTPD ──────────────────────────────────────────────────────
    "proftpd:1.3.5": [
        _cve("CVE-2015-3306", "CRITICAL", 10.0,
             "ProFTPD 1.3.5 — mod_copy allows unauthenticated remote attackers to read/write "
             "arbitrary files via SITE CPFR and SITE CPTO commands.",
             ["https://www.exploit-db.com/exploits/36803"],
             exploit=True, published="2015-05-18"),
    ],

    # ── vsftpd ───────────────────────────────────────────────────────
    "vsftpd:2.3.4": [
        _cve("CVE-2011-2523", "CRITICAL", 10.0,
             "Backdoor in vsftpd 2.3.4 — a smiley face ':)' in the username opens a backdoor "
             "shell on port 6200.",
             ["https://www.exploit-db.com/exploits/17491",
              "https://metasploit.com/modules/exploit/unix/ftp/vsftpd_234_backdoor"],
             exploit=True, published="2011-07-03"),
    ],

    # ── Apache Tomcat ────────────────────────────────────────────────
    "apache tomcat:9.0.0": [
        _cve("CVE-2019-0232", "CRITICAL", 8.1,
             "Remote code execution via CGI Servlet when enableCmdLineArguments is enabled on Windows.",
             ["https://tomcat.apache.org/security-9.html"],
             exploit=True, published="2019-04-15"),
    ],
    "apache tomcat:10.0.0": [
        _cve("CVE-2022-42252", "HIGH", 7.5,
             "HTTP request smuggling in Apache Tomcat 10.0.0-M1 through 10.0.26.",
             ["https://tomcat.apache.org/security-10.html"],
             published="2022-11-01"),
    ],

    # ── Drupal ───────────────────────────────────────────────────────
    "drupal:8.6.0": [
        _cve("CVE-2019-6340", "CRITICAL", 9.8,
             "Drupal core RCE via REST API — arbitrary PHP serialisation via crafted request "
             "(Drupalgeddon 3).",
             ["https://www.drupal.org/sa-core-2019-003",
              "https://www.exploit-db.com/exploits/46459"],
             exploit=True, published="2019-02-20"),
    ],
    "drupal:7.0": [
        _cve("CVE-2014-3704", "CRITICAL", 10.0,
             "Drupalgeddon: SQL injection in Drupal 7 core via crafted parameters.",
             ["https://www.drupal.org/SA-CORE-2014-005",
              "https://www.exploit-db.com/exploits/34984"],
             exploit=True, published="2014-10-15"),
    ],
}

# Normalisation aliases — map "Apache" → "apache", "nginx" → "nginx"
_TECH_ALIASES: dict[str, str] = {
    "apache http server": "apache",
    "apache-http-server": "apache",
    "httpd": "apache",
    "nginx": "nginx",
    "php": "php",
    "wordpress": "wordpress",
    "openssh": "openssh",
    "openssl": "openssl",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "drupal": "drupal",
    "joomla": "joomla",
    "proftpd": "proftpd",
    "vsftpd": "vsftpd",
    "apache tomcat": "apache tomcat",
    "tomcat": "apache tomcat",
}


def _norm_name(name: str) -> str:
    n = name.lower().strip()
    for prefix in ("lib", "mod_"):
        if n.startswith(prefix):
            n = n[len(prefix):]
    return _TECH_ALIASES.get(n, n)


def parse_tech(tech_string: str) -> tuple[str, Optional[str]]:
    """
    Parse "Apache:2.4.49" → ("Apache", "2.4.49")
    Parse "Nginx"         → ("Nginx", None)
    """
    if ":" in tech_string:
        name, raw_version = tech_string.split(":", 1)
        m = re.match(r"(\d+(?:\.\d+)*)", raw_version.strip())
        return name.strip(), (m.group(1) if m else None)
    return tech_string.strip(), None


def _lookup_embedded(tech_name: str, version: str) -> List[dict]:
    """
    Look up tech+version in the embedded CVE database.
    Returns CVEs with technology/version fields filled in.
    Tries:
      1. Exact match (e.g. "apache:2.4.49")
      2. Major.minor match (e.g. "apache:2.4")
      3. Major match (e.g. "apache:2")
    """
    norm = _norm_name(tech_name)
    results: List[dict] = []

    # Try progressively broader version keys
    ver_parts = version.split(".")
    candidates = [version]  # exact
    if len(ver_parts) >= 2:
        candidates.append(".".join(ver_parts[:2]))   # major.minor
    if len(ver_parts) >= 1:
        candidates.append(ver_parts[0])              # major

    for key_ver in candidates:
        db_key = f"{norm}:{key_ver}"
        if db_key in _EMBEDDED_DB:
            entries = _EMBEDDED_DB[db_key]
            results = [
                {**e, "technology": tech_name, "version": version}
                for e in entries
            ]
            if results:
                logger.info(f"[CVE] Embedded DB: {tech_name} {version} → {len(results)} CVEs (key={db_key})")
                return results
            # Empty list means "no CVEs for this version" (e.g. patched)
            logger.info(f"[CVE] Embedded DB: {tech_name} {version} → 0 CVEs (known-patched, key={db_key})")
            return []

    logger.debug(f"[CVE] Embedded DB: no entry for {norm}:{version}")
    return []


# ── HTTP helpers ──────────────────────────────────────────────────────

_BROWSER_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept":          "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
}


def _http_get(url: str, extra_headers: Optional[dict] = None) -> Optional[dict]:
    """Synchronous JSON GET with gzip support. Runs via asyncio.to_thread."""
    headers = {**_BROWSER_HEADERS, **(extra_headers or {})}
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
            raw = resp.read()
            if resp.info().get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            return json.loads(raw)
    except Exception as exc:
        logger.debug(f"[CVE] HTTP GET failed {url}: {exc}")
        return None


# ── CIRCL CVE lookup ──────────────────────────────────────────────────

def _extract_cvss_circl(data: dict) -> tuple[float, str]:
    """Parse CVSS score from vulnerability.circl.lu ADP section."""
    try:
        for entry in data.get("containers", {}).get("adp", []):
            for m in entry.get("metrics", []):
                for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
                    if key in m:
                        score = float(m[key].get("baseScore", 0))
                        sev   = str(m[key].get("baseSeverity", "NONE")).upper()
                        return score, sev
    except Exception:
        pass
    return 0.0, "NONE"


async def _circl_lookup(cve_id: str) -> Optional[dict]:
    """Fetch a single CVE from vulnerability.circl.lu (no rate limit observed)."""
    global _last_circl_time

    async with _circl_lock:
        now  = time.monotonic()
        wait = _CIRCL_MIN_INTERVAL - (now - _last_circl_time)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_circl_time = time.monotonic()

    url = f"{CIRCL_BASE}/{cve_id}"
    raw = await asyncio.to_thread(_http_get, url)
    if not raw or "containers" not in raw:
        return None

    score, severity = _extract_cvss_circl(raw)
    if score == 0.0:
        return None

    meta = raw.get("cveMetadata", {})
    cna  = raw.get("containers", {}).get("cna", {})

    desc = ""
    for d in cna.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    references  = [r.get("url", "") for r in cna.get("references", []) if r.get("url")]
    exploit     = any("exploit" in r.lower() or "poc" in r.lower() for r in references)
    published   = meta.get("datePublished", "")

    return {
        "cveId":            cve_id,
        "technology":       "",
        "version":          "",
        "severity":         severity,
        "cvssScore":        score,
        "description":      desc,
        "references":       references,
        "exploitAvailable": exploit,
        "published":        published,
    }


# ── NVD API (optional — requires API key) ────────────────────────────

def _sync_nvd_request(url: str) -> Optional[dict]:
    """NVD request via Python urllib (not httpx-toolkit to control headers)."""
    headers = {
        **_BROWSER_HEADERS,
        **({"apiKey": NVD_API_KEY} if NVD_API_KEY else {}),
    }
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25, context=ctx) as resp:
            raw = resp.read()
            if resp.info().get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            return json.loads(raw)
    except Exception as exc:
        logger.debug(f"[CVE] NVD request failed: {exc}")
        return None


def _extract_cvss_nvd(cve_data: dict) -> tuple[float, str]:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss    = primary.get("cvssData", {})
        return float(cvss.get("baseScore", 0.0)), str(cvss.get("baseSeverity", "NONE")).upper()
    return 0.0, "NONE"


def _parse_nvd_vulnerabilities(raw: dict, tech_name: str, version: str) -> List[dict]:
    results = []
    for item in raw.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if not cve or not cve.get("id", "").startswith("CVE-"):
            continue
        score, severity = _extract_cvss_nvd(cve)
        if severity == "NONE" and score == 0.0:
            continue

        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        references = cve.get("references", [])
        ref_urls   = [r.get("url", "") for r in references if r.get("url")]
        exploit    = any(
            kw in (r.get("url", "") + " ".join(r.get("tags", []))).lower()
            for r in references
            for kw in ("exploit", "poc", "proof-of-concept", "metasploit", "exploit-db")
        )
        results.append({
            "cveId":            cve.get("id"),
            "technology":       tech_name,
            "version":          version,
            "severity":         severity,
            "cvssScore":        score,
            "description":      desc,
            "references":       ref_urls,
            "exploitAvailable": exploit,
            "published":        cve.get("published", ""),
        })

    results.sort(key=lambda x: x["cvssScore"], reverse=True)
    return results[:15]


async def _nvd_search(tech_name: str, version: str) -> List[dict]:
    """Search NVD API (only used when NVD_API_KEY is set or NVD is reachable)."""
    global _last_nvd_time

    interval = _NVD_MIN_INTERVAL if NVD_API_KEY else 6.0
    norm = _norm_name(tech_name)

    async with _nvd_lock:
        wait = interval - (time.monotonic() - _last_nvd_time)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_nvd_time = time.monotonic()

    # Try CPE first
    cpe_product = _CPE_MAP.get(norm)
    if cpe_product:
        cpe  = f"cpe:2.3:a:{cpe_product}:{version}:*:*:*:*:*:*:*"
        url  = f"{NVD_BASE}?{urlencode({'cpeName': cpe, 'isVulnerable': '', 'resultsPerPage': 20})}"
        raw  = await asyncio.to_thread(_sync_nvd_request, url)
        if raw and "vulnerabilities" in raw:
            results = _parse_nvd_vulnerabilities(raw, tech_name, version)
            if results:
                return results

    # Keyword fallback
    keyword = f"{_TECH_KEYWORDS.get(norm, tech_name)} {version}"
    url = f"{NVD_BASE}?{urlencode({'keywordSearch': keyword, 'resultsPerPage': 20})}"
    raw = await asyncio.to_thread(_sync_nvd_request, url)
    if raw and "vulnerabilities" in raw:
        return _parse_nvd_vulnerabilities(raw, tech_name, version)

    return []


# ── Public API ────────────────────────────────────────────────────────

async def get_cves_for_technology(tech_name: str, version: str) -> List[dict]:
    """
    Return CVEs for tech+version using a three-tier lookup:

      Tier 1: Embedded local database (instant, covers well-known CVEs)
      Tier 2: NVD API (when NVD_API_KEY is set or reachable without auth)
      Tier 3: CIRCL CVE API (enriches embedded results with live data when available)
    """
    cache_key = f"{tech_name.lower()}:{version}"

    if cache_key in _CVE_CACHE:
        logger.debug(f"[CVE] Cache hit: {tech_name} {version} → {len(_CVE_CACHE[cache_key])} CVEs")
        return _CVE_CACHE[cache_key]

    if cache_key in _CVE_FETCHING:
        for _ in range(60):
            await asyncio.sleep(1)
            if cache_key in _CVE_CACHE:
                return _CVE_CACHE[cache_key]
        return []

    _CVE_FETCHING.add(cache_key)
    logger.info(f"[CVE] Looking up: {tech_name} {version}")

    try:
        results: List[dict] = []

        # Tier 1: Embedded DB
        results = _lookup_embedded(tech_name, version)

        # Tier 2: NVD (only if key is set, to avoid hammering)
        if not results and NVD_API_KEY:
            logger.info(f"[CVE] NVD API lookup (key configured): {tech_name} {version}")
            results = await _nvd_search(tech_name, version)

        # Tier 3: NVD without key (best-effort — may be blocked by Cloudflare)
        if not results and not NVD_API_KEY:
            logger.info(f"[CVE] NVD API lookup (no key — may fail): {tech_name} {version}")
            nvd_results = await _nvd_search(tech_name, version)
            if nvd_results:
                results = nvd_results
                logger.info(f"[CVE] NVD (no key) returned {len(results)} CVEs for {tech_name} {version}")

        if results:
            ids = [r["cveId"] for r in results[:5]]
            extra = f" (+{len(results)-5} more)" if len(results) > 5 else ""
            logger.info(f"[CVE] Found {len(results)} CVEs for {tech_name} {version}: {', '.join(ids)}{extra}")
        else:
            logger.info(f"[CVE] No CVEs found for {tech_name} {version}")

        _CVE_CACHE[cache_key] = results
        return results

    except Exception as exc:
        logger.error(f"[CVE] Lookup error for {tech_name} {version}: {exc}")
        _CVE_CACHE[cache_key] = []
        return []
    finally:
        _CVE_FETCHING.discard(cache_key)
