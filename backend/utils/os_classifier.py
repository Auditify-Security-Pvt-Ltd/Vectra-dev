"""
OS string classifier — maps raw nmap OS fingerprint strings to canonical names.
"""
from __future__ import annotations

import re
from typing import Any, Dict

# (regex pattern, canonical name, os family, confidence %)
_OS_PATTERNS = [
    (r"windows server 2022",          "Windows Server 2022",      "windows", 95),
    (r"windows server 2019",          "Windows Server 2019",      "windows", 95),
    (r"windows server 2016",          "Windows Server 2016",      "windows", 95),
    (r"windows server 2012",          "Windows Server 2012",      "windows", 90),
    (r"windows server 2008",          "Windows Server 2008",      "windows", 90),
    (r"windows 11",                   "Windows 11",               "windows", 90),
    (r"windows 10",                   "Windows 10",               "windows", 90),
    (r"windows 7",                    "Windows 7",                "windows", 90),
    (r"windows xp",                   "Windows XP",               "windows", 90),
    (r"windows",                      "Windows",                  "windows", 60),
    (r"ubuntu 22\.04|ubuntu 22",      "Ubuntu 22.04 LTS",         "linux",   92),
    (r"ubuntu 20\.04|ubuntu 20",      "Ubuntu 20.04 LTS",         "linux",   92),
    (r"ubuntu 18\.04|ubuntu 18",      "Ubuntu 18.04 LTS",         "linux",   92),
    (r"ubuntu",                       "Ubuntu Linux",             "linux",   72),
    (r"debian 12|debian bookworm",    "Debian 12 Bookworm",       "linux",   92),
    (r"debian 11|debian bullseye",    "Debian 11 Bullseye",       "linux",   92),
    (r"debian 10|debian buster",      "Debian 10 Buster",         "linux",   92),
    (r"debian",                       "Debian Linux",             "linux",   70),
    (r"centos stream 9|centos 9",     "CentOS Stream 9",          "linux",   90),
    (r"centos stream 8|centos 8",     "CentOS Stream 8",          "linux",   90),
    (r"centos 7",                     "CentOS 7",                 "linux",   90),
    (r"centos",                       "CentOS Linux",             "linux",   70),
    (r"red hat enterprise|rhel",      "Red Hat Enterprise Linux", "linux",   82),
    (r"fedora",                       "Fedora Linux",             "linux",   82),
    (r"kali linux|kali",              "Kali Linux",               "linux",   90),
    (r"arch linux",                   "Arch Linux",               "linux",   85),
    (r"alpine linux|alpine",          "Alpine Linux",             "linux",   82),
    (r"linux kernel 6",               "Linux (Kernel 6.x)",       "linux",   55),
    (r"linux kernel 5",               "Linux (Kernel 5.x)",       "linux",   55),
    (r"linux kernel 4",               "Linux (Kernel 4.x)",       "linux",   55),
    (r"linux",                        "Linux",                    "linux",   50),
    (r"cisco ios xe",                 "Cisco IOS XE",             "network", 92),
    (r"cisco ios",                    "Cisco IOS",                "network", 90),
    (r"cisco nx-os",                  "Cisco NX-OS",              "network", 92),
    (r"cisco",                        "Cisco Device",             "network", 70),
    (r"juniper junos",                "Juniper JunOS",            "network", 90),
    (r"juniper",                      "Juniper Network Device",   "network", 80),
    (r"fortigate|fortios|fortinet",   "Fortinet FortiGate",       "network", 88),
    (r"palo alto",                    "Palo Alto NGFW",           "network", 88),
    (r"mikrotik",                     "MikroTik RouterOS",        "network", 88),
    (r"vmware esxi|esxi",             "VMware ESXi",              "vmware",  92),
    (r"vmware",                       "VMware",                   "vmware",  70),
    (r"freebsd",                      "FreeBSD",                  "bsd",     88),
    (r"openbsd",                      "OpenBSD",                  "bsd",     88),
    (r"netbsd",                       "NetBSD",                   "bsd",     88),
    (r"macos|mac os x|darwin",        "macOS",                    "macos",   82),
    (r"android",                      "Android",                  "mobile",  78),
    (r"ios \d|iphone os|ipados",      "iOS/iPadOS",               "mobile",  78),
    (r"printer|hp jetdirect|laserjet","Network Printer",          "printer", 72),
    (r"embedded|rtos|vxworks",        "Embedded / RTOS",          "embedded",62),
    (r"synology",                     "Synology NAS",             "nas",     88),
    (r"qnap",                         "QNAP NAS",                 "nas",     88),
]

_COMPILED = [
    (re.compile(pat, re.IGNORECASE), name, fam, conf)
    for pat, name, fam, conf in _OS_PATTERNS
]


def classify_os(raw: str) -> Dict[str, Any]:
    """
    Classify a raw nmap OS string into a canonical name, family, and confidence.
    Returns {"normalized": str, "family": str, "confidence": int}.
    """
    if not raw or not raw.strip():
        return {"normalized": "", "family": "unknown", "confidence": 0}

    clean = raw.strip()
    for pattern, name, family, confidence in _COMPILED:
        if pattern.search(clean):
            return {"normalized": name, "family": family, "confidence": confidence}

    return {"normalized": clean[:80], "family": "unknown", "confidence": 30}
