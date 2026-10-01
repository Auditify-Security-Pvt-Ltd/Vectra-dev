"""
Organization profile validation.

Mirrors frontend/lib/org-validation.ts and the checks in firestore.rules, so an
organization looks the same whether it was created at signup (browser) or
edited by a platform admin (backend).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

NAME_MIN, NAME_MAX = 2, 100
WEBSITE_MAX = 200
_PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()-]{5,18}[0-9]$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


def clean_name(value: str) -> str:
    name = re.sub(r"\s+", " ", (value or "")).strip()
    name = re.sub(r"[<>]", "", name)
    if not NAME_MIN <= len(name) <= NAME_MAX:
        raise ValueError(f"Organization name must be {NAME_MIN}–{NAME_MAX} characters")
    return name


def clean_website(value: str) -> str:
    """Normalize to scheme://host[/path]. Only http(s); no credentials."""
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Website URL is required")
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Website must use http or https")
    if parsed.username or parsed.password or not parsed.hostname or not _HOST_RE.match(parsed.hostname):
        raise ValueError("Website URL is not valid")
    host = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path.rstrip("/")
    url = f"{parsed.scheme.lower()}://{host}{port}{path}"
    if len(url) > WEBSITE_MAX:
        raise ValueError("Website URL is too long")
    return url


def clean_phone(value: str) -> str:
    """Stored as typed minus redundant whitespace; digits, spaces, ()- and a leading +."""
    phone = re.sub(r"\s+", " ", (value or "")).strip()
    if not _PHONE_RE.match(phone):
        raise ValueError("Contact phone must be 7–20 characters: digits, spaces, ( ) - and an optional leading +")
    return phone
