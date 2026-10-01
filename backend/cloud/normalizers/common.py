"""Helpers shared by provider normalizers."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Optional

MAX_TITLE = 300
MAX_TEXT = 8_000
MAX_RAW_JSON = 20_000
MAX_LIST = 25

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def fingerprint(*parts: str) -> str:
    """Deterministic Firestore-safe id; identical input → identical document."""
    joined = "\x1f".join(p or "" for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:40]


def clip(value: Any, limit: int = MAX_TEXT) -> str:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = text.replace("\x00", "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def opt(value: Any, limit: int = 1_000) -> Optional[str]:
    if value is None or value == "":
        return None
    return clip(value, limit)


def iso(value: Any) -> Optional[str]:
    """Normalize provider timestamps to ISO-8601 UTC strings."""
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            return None
    return None


def safe_float(value: Any) -> Optional[float]:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if 0.0 <= f <= 10.0 else None


def cve_ids(values: list[Any]) -> list[str]:
    """Only well-formed CVE identifiers — never manufacture one."""
    seen: list[str] = []
    for v in values:
        if isinstance(v, str) and CVE_RE.match(v.strip().upper()):
            cve = v.strip().upper()
            if cve not in seen:
                seen.append(cve)
    return seen[:MAX_LIST]


def raw_json(payload: Any) -> str:
    """Size-capped JSON copy of the provider payload for diagnostics."""
    try:
        text = json.dumps(payload, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return ""
    if len(text) <= MAX_RAW_JSON:
        return text
    return json.dumps({"truncated": True, "originalBytes": len(text), "prefix": text[:MAX_RAW_JSON - 200]})


def str_dict(value: Any, limit: int = 50) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in list(value.items())[:limit]:
        out[clip(k, 128)] = clip(v, 256)
    return out
