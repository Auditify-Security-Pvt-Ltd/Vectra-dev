"""
Provider catalogue and capability model.

Only real connectors are registered. Future providers are listed with
capabilities marked "future" so the UI can show them as Coming Soon without
implying data exists. Vercel and Netlify expose no native security-findings
service today; their entries say so rather than promising one.
"""
from __future__ import annotations

from typing import Optional

from cloud.providers.aws import AWSProvider
from cloud.providers.base import CloudProvider
from cloud.providers.gcp import GCPProvider

_PROVIDERS: dict[str, CloudProvider] = {p.key: p for p in (AWSProvider(), GCPProvider())}

_FUTURE = [
    {"key": "azure", "name": "Microsoft Azure", "securityService": "Microsoft Defender for Cloud",
     "note": "Planned: findings from Microsoft Defender for Cloud."},
    {"key": "vercel", "name": "Vercel", "securityService": None,
     "note": "No native security-findings API. Planned support would be configuration checks."},
    {"key": "netlify", "name": "Netlify", "securityService": None,
     "note": "No native security-findings API. Planned support would be configuration checks."},
]

_FUTURE_CAPABILITIES = {
    "findings": "future", "vulnerability_metadata": "future", "compliance": "future",
    "assets": "future", "asset_inventory": "future", "iam_analysis": "future",
    "configuration_analysis": "future",
}


def get_provider(key: str) -> Optional[CloudProvider]:
    return _PROVIDERS.get(key)


def provider_keys() -> list[str]:
    return list(_PROVIDERS)


def catalogue(org_id: Optional[str] = None) -> list[dict]:
    items = [p.describe() for p in _PROVIDERS.values()]
    for f in _FUTURE:
        items.append({**f, "status": "coming_soon", "capabilities": _FUTURE_CAPABILITIES, "authMethods": []})
    return items
