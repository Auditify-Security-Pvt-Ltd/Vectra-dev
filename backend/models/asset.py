from __future__ import annotations

import re
from typing import List, Optional

from pydantic import BaseModel, field_validator


class DiscoveryRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        v = v.strip()
        # Strip protocol
        v = re.sub(r"^https?://", "", v)
        # Strip path and port
        v = v.split("/")[0].split(":")[0].strip()
        if not v or "." not in v:
            raise ValueError(f"Invalid domain: {v!r}")
        if " " in v:
            raise ValueError("Domain cannot contain spaces")
        return v.lower()


class AssetResult(BaseModel):
    assetId: str
    discoveryId: str
    domain: str
    subdomain: str
    alive: bool = False
    statusCode: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    ip: Optional[str] = None
    contentType: Optional[str] = None
    technologies: List[str] = []
    url: Optional[str] = None
    createdAt: str
