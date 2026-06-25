from __future__ import annotations

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, field_validator


class NetworkScanProfile(str, Enum):
    QUICK_SCAN = "QUICK_SCAN"
    FULL_SCAN  = "FULL_SCAN"


class NetworkScanRequest(BaseModel):
    target:      str
    scanProfile: NetworkScanProfile = NetworkScanProfile.QUICK_SCAN

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        # Accept single IP, CIDR, dash-range, or hostname/domain
        patterns = [
            r"^\d{1,3}(\.\d{1,3}){3}$",            # 192.168.1.1
            r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$",    # 192.168.1.0/24
            r"^\d{1,3}(\.\d{1,3}){2}\.\d+-\d+$",   # 192.168.1.1-20
            r"^[a-zA-Z0-9._-]+$",                   # hostname/domain
        ]
        if not any(re.match(p, v) for p in patterns):
            raise ValueError(
                f"Invalid network target '{v}'. "
                "Use an IP address, CIDR range (192.168.1.0/24), or hostname."
            )
        return v


class NetworkHealthResponse(BaseModel):
    status: str
    nmap:   bool
    nuclei: bool
