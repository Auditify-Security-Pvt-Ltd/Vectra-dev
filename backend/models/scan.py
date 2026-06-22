from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, HttpUrl, field_validator


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    unknown = "unknown"


class ScanProfile(str, Enum):
    QUICK_SCAN = "QUICK_SCAN"
    FULL_SCAN = "FULL_SCAN"


class ScanRequest(BaseModel):
    target: HttpUrl
    scanProfile: ScanProfile = ScanProfile.FULL_SCAN

    @field_validator("target")
    @classmethod
    def target_must_be_http(cls, v: HttpUrl) -> HttpUrl:
        if v.scheme not in ("http", "https"):
            raise ValueError("Target must use http or https scheme")
        return v


class Finding(BaseModel):
    severity: Severity
    title: str
    template: str
    host: Optional[str] = None
    matched_at: Optional[str] = None
    description: Optional[str] = None


class ScanLog(BaseModel):
    timestamp: str
    message: str


class ScanResponse(BaseModel):
    scanId: str
    target: str
    status: str
    findings: List[Finding]
    total_findings: int
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
