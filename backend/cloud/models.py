"""Provider-independent Cloud Security models."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# Vectra severity scale shared with web/network/SAST findings (lower-case).
SEVERITIES = ("critical", "high", "medium", "low", "info")

# Provider-reported lifecycle of a finding. Team workflow (assignee, in
# progress, accepted risk…) stays in the existing finding_tracking collection.
STATUS_OPEN       = "open"
STATUS_RESOLVED   = "resolved"
STATUS_SUPPRESSED = "suppressed"
STATUSES = (STATUS_OPEN, STATUS_RESOLVED, STATUS_SUPPRESSED)

INTEGRATION_STATUSES = ("connected", "error", "disconnected")
SYNC_STATUSES = ("queued", "running", "completed", "partial", "failed")


@dataclass
class NormalizedAsset:
    assetId: str
    provider: str
    integrationId: str
    accountId: Optional[str]
    region: Optional[str]
    resourceType: str
    resourceId: str
    resourceName: Optional[str]
    service: Optional[str] = None
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NormalizedFinding:
    fingerprint: str
    provider: str
    integrationId: str
    providerFindingId: str
    providerProduct: Optional[str]
    title: str
    description: str
    severity: str                 # one of SEVERITIES
    providerSeverity: Optional[str]
    status: str                   # one of STATUSES
    providerStatus: Optional[str]
    findingType: Optional[str]
    findingClass: Optional[str]
    assetId: Optional[str]
    resourceType: Optional[str]
    resourceId: Optional[str]
    resourceName: Optional[str]
    accountId: Optional[str]
    region: Optional[str]
    cveIds: list[str] = field(default_factory=list)
    cveId: Optional[str] = None
    cvssScore: Optional[float] = None
    cvssVector: Optional[str] = None
    affectedPackages: list[dict[str, Any]] = field(default_factory=list)
    compliance: dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None
    remediationUrl: Optional[str] = None
    sourceUrl: Optional[str] = None
    providerCreatedAt: Optional[str] = None
    providerUpdatedAt: Optional[str] = None
    firstObservedAt: Optional[str] = None
    lastObservedAt: Optional[str] = None
    rawProviderMetadata: str = ""  # JSON, size-capped
    # Where the finding came from inside the provider (e.g. Security Command
    # Center vs Vectra configuration analysis), a coarse category, and the
    # configuration evidence that justifies it. Optional: AWS leaves them unset.
    source: Optional[str] = None
    category: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    # Resolution scope: with FetchResult.scopedResolution, a stored finding is
    # resolved only when its scope was fetched completely in this sync.
    scope: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ValidationResult:
    """Outcome of a live permission check against the provider."""
    ok: bool
    accountId: Optional[str] = None
    accountLabel: Optional[str] = None
    checks: list[dict[str, Any]] = field(default_factory=list)  # [{name, ok, detail}]
    scopes: list[str] = field(default_factory=list)            # regions / parents usable
    error: Optional[dict[str, Any]] = None
    # Provider capability report (GCP): what this connection can actually do.
    capabilities: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FetchResult:
    """Everything one sync pulled from a provider."""
    findings: list[NormalizedFinding] = field(default_factory=list)
    assets: dict[str, NormalizedAsset] = field(default_factory=dict)
    completedScopes: list[str] = field(default_factory=list)
    failedScopes: list[dict[str, Any]] = field(default_factory=list)  # [{scope, code, message}]
    truncated: bool = False
    apiCalls: int = 0
    apiLatencyMs: int = 0
    # Scopes deliberately not fetched because the capability is unavailable
    # (e.g. Security Command Center not activated). Not a failure.
    skippedScopes: list[dict[str, Any]] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    # True → resolve only findings whose `scope` is in completedScopes.
    scopedResolution: bool = False
