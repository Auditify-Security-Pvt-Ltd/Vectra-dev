"""
Google Security Command Center (API v2) → normalized Vectra finding.

Input is one element of ListFindingsResponse.listFindingsResults:
    {"finding": Finding, "resource": Resource}

Severity mapping (Finding.severity enum):
    CRITICAL → critical, HIGH → high, MEDIUM → medium, LOW → low,
    SEVERITY_UNSPECIFIED / absent → info, with providerSeverity recording that
    Security Command Center did not rate it (no severity is invented).

Status mapping:
    mute MUTED       → suppressed
    state INACTIVE   → resolved
    state ACTIVE     → open
"""
from __future__ import annotations

from typing import Any, Optional

from cloud.models import (
    NormalizedAsset, NormalizedFinding,
    STATUS_OPEN, STATUS_RESOLVED, STATUS_SUPPRESSED,
)
from cloud.normalizers.common import (
    MAX_LIST, MAX_TITLE, clip, cve_ids, fingerprint, iso, opt, raw_json, safe_float,
)

PROVIDER = "gcp"
SOURCE = "gcp-security-command-center"
SCOPE = "Security Command Center"  # must match providers.gcp.SCOPE_SCC

_CATEGORY = {"VULNERABILITY": "Vulnerability", "MISCONFIGURATION": "Misconfiguration", "THREAT": "Threat",
             "OBSERVATION": "Observation", "SCC_ERROR": "Security Command Center", "POSTURE_VIOLATION": "Posture",
             "TOXIC_COMBINATION": "Toxic combination"}

_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def severity(value: Any) -> tuple[str, Optional[str]]:
    label = str(value or "SEVERITY_UNSPECIFIED").upper()
    return _SEVERITY.get(label, "info"), label


def status(finding: dict) -> tuple[str, str]:
    state = str(finding.get("state") or "STATE_UNSPECIFIED").upper()
    mute = str(finding.get("mute") or "MUTE_UNSPECIFIED").upper()
    provider_status = f"{state}/{mute}"
    if mute == "MUTED":
        return STATUS_SUPPRESSED, provider_status
    if state == "INACTIVE":
        return STATUS_RESOLVED, provider_status
    return STATUS_OPEN, provider_status


def _project(resource: dict) -> Optional[str]:
    meta = resource.get("gcpMetadata") if isinstance(resource.get("gcpMetadata"), dict) else {}
    if meta.get("projectDisplayName"):
        return opt(meta["projectDisplayName"], 100)
    project = meta.get("project")
    if isinstance(project, str) and project:
        return opt(project.rsplit("/", 1)[-1], 100)
    return None


def _short_type(resource_type: str) -> str:
    # "google.compute.Instance" stays as-is; also accept bare types.
    return clip(resource_type or "Other", 200)


def _service(resource: dict, resource_type: str) -> Optional[str]:
    if resource.get("service"):
        return opt(resource["service"], 100)
    parts = resource_type.split(".")
    return parts[1] if len(parts) >= 3 and parts[0] == "google" else None


def _package(pkg: Any) -> Optional[dict]:
    if not isinstance(pkg, dict) or not pkg.get("packageName"):
        return None
    return {
        "name": clip(pkg.get("packageName"), 200),
        "version": opt(pkg.get("packageVersion"), 100),
        "cpeUri": opt(pkg.get("cpeUri"), 300),
        "packageType": opt(pkg.get("packageType"), 50),
    }


def normalize(result: dict, integration_id: str) -> tuple[NormalizedFinding, list[NormalizedAsset]]:
    """Raises ValueError when the result lacks a finding name."""
    if not isinstance(result, dict) or not isinstance(result.get("finding"), dict):
        raise ValueError("result has no finding")
    finding = result["finding"]
    resource = result.get("resource") if isinstance(result.get("resource"), dict) else {}

    name = finding.get("canonicalName") or finding.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("finding is missing name")

    resource_id = clip(resource.get("name") or finding.get("resourceName") or "", 1_000)
    resource_type = _short_type(str(resource.get("type") or ""))
    project = _project(resource)
    location = opt(resource.get("location"), 64)

    assets: list[NormalizedAsset] = []
    if resource_id:
        assets.append(NormalizedAsset(
            assetId=fingerprint(PROVIDER, integration_id, resource_id),
            provider=PROVIDER,
            integrationId=integration_id,
            accountId=project,
            region=location,
            resourceType=resource_type,
            resourceId=resource_id,
            resourceName=opt(resource.get("displayName"), 300) or opt(resource_id.rsplit("/", 1)[-1], 300),
            service=_service(resource, resource_type),
        ))
    primary = assets[0] if assets else None

    vuln = finding.get("vulnerability") if isinstance(finding.get("vulnerability"), dict) else {}
    cve = vuln.get("cve") if isinstance(vuln.get("cve"), dict) else {}
    cves = cve_ids([cve.get("id")])
    cvss = safe_float((cve.get("cvssv3") or {}).get("baseScore")) if isinstance(cve.get("cvssv3"), dict) else None
    packages = []
    offending, fixed = _package(vuln.get("offendingPackage")), _package(vuln.get("fixedPackage"))
    if offending:
        if fixed:
            offending["fixedInVersion"] = fixed.get("version")
        offending["cve"] = cves[0] if cves else None
        packages.append(offending)

    compliance: dict[str, Any] = {}
    standards = []
    for c in (finding.get("compliances") or [])[:MAX_LIST]:
        if isinstance(c, dict) and c.get("standard"):
            ids = ", ".join(clip(i, 40) for i in (c.get("ids") or [])[:10])
            standards.append(clip(f"{c.get('standard')} {c.get('version') or ''} {ids}".strip(), 200))
    if standards:
        compliance["relatedRequirements"] = standards

    sev, provider_sev = severity(finding.get("severity"))
    st, provider_st = status(finding)
    finding_class = opt(finding.get("findingClass"), 40)
    external = finding.get("externalUri")

    normalized = NormalizedFinding(
        fingerprint=fingerprint(PROVIDER, integration_id, name),
        provider=PROVIDER,
        integrationId=integration_id,
        providerFindingId=clip(name, 1_000),
        providerProduct=opt(finding.get("parentDisplayName"), 120) or "Security Command Center",
        title=clip(_title(finding), MAX_TITLE),
        description=clip(finding.get("description") or ""),
        severity=sev,
        providerSeverity=provider_sev,
        status=st,
        providerStatus=provider_st,
        findingType=opt(finding.get("category"), 300),
        findingClass=finding_class,
        assetId=primary.assetId if primary else None,
        resourceType=primary.resourceType if primary else (resource_type if resource_id else None),
        resourceId=resource_id or None,
        resourceName=primary.resourceName if primary else None,
        accountId=project,
        region=location,
        cveIds=cves,
        cveId=cves[0] if cves else None,
        cvssScore=cvss,
        cvssVector=None,  # SCC v2 exposes CVSS components, not a vector string
        affectedPackages=packages,
        compliance=compliance,
        recommendation=opt(finding.get("nextSteps"), 4_000),
        remediationUrl=None,
        sourceUrl=external if isinstance(external, str) and external.lower().startswith(("https://", "http://")) and len(external) <= 2_000 else None,
        providerCreatedAt=iso(finding.get("createTime")),
        providerUpdatedAt=iso(finding.get("eventTime")),
        firstObservedAt=iso(finding.get("createTime")),
        lastObservedAt=iso(finding.get("eventTime")) or iso(finding.get("createTime")),
        source=SOURCE,
        category=_CATEGORY.get(str(finding_class or "").upper(), "Security Command Center"),
        evidence={k: v for k, v in {
            "sccCategory": opt(finding.get("category"), 300),
            "resource": resource_id or None,
            "state": opt(finding.get("state"), 40),
            "eventTime": iso(finding.get("eventTime")),
        }.items() if v},
        scope=SCOPE,
        rawProviderMetadata=raw_json({
            "finding": {k: finding.get(k) for k in (
                "name", "canonicalName", "parent", "resourceName", "state", "category", "severity",
                "mute", "findingClass", "vulnerability", "compliances", "sourceProperties",
            ) if k in finding},
            "resource": resource,
        }),
    )
    return normalized, assets


def _title(finding: dict) -> str:
    """SCC findings have a category, not a title; make it readable without changing meaning."""
    category = str(finding.get("category") or "").strip()
    if not category:
        return "Security Command Center finding"
    if category.isupper() or "_" in category:
        return category.replace("_", " ").title()
    return category
