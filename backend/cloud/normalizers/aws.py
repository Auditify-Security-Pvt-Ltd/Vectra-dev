"""
AWS Security Hub (ASFF) → normalized Vectra finding.

Severity mapping (Severity.Label, per the ASFF reference):
    CRITICAL → critical, HIGH → high, MEDIUM → medium, LOW → low,
    INFORMATIONAL → info.
When Label is absent, Severity.Normalized is mapped with AWS's documented
ranges: 0 → info, 1–39 → low, 40–69 → medium, 70–89 → high, 90–100 → critical.
With neither present the finding is kept as info and providerSeverity is None,
so the UI can show that the provider did not rate it.

Status mapping:
    RecordState ARCHIVED           → resolved  (AWS hides archived findings)
    Workflow.Status RESOLVED       → resolved
    Workflow.Status SUPPRESSED     → suppressed
    Workflow.Status NEW / NOTIFIED → open
"""
from __future__ import annotations

import re
from typing import Any, Optional

from cloud.models import (
    NormalizedAsset, NormalizedFinding,
    STATUS_OPEN, STATUS_RESOLVED, STATUS_SUPPRESSED,
)
from cloud.normalizers.common import (
    MAX_LIST, MAX_TITLE, clip, cve_ids, fingerprint, iso, opt, raw_json, safe_float, str_dict,
)

PROVIDER = "aws"
_SERVICE_RE = re.compile(r"^Aws([A-Z][a-z0-9]+)")

_LABELS = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFORMATIONAL": "info",
}


def severity(sev: Any) -> tuple[str, Optional[str]]:
    if not isinstance(sev, dict):
        return "info", None
    label = sev.get("Label")
    if isinstance(label, str) and label.upper() in _LABELS:
        return _LABELS[label.upper()], label.upper()
    normalized = sev.get("Normalized")
    if isinstance(normalized, (int, float)) and 0 <= normalized <= 100:
        n = int(normalized)
        mapped = ("info" if n == 0 else "low" if n < 40 else "medium" if n < 70
                  else "high" if n < 90 else "critical")
        return mapped, f"NORMALIZED:{n}"
    return "info", None


def status(finding: dict) -> tuple[str, str]:
    record = str(finding.get("RecordState") or "ACTIVE").upper()
    workflow = str((finding.get("Workflow") or {}).get("Status") or "NEW").upper()
    provider_status = f"{record}/{workflow}"
    if record == "ARCHIVED" or workflow == "RESOLVED":
        return STATUS_RESOLVED, provider_status
    if workflow == "SUPPRESSED":
        return STATUS_SUPPRESSED, provider_status
    return STATUS_OPEN, provider_status


def _best_cvss(vulns: list[dict]) -> tuple[Optional[float], Optional[str]]:
    """Highest CVSS base score, preferring v3/v4 vectors over v2."""
    best: tuple[int, float, Optional[str]] | None = None
    for v in vulns:
        for c in v.get("Cvss") or []:
            score = safe_float(c.get("BaseScore"))
            if score is None:
                continue
            version = str(c.get("Version") or "")
            rank = 2 if version.upper().startswith(("V3", "3", "V4", "4")) else 1
            candidate = (rank, score, opt(c.get("BaseVector"), 200))
            if best is None or candidate[:2] > best[:2]:
                best = candidate
    return (best[1], best[2]) if best else (None, None)


def asset_for(resource: dict, integration_id: str, account_id: Optional[str], region: Optional[str]) -> NormalizedAsset:
    resource_id = clip(resource.get("Id") or "unknown", 1_000)
    resource_type = clip(resource.get("Type") or "Other", 200)
    name = resource_id.rsplit("/", 1)[-1].rsplit(":", 1)[-1] if resource_id else None
    # "AwsEc2Instance" → "Ec2"; keeps the service family for grouping.
    m = _SERVICE_RE.match(resource_type)
    service = m.group(1) if m else None
    return NormalizedAsset(
        assetId=fingerprint(PROVIDER, integration_id, resource_id),
        provider=PROVIDER,
        integrationId=integration_id,
        accountId=account_id,
        region=opt(resource.get("Region"), 64) or region,
        resourceType=resource_type,
        resourceId=resource_id,
        resourceName=opt(name, 300),
        service=service,
        tags=str_dict(resource.get("Tags")),
    )


def normalize(finding: dict, integration_id: str) -> tuple[NormalizedFinding, list[NormalizedAsset]]:
    """Raises ValueError when the payload lacks the identifiers ASFF requires."""
    if not isinstance(finding, dict):
        raise ValueError("finding is not an object")
    finding_id = finding.get("Id")
    product_arn = finding.get("ProductArn")
    if not isinstance(finding_id, str) or not finding_id or not isinstance(product_arn, str):
        raise ValueError("finding is missing Id or ProductArn")

    account_id = opt(finding.get("AwsAccountId"), 32)
    region = opt(finding.get("Region"), 64)

    resources = [r for r in (finding.get("Resources") or []) if isinstance(r, dict)][:MAX_LIST]
    assets = [asset_for(r, integration_id, account_id, region) for r in resources]
    primary = assets[0] if assets else None

    vulns = [v for v in (finding.get("Vulnerabilities") or []) if isinstance(v, dict)][:MAX_LIST]
    cves = cve_ids([v.get("Id") for v in vulns])
    cvss, vector = _best_cvss(vulns)
    packages = []
    for v in vulns:
        for p in (v.get("VulnerablePackages") or [])[:MAX_LIST]:
            if isinstance(p, dict) and p.get("Name"):
                packages.append({
                    "name": clip(p.get("Name"), 200),
                    "version": opt(p.get("Version"), 100),
                    "fixedInVersion": opt(p.get("FixedInVersion"), 100),
                    "packageManager": opt(p.get("PackageManager"), 50),
                    "cve": opt(v.get("Id"), 40),
                })
    packages = packages[:MAX_LIST]

    compliance_src = finding.get("Compliance") if isinstance(finding.get("Compliance"), dict) else {}
    compliance = {
        k: v for k, v in {
            "status": opt(compliance_src.get("Status"), 40),
            "securityControlId": opt(compliance_src.get("SecurityControlId"), 80),
            "relatedRequirements": [clip(r, 120) for r in (compliance_src.get("RelatedRequirements") or [])][:MAX_LIST],
        }.items() if v
    }

    remediation = (finding.get("Remediation") or {}).get("Recommendation") or {}
    sev, provider_sev = severity(finding.get("Severity"))
    st, provider_st = status(finding)
    types = [t for t in (finding.get("Types") or []) if isinstance(t, str)]

    normalized = NormalizedFinding(
        fingerprint=fingerprint(PROVIDER, integration_id, product_arn, finding_id),
        provider=PROVIDER,
        integrationId=integration_id,
        providerFindingId=clip(finding_id, 1_000),
        providerProduct=opt(finding.get("ProductName"), 120) or opt(product_arn.rsplit("/", 1)[-1], 120),
        title=clip(finding.get("Title") or "Untitled finding", MAX_TITLE),
        description=clip(finding.get("Description")),
        severity=sev,
        providerSeverity=provider_sev,
        status=st,
        providerStatus=provider_st,
        findingType=opt(types[0], 300) if types else None,
        findingClass="VULNERABILITY" if cves else None,
        assetId=primary.assetId if primary else None,
        resourceType=primary.resourceType if primary else None,
        resourceId=primary.resourceId if primary else None,
        resourceName=primary.resourceName if primary else None,
        accountId=account_id,
        region=region,
        cveIds=cves,
        cveId=cves[0] if cves else None,
        cvssScore=cvss,
        cvssVector=vector,
        affectedPackages=packages,
        compliance=compliance,
        recommendation=opt(remediation.get("Text"), 4_000),
        remediationUrl=_https(remediation.get("Url")),
        sourceUrl=_https(finding.get("SourceUrl")),
        providerCreatedAt=iso(finding.get("CreatedAt")),
        providerUpdatedAt=iso(finding.get("UpdatedAt")),
        firstObservedAt=iso(finding.get("FirstObservedAt")),
        lastObservedAt=iso(finding.get("LastObservedAt")) or iso(finding.get("UpdatedAt")),
        rawProviderMetadata=raw_json({
            k: finding.get(k) for k in (
                "Id", "ProductArn", "GeneratorId", "Types", "Severity", "Compliance",
                "Workflow", "RecordState", "ProductFields", "Resources", "Vulnerabilities",
            ) if k in finding
        }),
    )
    return normalized, assets


def _https(url: Any) -> Optional[str]:
    """Only http(s) links are kept, so a provider payload cannot inject javascript: URLs."""
    if isinstance(url, str) and url.lower().startswith(("https://", "http://")) and len(url) <= 2_000:
        return url
    return None
