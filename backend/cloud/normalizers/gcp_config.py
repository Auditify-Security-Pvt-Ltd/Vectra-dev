"""
Google Cloud configuration analysis → normalized Vectra findings and assets.

Deterministic checks over resource configuration read from Google Cloud APIs
(Compute Engine, Cloud Storage, Resource Manager, IAM). A finding is produced
only when the retrieved configuration itself is the evidence, and that evidence
is stored with the finding. Nothing is inferred from resources that were not
read, and nothing is raised for settings Google Cloud enforces anyway (Cloud
Storage always encrypts data at rest, so "missing encryption" is never claimed).

Instance metadata is never copied: startup scripts and custom metadata can hold
secrets, so only the single `serial-port-enable` flag is inspected.

Control references are the CIS Google Cloud Platform Foundation Benchmark.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from cloud.models import NormalizedAsset, NormalizedFinding, STATUS_OPEN
from cloud.normalizers.common import MAX_LIST, clip, fingerprint, iso, opt, raw_json

PROVIDER = "gcp"
SOURCE = "gcp-configuration-analysis"
PRODUCT = "Vectra Configuration Analysis"

# Resolution scopes: one per collection, so a failed read never resolves
# findings belonging to it.
SCOPE_INSTANCES = "Compute Engine instances"
SCOPE_FIREWALLS = "VPC firewall rules"
SCOPE_STORAGE = "Cloud Storage buckets"
SCOPE_PROJECT_IAM = "Project IAM policy"
SCOPE_SERVICE_ACCOUNTS = "Service accounts"

INTERNET_V4 = ipaddress.ip_network("0.0.0.0/0")
INTERNET_V6 = ipaddress.ip_network("::/0")

KEY_ROTATION_DAYS = 90

DEFAULT_COMPUTE_SA_RE = re.compile(r"^\d+-compute@developer\.gserviceaccount\.com$")
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# Ports whose exposure to the whole internet is a well-known attack path.
SENSITIVE_PORTS: dict[int, str] = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 2375: "Docker API", 2379: "etcd",
    3306: "MySQL", 5432: "PostgreSQL", 5601: "Kibana", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: str
    category: str
    scope: str
    description: str
    remediation: str
    controls: tuple[str, ...] = ()


CHECKS: dict[str, Check] = {c.id: c for c in (
    Check("GCP_FIREWALL_ALL_PORTS_OPEN_TO_INTERNET", "Firewall rule allows all ports from the internet", "critical",
          "Network", SCOPE_FIREWALLS,
          "An enabled ingress firewall rule allows every port of a protocol from any internet address.",
          "Restrict the rule to the specific ports your service needs and to known source ranges, "
          "or delete it. Prefer Identity-Aware Proxy for administrative access."),
    Check("GCP_FIREWALL_SSH_OPEN_TO_INTERNET", "SSH is open to the internet", "high", "Network", SCOPE_FIREWALLS,
          "An enabled ingress firewall rule allows TCP port 22 from any internet address.",
          "Remove 0.0.0.0/0 (and ::/0) from the rule's source ranges. Use Identity-Aware Proxy TCP forwarding "
          "(source 35.235.240.0/20) or a bastion with a restricted source range.",
          ("CIS GCP 3.6",)),
    Check("GCP_FIREWALL_RDP_OPEN_TO_INTERNET", "RDP is open to the internet", "high", "Network", SCOPE_FIREWALLS,
          "An enabled ingress firewall rule allows TCP port 3389 from any internet address.",
          "Remove 0.0.0.0/0 (and ::/0) from the rule's source ranges and use Identity-Aware Proxy or a VPN.",
          ("CIS GCP 3.7",)),
    Check("GCP_FIREWALL_SENSITIVE_PORT_OPEN_TO_INTERNET", "Sensitive service port open to the internet", "high",
          "Network", SCOPE_FIREWALLS,
          "An enabled ingress firewall rule exposes a database, cache or management port to any internet address.",
          "Limit the source ranges to the application tiers that need the service, or reach it through "
          "private networking only."),
    Check("GCP_VM_PUBLIC_IP", "VM instance has an external IP address", "low", "Compute", SCOPE_INSTANCES,
          "The instance has an external (public) IP address, so it is reachable from the internet wherever "
          "firewall rules allow it.",
          "Remove the external IP if the instance does not need direct inbound access; use Cloud NAT for "
          "outbound traffic and a load balancer or Identity-Aware Proxy for inbound access.",
          ("CIS GCP 4.9",)),
    Check("GCP_VM_DEFAULT_SA_FULL_API_ACCESS",
          "VM uses the default service account with full Cloud API access", "high", "Compute", SCOPE_INSTANCES,
          "The instance runs as the Compute Engine default service account with the cloud-platform access "
          "scope, so code on the VM can use every permission that account holds (Editor by default).",
          "Attach a dedicated least-privilege service account, or restrict the access scopes.",
          ("CIS GCP 4.2",)),
    Check("GCP_VM_DEFAULT_SERVICE_ACCOUNT", "VM uses the Compute Engine default service account", "medium",
          "Compute", SCOPE_INSTANCES,
          "The instance runs as the Compute Engine default service account, which is granted the Editor role "
          "on the project by default.",
          "Attach a dedicated service account with only the permissions the workload needs.",
          ("CIS GCP 4.1",)),
    Check("GCP_VM_SERIAL_PORT_ENABLED", "Interactive serial console access is enabled", "medium", "Compute",
          SCOPE_INSTANCES,
          "The instance metadata enables interactive serial port access, which accepts connections from any "
          "IP address and bypasses firewall rules.",
          "Set the instance metadata key serial-port-enable to false.",
          ("CIS GCP 4.5",)),
    Check("GCP_VM_IP_FORWARDING_ENABLED", "IP forwarding is enabled on the VM", "medium", "Compute",
          SCOPE_INSTANCES,
          "The instance can send and receive packets with non-matching source or destination IPs, which lets "
          "it route traffic and bypass network controls.",
          "Disable IP forwarding unless the instance is a deliberate network appliance (recreate the instance "
          "with canIpForward=false).",
          ("CIS GCP 4.6",)),
    Check("GCP_VM_SECURE_BOOT_DISABLED", "Shielded VM Secure Boot is disabled", "low", "Compute", SCOPE_INSTANCES,
          "Secure Boot is turned off, so the instance does not verify its boot components' signatures.",
          "Enable Secure Boot in the instance's Shielded VM settings (requires stopping the instance).",
          ("CIS GCP 4.8",)),
    Check("GCP_STORAGE_BUCKET_PUBLIC", "Cloud Storage bucket is publicly accessible", "critical", "Storage",
          SCOPE_STORAGE,
          "The bucket's IAM policy grants access to allUsers or allAuthenticatedUsers and public access "
          "prevention is not enforced.",
          "Remove allUsers and allAuthenticatedUsers from the bucket IAM policy and enforce public access "
          "prevention on the bucket or organization.",
          ("CIS GCP 5.1",)),
    Check("GCP_STORAGE_UNIFORM_ACCESS_DISABLED", "Uniform bucket-level access is disabled", "medium", "Storage",
          SCOPE_STORAGE,
          "The bucket uses fine-grained ACLs, so individual objects can be shared independently of the bucket's "
          "IAM policy.",
          "Enable uniform bucket-level access on the bucket.",
          ("CIS GCP 5.2",)),
    Check("GCP_IAM_PUBLIC_PRINCIPAL", "Project IAM policy grants access to the public", "critical", "IAM",
          SCOPE_PROJECT_IAM,
          "The project IAM policy includes allUsers or allAuthenticatedUsers.",
          "Remove allUsers and allAuthenticatedUsers from the project IAM policy."),
    Check("GCP_IAM_SERVICE_ACCOUNT_PRIMITIVE_ROLE", "Service account has a basic (Owner/Editor) role", "high",
          "IAM", SCOPE_PROJECT_IAM,
          "A service account is granted a basic role on the project, giving any holder of its credentials "
          "broad control over project resources.",
          "Replace the basic role with predefined or custom roles that grant only the permissions needed.",
          ("CIS GCP 1.5",)),
    Check("GCP_IAM_PROJECT_LEVEL_SA_IMPERSONATION",
          "Service account impersonation granted at project level", "medium", "IAM", SCOPE_PROJECT_IAM,
          "A user or group holds Service Account User or Token Creator on the whole project, so it can act as "
          "every service account in the project.",
          "Grant these roles on the specific service accounts that need them instead of the project.",
          ("CIS GCP 1.6",)),
    Check("GCP_IAM_USER_MANAGED_SA_KEY", "Service account has user-managed keys", "low", "IAM",
          SCOPE_SERVICE_ACCOUNTS,
          "The service account has active user-managed keys. Downloaded keys are long-lived credentials that "
          "can leak outside Google Cloud.",
          "Prefer workload identity federation or attached service accounts; delete keys that are not needed.",
          ("CIS GCP 1.4",)),
    Check("GCP_IAM_SA_KEY_NOT_ROTATED", f"Service account key older than {KEY_ROTATION_DAYS} days", "medium",
          "IAM", SCOPE_SERVICE_ACCOUNTS,
          f"An active user-managed service account key was created more than {KEY_ROTATION_DAYS} days ago.",
          "Create a new key, move workloads to it, then delete the old key.",
          ("CIS GCP 1.7",)),
)}


# ── Assets ────────────────────────────────────────────────────────────

def _asset(integration_id: str, project_id: str, resource_type: str, resource_id: str,
           name: Optional[str], region: Optional[str], service: str, tags: Optional[dict] = None) -> NormalizedAsset:
    return NormalizedAsset(
        assetId=fingerprint(PROVIDER, integration_id, resource_id),
        provider=PROVIDER,
        integrationId=integration_id,
        accountId=project_id,
        region=region,
        resourceType=resource_type,
        resourceId=resource_id,
        resourceName=opt(name, 300),
        service=service,
        tags={clip(k, 128): clip(v, 256) for k, v in list((tags or {}).items())[:50]} if isinstance(tags, dict) else {},
    )


def _last(url: Any) -> Optional[str]:
    return url.rstrip("/").rsplit("/", 1)[-1] if isinstance(url, str) and url else None


def project_asset(integration_id: str, project: dict) -> NormalizedAsset:
    pid = project.get("projectId") or ""
    number = _last(project.get("name")) or pid
    return _asset(integration_id, pid, "google.cloud.resourcemanager.Project",
                  f"//cloudresourcemanager.googleapis.com/projects/{number}",
                  project.get("displayName") or pid, "global", "cloudresourcemanager")


def instance_asset(integration_id: str, project_id: str, inst: dict) -> NormalizedAsset:
    zone = _last(inst.get("zone"))
    return _asset(integration_id, project_id, "google.compute.Instance",
                  f"//compute.googleapis.com/projects/{project_id}/zones/{zone}/instances/{inst.get('name')}",
                  inst.get("name"), zone, "compute", inst.get("labels"))


def firewall_asset(integration_id: str, project_id: str, rule: dict) -> NormalizedAsset:
    return _asset(integration_id, project_id, "google.compute.Firewall",
                  f"//compute.googleapis.com/projects/{project_id}/global/firewalls/{rule.get('name')}",
                  rule.get("name"), "global", "compute")


def bucket_asset(integration_id: str, project_id: str, bucket: dict) -> NormalizedAsset:
    return _asset(integration_id, project_id, "google.cloud.storage.Bucket",
                  f"//storage.googleapis.com/{bucket.get('name')}",
                  bucket.get("name"), (bucket.get("location") or "").lower() or None, "storage", bucket.get("labels"))


def service_account_asset(integration_id: str, project_id: str, sa: dict) -> NormalizedAsset:
    return _asset(integration_id, project_id, "google.iam.ServiceAccount",
                  f"//iam.googleapis.com/projects/{project_id}/serviceAccounts/{sa.get('uniqueId') or sa.get('email')}",
                  sa.get("email"), "global", "iam")


# ── Finding builder ───────────────────────────────────────────────────

def _finding(check_id: str, integration_id: str, asset: NormalizedAsset, evidence: dict,
             discriminator: str = "", title: Optional[str] = None, severity: Optional[str] = None,
             description_suffix: str = "") -> NormalizedFinding:
    check = CHECKS[check_id]
    provider_id = f"{check_id}:{asset.resourceId}" + (f":{discriminator}" if discriminator else "")
    return NormalizedFinding(
        fingerprint=fingerprint(PROVIDER, integration_id, SOURCE, provider_id),
        provider=PROVIDER,
        integrationId=integration_id,
        providerFindingId=clip(provider_id, 1_000),
        providerProduct=PRODUCT,
        title=clip(title or check.title, 300),
        description=clip(check.description + (f" {description_suffix}" if description_suffix else "")),
        severity=severity or check.severity,
        providerSeverity=None,  # Vectra's own rating; Google did not rate this
        status=STATUS_OPEN,
        providerStatus="ACTIVE",
        findingType=check_id,
        findingClass="MISCONFIGURATION",
        assetId=asset.assetId,
        resourceType=asset.resourceType,
        resourceId=asset.resourceId,
        resourceName=asset.resourceName,
        accountId=asset.accountId,
        region=asset.region,
        compliance={"relatedRequirements": list(check.controls)} if check.controls else {},
        recommendation=check.remediation,
        source=SOURCE,
        category=check.category,
        evidence=evidence,
        scope=check.scope,
        rawProviderMetadata=raw_json({"check": check_id, "evidence": evidence}),
    )


# ── Firewall rules ────────────────────────────────────────────────────

def _is_internet(ranges: Iterable[Any]) -> list[str]:
    out = []
    for r in ranges or []:
        try:
            net = ipaddress.ip_network(str(r).strip(), strict=False)
        except ValueError:
            continue
        if net in (INTERNET_V4, INTERNET_V6):
            out.append(str(net))
    return out


def _port_ranges(entry: dict) -> Optional[list[tuple[int, int]]]:
    """None → every port of the protocol; otherwise inclusive (low, high) ranges."""
    ports = entry.get("ports")
    if not ports:
        return None
    ranges = []
    for p in ports:
        text = str(p).strip()
        try:
            if "-" in text:
                lo, hi = (int(x) for x in text.split("-", 1))
            else:
                lo = hi = int(text)
        except ValueError:
            continue
        if 0 <= lo <= hi <= 65535:
            ranges.append((lo, hi))
    return ranges


def _applies_to_all_instances(rule: dict) -> bool:
    return not rule.get("targetTags") and not rule.get("targetServiceAccounts")


def _denied_by_higher_priority(rule: dict, protocol: str, port: Optional[int], denies: list[dict]) -> bool:
    """A lower-priority-number DENY on the same network, from the whole internet, to every instance, wins."""
    for d in denies:
        if d.get("network") != rule.get("network"):
            continue
        if int(d.get("priority", 1000)) >= int(rule.get("priority", 1000)):
            continue
        if not _applies_to_all_instances(d) or not _is_internet(d.get("sourceRanges")):
            continue
        for entry in d.get("denied") or []:
            proto = str(entry.get("IPProtocol", "")).lower()
            if proto not in ("all", protocol):
                continue
            ranges = _port_ranges(entry)
            if ranges is None or (port is not None and any(lo <= port <= hi for lo, hi in ranges)):
                return True
    return False


def analyze_firewalls(integration_id: str, project_id: str, rules: list[dict]) -> tuple[list[NormalizedFinding], list[NormalizedAsset]]:
    findings: list[NormalizedFinding] = []
    assets: list[NormalizedAsset] = []
    ingress = [r for r in rules if isinstance(r, dict) and str(r.get("direction") or "INGRESS").upper() == "INGRESS"
               and not r.get("disabled")]
    denies = [r for r in ingress if r.get("denied")]

    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("name"):
            continue
        asset = firewall_asset(integration_id, project_id, rule)
        assets.append(asset)
        if rule not in ingress or not rule.get("allowed"):
            continue
        internet = _is_internet(rule.get("sourceRanges"))
        if not internet:
            continue

        evidence_base = {
            "rule": rule.get("name"),
            "network": _last(rule.get("network")),
            "direction": "INGRESS",
            "priority": rule.get("priority", 1000),
            "sourceRanges": internet,
            "targetTags": list(rule.get("targetTags") or [])[:MAX_LIST],
            "targetServiceAccounts": list(rule.get("targetServiceAccounts") or [])[:MAX_LIST],
            "appliesTo": "all instances in the network" if _applies_to_all_instances(rule) else "tagged or service-account-targeted instances",
        }
        all_ports: list[str] = []
        exposed: dict[int, str] = {}
        for entry in rule.get("allowed") or []:
            proto = str(entry.get("IPProtocol", "")).lower()
            ranges = _port_ranges(entry)
            if proto == "all" or (proto in ("tcp", "udp", "sctp") and ranges is None):
                if not _denied_by_higher_priority(rule, proto if proto != "all" else "tcp", None, denies):
                    all_ports.append("all protocols" if proto == "all" else f"all {proto.upper()} ports")
                continue
            if proto != "tcp" or ranges is None:
                continue
            for port in [22, 3389, *SENSITIVE_PORTS]:
                if any(lo <= port <= hi for lo, hi in ranges) and not _denied_by_higher_priority(rule, "tcp", port, denies):
                    exposed[port] = "SSH" if port == 22 else "RDP" if port == 3389 else SENSITIVE_PORTS[port]

        if all_ports:
            findings.append(_finding("GCP_FIREWALL_ALL_PORTS_OPEN_TO_INTERNET", integration_id, asset,
                                     {**evidence_base, "allowed": all_ports}))
            continue  # the specific-port findings would only repeat this one
        if 22 in exposed:
            findings.append(_finding("GCP_FIREWALL_SSH_OPEN_TO_INTERNET", integration_id, asset,
                                     {**evidence_base, "allowed": ["tcp:22"]}))
        if 3389 in exposed:
            findings.append(_finding("GCP_FIREWALL_RDP_OPEN_TO_INTERNET", integration_id, asset,
                                     {**evidence_base, "allowed": ["tcp:3389"]}))
        sensitive = {p: s for p, s in exposed.items() if p in SENSITIVE_PORTS}
        if sensitive:
            services = ", ".join(f"{s} ({p})" for p, s in sorted(sensitive.items()))
            findings.append(_finding("GCP_FIREWALL_SENSITIVE_PORT_OPEN_TO_INTERNET", integration_id, asset,
                                     {**evidence_base, "allowed": [f"tcp:{p}" for p in sorted(sensitive)]},
                                     title=f"Sensitive service port open to the internet: {services}"))
    return findings, assets


# ── Compute instances ─────────────────────────────────────────────────

def _is_gke_node(inst: dict) -> bool:
    return "goog-gke-node" in (inst.get("labels") or {})


def analyze_instance(integration_id: str, project_id: str, inst: dict) -> tuple[list[NormalizedFinding], NormalizedAsset]:
    asset = instance_asset(integration_id, project_id, inst)
    findings: list[NormalizedFinding] = []
    base = {"instance": inst.get("name"), "zone": _last(inst.get("zone")), "status": inst.get("status")}

    for nic in inst.get("networkInterfaces") or []:
        for ac in nic.get("accessConfigs") or []:
            if ac.get("natIP"):
                findings.append(_finding("GCP_VM_PUBLIC_IP", integration_id, asset,
                                         {**base, "networkInterface": nic.get("name"), "network": _last(nic.get("network")),
                                          "externalIp": ac.get("natIP"), "accessConfigType": ac.get("type")},
                                         discriminator=f"{nic.get('name')}:{ac.get('natIP')}"))

    if not _is_gke_node(inst):
        for sa in inst.get("serviceAccounts") or []:
            email = str(sa.get("email") or "")
            if not DEFAULT_COMPUTE_SA_RE.match(email):
                continue
            scopes = list(sa.get("scopes") or [])
            evidence = {**base, "serviceAccount": email, "scopes": scopes[:MAX_LIST]}
            if CLOUD_PLATFORM_SCOPE in scopes:
                findings.append(_finding("GCP_VM_DEFAULT_SA_FULL_API_ACCESS", integration_id, asset, evidence))
            else:
                findings.append(_finding("GCP_VM_DEFAULT_SERVICE_ACCOUNT", integration_id, asset, evidence))

        if inst.get("canIpForward") is True:
            findings.append(_finding("GCP_VM_IP_FORWARDING_ENABLED", integration_id, asset, {**base, "canIpForward": True}))

    for item in (inst.get("metadata") or {}).get("items") or []:
        if item.get("key") == "serial-port-enable" and str(item.get("value")).strip().lower() in ("true", "1"):
            findings.append(_finding("GCP_VM_SERIAL_PORT_ENABLED", integration_id, asset,
                                     {**base, "metadataKey": "serial-port-enable", "value": str(item.get("value"))}))

    shielded = inst.get("shieldedInstanceConfig")
    if isinstance(shielded, dict) and shielded.get("enableSecureBoot") is False:
        findings.append(_finding("GCP_VM_SECURE_BOOT_DISABLED", integration_id, asset,
                                 {**base, "enableSecureBoot": False}))
    return findings, asset


# ── Cloud Storage ─────────────────────────────────────────────────────

PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")


def analyze_bucket(integration_id: str, project_id: str, bucket: dict,
                   iam_policy: Optional[dict]) -> tuple[list[NormalizedFinding], NormalizedAsset]:
    """iam_policy None means it could not be read: public access is then not assessed."""
    asset = bucket_asset(integration_id, project_id, bucket)
    findings: list[NormalizedFinding] = []
    iam_cfg = bucket.get("iamConfiguration") or {}
    prevention = iam_cfg.get("publicAccessPrevention")

    if iam_policy is not None and str(prevention).lower() != "enforced":
        grants = [{"role": b.get("role"), "member": m}
                  for b in iam_policy.get("bindings") or [] for m in b.get("members") or [] if m in PUBLIC_MEMBERS]
        if grants:
            severity = "critical" if any(g["member"] == "allUsers" for g in grants) else "high"
            findings.append(_finding("GCP_STORAGE_BUCKET_PUBLIC", integration_id, asset,
                                     {"bucket": bucket.get("name"), "publicGrants": grants[:MAX_LIST],
                                      "publicAccessPrevention": prevention or "inherited"},
                                     severity=severity))

    ubla = iam_cfg.get("uniformBucketLevelAccess") or {}
    if ubla.get("enabled") is False:
        findings.append(_finding("GCP_STORAGE_UNIFORM_ACCESS_DISABLED", integration_id, asset,
                                 {"bucket": bucket.get("name"), "uniformBucketLevelAccess": False}))
    return findings, asset


# ── Project IAM policy ────────────────────────────────────────────────

GOOGLE_MANAGED_SA_SUFFIXES = ("@cloudservices.gserviceaccount.com",)
IMPERSONATION_ROLES = ("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator")


def analyze_project_iam(integration_id: str, project: dict, policy: dict) -> tuple[list[NormalizedFinding], NormalizedAsset]:
    asset = project_asset(integration_id, project)
    findings: list[NormalizedFinding] = []
    for binding in policy.get("bindings") or []:
        role = str(binding.get("role") or "")
        condition = (binding.get("condition") or {}).get("title")
        for member in binding.get("members") or []:
            member = str(member)
            evidence = {"role": role, "member": member, **({"condition": condition} if condition else {})}
            disc = f"{role}:{member}"
            if member in PUBLIC_MEMBERS:
                findings.append(_finding("GCP_IAM_PUBLIC_PRINCIPAL", integration_id, asset, evidence, discriminator=disc))
            elif member.startswith("serviceAccount:") and role in ("roles/owner", "roles/editor") \
                    and not member.endswith(GOOGLE_MANAGED_SA_SUFFIXES):
                findings.append(_finding("GCP_IAM_SERVICE_ACCOUNT_PRIMITIVE_ROLE", integration_id, asset, evidence,
                                         discriminator=disc, severity="high" if role == "roles/owner" else "medium",
                                         title=f"Service account has the {role.rsplit('/', 1)[-1].title()} role"))
            elif role in IMPERSONATION_ROLES and member.startswith(("user:", "group:", "domain:")):
                findings.append(_finding("GCP_IAM_PROJECT_LEVEL_SA_IMPERSONATION", integration_id, asset, evidence,
                                         discriminator=disc))
    return findings, asset


# ── Service accounts ──────────────────────────────────────────────────

def _key_id(key: dict) -> str:
    return _last(key.get("name")) or ""


def analyze_service_account(integration_id: str, project_id: str, sa: dict, keys: Optional[list[dict]],
                            now: Optional[datetime] = None) -> tuple[list[NormalizedFinding], NormalizedAsset]:
    """keys None means they could not be listed: key checks are then skipped."""
    asset = service_account_asset(integration_id, project_id, sa)
    findings: list[NormalizedFinding] = []
    if sa.get("disabled") or keys is None:
        return findings, asset
    now = now or datetime.now(timezone.utc)
    active = [k for k in keys if isinstance(k, dict) and k.get("keyType", "USER_MANAGED") == "USER_MANAGED"
              and not k.get("disabled")]
    if not active:
        return findings, asset

    # Key ids identify keys (like an AWS access key id); they are not secret, but
    # only a suffix is kept since the full id adds nothing to remediation.
    summary = [{"keyIdSuffix": _key_id(k)[-8:], "createdAt": iso(k.get("validAfterTime"))} for k in active[:MAX_LIST]]
    findings.append(_finding("GCP_IAM_USER_MANAGED_SA_KEY", integration_id, asset,
                             {"serviceAccount": sa.get("email"), "activeUserManagedKeys": len(active), "keys": summary}))
    for k in active:
        created = iso(k.get("validAfterTime"))
        if not created:
            continue
        age = (now - datetime.fromisoformat(created)).days
        if age > KEY_ROTATION_DAYS:
            findings.append(_finding("GCP_IAM_SA_KEY_NOT_ROTATED", integration_id, asset,
                                     {"serviceAccount": sa.get("email"), "keyIdSuffix": _key_id(k)[-8:],
                                      "createdAt": created, "ageDays": age},
                                     discriminator=fingerprint(_key_id(k))[:16]))
    return findings, asset
