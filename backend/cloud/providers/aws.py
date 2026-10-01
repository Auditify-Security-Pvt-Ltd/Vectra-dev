"""
AWS connector — AWS Security Hub (GetFindings, ASFF).

Authentication (no root credentials, read-only):
  * assume_role (recommended): Vectra's own AWS principal calls sts:AssumeRole
    on a customer role with an organization-specific ExternalId.
  * access_key: long-term keys of a dedicated read-only IAM user, encrypted at
    rest by cloud.secrets.

Required customer permissions: securityhub:GetFindings, securityhub:DescribeHub.

Security Hub is regional; each configured region is fetched independently so a
failure in one region never hides findings from the others. If cross-Region
aggregation is enabled, configuring only the aggregation Region is sufficient.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Optional

from cloud import secrets
from cloud.errors import CloudProviderError, ConfigurationError
from cloud.models import FetchResult, ValidationResult
from cloud.normalizers import aws as normalizer
from cloud.providers.base import AuthMethod, CloudProvider, ProviderSession
from utils.logger import get_logger

logger = get_logger(__name__)

ROLE_ARN_RE = re.compile(r"^arn:aws(-us-gov)?:iam::(\d{12}):role/[\w+=,.@/-]{1,512}$")
REGION_RE = re.compile(r"^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d{1,2}$")
ACCESS_KEY_RE = re.compile(r"^AKIA[A-Z0-9]{16}$")
SECRET_KEY_RE = re.compile(r"^[A-Za-z0-9/+=]{40}$")
MAX_REGIONS = 20
PAGE_SIZE = 100  # GetFindings MaxResults maximum

PLATFORM_PRINCIPAL_ENV = "VECTRA_AWS_PRINCIPAL_ARN"

PERMISSIONS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "VectraSecurityHubReadOnly",
        "Effect": "Allow",
        "Action": ["securityhub:GetFindings", "securityhub:DescribeHub"],
        "Resource": "*",
    }],
}


def _boto_config():
    from botocore.config import Config
    return Config(
        retries={"max_attempts": 6, "mode": "adaptive"},  # bounded; throttling-aware
        connect_timeout=10,
        read_timeout=30,
        user_agent_extra="vectra-cloud-security",
    )


def map_aws_error(exc: Exception, context: str = "") -> CloudProviderError:
    """Translate botocore exceptions into user-safe errors (no raw messages)."""
    from botocore.exceptions import (
        ClientError, ConnectTimeoutError, EndpointConnectionError, NoCredentialsError,
        ParamValidationError, ReadTimeoutError,
    )

    where = f" ({context})" if context else ""
    if isinstance(exc, CloudProviderError):
        return exc
    if isinstance(exc, NoCredentialsError):
        return CloudProviderError(
            CloudProviderError.NOT_CONFIGURED,
            "Vectra's AWS identity is not configured on this deployment.",
            "Use access-key authentication, or ask an administrator to configure Vectra's AWS principal.",
        )
    if isinstance(exc, (ConnectTimeoutError, ReadTimeoutError, EndpointConnectionError)):
        return CloudProviderError(CloudProviderError.TIMEOUT, f"AWS did not respond in time{where}.",
                                  "Retry the sync. If it persists, check the Region names.")
    if isinstance(exc, ParamValidationError):
        return CloudProviderError(CloudProviderError.INVALID_CONFIGURATION, f"AWS rejected the request parameters{where}.")
    if isinstance(exc, ClientError):
        code = (exc.response.get("Error") or {}).get("Code", "")
        if code in {"InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException", "ExpiredToken", "ExpiredTokenException", "AuthFailure"}:
            return CloudProviderError(CloudProviderError.INVALID_CREDENTIALS, "AWS rejected the credentials.",
                                      "Check that the access key is active, or reconnect with a new key.")
        if code == "InvalidAccessException":
            return CloudProviderError(CloudProviderError.SERVICE_NOT_ENABLED, f"Security Hub is not enabled{where}.",
                                      "Enable AWS Security Hub in this Region, or remove the Region from the integration.")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            return CloudProviderError(CloudProviderError.ACCESS_DENIED, f"Access denied by AWS{where}.",
                                      "Required: securityhub:GetFindings and securityhub:DescribeHub (and a trust policy with Vectra's ExternalId for role access).")
        if code in {"LimitExceededException", "ThrottlingException", "TooManyRequestsException", "Throttling"}:
            return CloudProviderError(CloudProviderError.THROTTLED, f"AWS throttled the request{where}.", "Retry the sync in a few minutes.")
        if code in {"InvalidInputException", "ValidationError", "ValidationException"}:
            return CloudProviderError(CloudProviderError.INVALID_CONFIGURATION, f"AWS rejected the integration settings{where}.")
        return CloudProviderError(CloudProviderError.PROVIDER_ERROR, f"AWS returned an error{where}: {code or 'unknown'}.")
    return CloudProviderError(CloudProviderError.PROVIDER_ERROR, f"Unexpected error while contacting AWS{where}.")


class AWSProvider(CloudProvider):
    key = "aws"
    display_name = "Amazon Web Services"
    security_service = "AWS Security Hub"
    auth_methods = [
        AuthMethod("assume_role", "IAM role (recommended)",
                   "Vectra assumes a read-only role in your account using an ExternalId unique to your organization. No keys are shared.",
                   recommended=True),
        AuthMethod("access_key", "Access key",
                   "Long-term access key of a dedicated read-only IAM user. Stored encrypted; never shown again.",
                   requires_secret=True),
    ]
    capabilities = {
        "findings": "available",
        "vulnerability_metadata": "available",
        "compliance": "available",
        "assets": "derived",               # resources referenced by findings
        "asset_inventory": "future",
        "iam_analysis": "future",
        "configuration_analysis": "future",
    }

    # ── Config ────────────────────────────────────────────────────────

    def parse_config(self, auth_method, config, credentials):
        regions = config.get("regions")
        if isinstance(regions, str):
            regions = [r.strip() for r in regions.split(",")]
        if not isinstance(regions, list) or not regions:
            raise ConfigurationError("At least one AWS Region is required.")
        clean_regions: list[str] = []
        for r in regions:
            r = str(r).strip().lower()
            if not REGION_RE.match(r):
                raise ConfigurationError(f"'{r[:40]}' is not a valid AWS Region name.")
            if r not in clean_regions:
                clean_regions.append(r)
        if len(clean_regions) > MAX_REGIONS:
            raise ConfigurationError(f"At most {MAX_REGIONS} Regions are supported per integration.")

        if auth_method == "assume_role":
            role_arn = str(config.get("roleArn") or "").strip()
            m = ROLE_ARN_RE.match(role_arn)
            if not m:
                raise ConfigurationError("Role ARN must look like arn:aws:iam::123456789012:role/VectraSecurityAudit.")
            return {"regions": clean_regions, "roleArn": role_arn, "accountId": m.group(2)}, None

        if auth_method == "access_key":
            creds = credentials or {}
            access_key = str(creds.get("accessKeyId") or "").strip()
            secret_key = str(creds.get("secretAccessKey") or "").strip()
            if not ACCESS_KEY_RE.match(access_key):
                raise ConfigurationError("Access key ID must be a long-term key starting with AKIA (temporary keys expire and are not supported).")
            if not SECRET_KEY_RE.match(secret_key):
                raise ConfigurationError("Secret access key is not in the expected format.")
            return (
                {"regions": clean_regions, "accessKeyIdSuffix": access_key[-4:]},
                {"accessKeyId": access_key, "secretAccessKey": secret_key},
            )

        raise ConfigurationError("Unsupported AWS authentication method.")

    # ── Sessions ──────────────────────────────────────────────────────

    def _boto_session(self, session: ProviderSession):
        import boto3

        if session.auth_method == "access_key":
            creds = session.credentials or {}
            return boto3.session.Session(
                aws_access_key_id=creds.get("accessKeyId"),
                aws_secret_access_key=creds.get("secretAccessKey"),
            )
        if session.auth_method == "assume_role":
            base = boto3.session.Session()  # Vectra's own principal (env / instance role)
            sts = base.client("sts", region_name=session.config["regions"][0], config=_boto_config())
            resp = sts.assume_role(
                RoleArn=session.config["roleArn"],
                RoleSessionName=f"vectra-{session.integration_id[:40]}",
                ExternalId=secrets.aws_external_id(session.org_id),
                DurationSeconds=3600,
            )
            c = resp["Credentials"]
            return boto3.session.Session(
                aws_access_key_id=c["AccessKeyId"],
                aws_secret_access_key=c["SecretAccessKey"],
                aws_session_token=c["SessionToken"],
            )
        raise CloudProviderError(CloudProviderError.INVALID_CONFIGURATION, "Unsupported AWS authentication method.")

    def _client(self, boto_session, service: str, region: str):
        return boto_session.client(service, region_name=region, config=_boto_config())

    # ── Validation ────────────────────────────────────────────────────

    def validate_connection(self, session: ProviderSession) -> ValidationResult:
        result = ValidationResult(ok=False)
        try:
            boto_session = self._boto_session(session)
            identity = self._client(boto_session, "sts", session.config["regions"][0]).get_caller_identity()
            result.accountId = identity.get("Account")
            result.accountLabel = f"AWS account {result.accountId}"
            result.checks.append({"name": "Authentication", "ok": True, "detail": "Credentials accepted by AWS"})
        except Exception as exc:
            err = map_aws_error(exc, "authentication")
            result.checks.append({"name": "Authentication", "ok": False, "detail": err.message})
            result.error = err.to_dict()
            return result

        if session.auth_method == "assume_role" and result.accountId != session.config.get("accountId"):
            err = CloudProviderError(CloudProviderError.INVALID_CONFIGURATION,
                                     "The assumed role belongs to a different AWS account than the Role ARN.")
            result.error = err.to_dict()
            return result

        last_error: Optional[CloudProviderError] = None
        for region in session.config["regions"]:
            try:
                hub = self._client(boto_session, "securityhub", region)
                hub.describe_hub()
                hub.get_findings(MaxResults=1)
                result.scopes.append(region)
                result.checks.append({"name": f"Security Hub · {region}", "ok": True, "detail": "Enabled and readable"})
            except Exception as exc:
                last_error = map_aws_error(exc, region)
                result.checks.append({"name": f"Security Hub · {region}", "ok": False, "detail": last_error.message})

        result.ok = bool(result.scopes)
        if not result.ok and last_error:
            result.error = last_error.to_dict()
        return result

    # ── Fetch ─────────────────────────────────────────────────────────

    def fetch_findings(self, session: ProviderSession, max_findings: int) -> FetchResult:
        out = FetchResult()
        seen: set[str] = set()
        try:
            boto_session = self._boto_session(session)
        except Exception as exc:
            err = map_aws_error(exc, "authentication")
            out.failedScopes = [{"scope": r, **err.to_dict()} for r in session.config["regions"]]
            return out

        malformed = 0
        for region in session.config["regions"]:
            if out.truncated:
                break
            try:
                hub = self._client(boto_session, "securityhub", region)
                paginator = hub.get_paginator("get_findings")
                pages = paginator.paginate(
                    Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
                    PaginationConfig={"PageSize": PAGE_SIZE},
                )
                started = time.monotonic()
                for page in pages:
                    out.apiCalls += 1
                    findings = page.get("Findings")
                    if not isinstance(findings, list):
                        raise CloudProviderError(CloudProviderError.MALFORMED_RESPONSE,
                                                 f"AWS returned an unexpected response ({region}).")
                    for raw in findings:
                        try:
                            finding, assets = normalizer.normalize(raw, session.integration_id)
                        except ValueError:
                            malformed += 1
                            continue
                        if finding.fingerprint in seen:  # cross-Region aggregation returns duplicates
                            continue
                        seen.add(finding.fingerprint)
                        out.findings.append(finding)
                        for a in assets:
                            out.assets.setdefault(a.assetId, a)
                        if len(out.findings) >= max_findings:
                            out.truncated = True
                            break
                    if out.truncated:
                        break
                out.apiLatencyMs += int((time.monotonic() - started) * 1000)
                if not out.truncated:
                    out.completedScopes.append(region)
            except Exception as exc:
                err = map_aws_error(exc, region)
                out.failedScopes.append({"scope": region, **err.to_dict()})
                logger.warning(f"[CLOUD:aws] integration={session.integration_id} region={region} fetch failed code={err.code}")

        if malformed:
            logger.warning(f"[CLOUD:aws] integration={session.integration_id} skipped {malformed} malformed finding(s)")
        return out

    # ── Setup ─────────────────────────────────────────────────────────

    def setup_info(self, org_id: str) -> dict[str, Any]:
        principal = os.getenv(PLATFORM_PRINCIPAL_ENV, "").strip() or None
        info: dict[str, Any] = {
            "permissionsPolicy": json.dumps(PERMISSIONS_POLICY, indent=2),
            "roleAuthAvailable": bool(principal),
            "vectraPrincipalArn": principal,
        }
        try:
            info["externalId"] = secrets.aws_external_id(org_id)
        except CloudProviderError as exc:
            info["externalId"] = None
            info["setupError"] = exc.to_dict()
        if principal and info.get("externalId"):
            info["trustPolicy"] = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": info["externalId"]}},
                }],
            }, indent=2)
        return info
