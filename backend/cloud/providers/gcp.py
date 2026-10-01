"""
Google Cloud connector.

    Authentication            service-account key (encrypted at rest by cloud.secrets)
    Project validation        Resource Manager v3 projects.get
    Resource discovery        Compute Engine, Cloud Storage, Resource Manager IAM, IAM (read-only)
    Configuration analysis    cloud.normalizers.gcp_config (deterministic, evidence-backed)
    Security Command Center   OPTIONAL — API v2 findings.list when available

A valid connection stays useful when Security Command Center cannot be used
(for example a project outside a Google Cloud Organization): SCC is reported as
an unavailable capability with a machine-readable reason, never as a failed
connection. A connection fails only when authentication fails, the project does
not exist, or nothing at all can be read.

Uses google-auth (already a Firebase Admin dependency) and the REST APIs, so no
extra client libraries are needed. Hosts are fixed, every path segment is
validated, and the key's token_uri is pinned to Google's OAuth endpoint, so a
crafted key or API response cannot redirect requests elsewhere (SSRF).
"""
from __future__ import annotations

import json
import random
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import quote

from cloud.errors import CloudProviderError, ConfigurationError
from cloud.models import FetchResult, NormalizedAsset, NormalizedFinding, ValidationResult
from cloud.normalizers import gcp as normalizer
from cloud.normalizers import gcp_config as config_checks
from cloud.providers.base import AuthMethod, CloudProvider, ProviderSession
from utils.logger import get_logger

logger = get_logger(__name__)

API_ROOT = "https://securitycenter.googleapis.com/v2"
CRM_ROOT = "https://cloudresourcemanager.googleapis.com/v3"
COMPUTE_ROOT = "https://compute.googleapis.com/compute/v1"
STORAGE_ROOT = "https://storage.googleapis.com/storage/v1"
IAM_ROOT = "https://iam.googleapis.com/v1"
TOKEN_URI = "https://oauth2.googleapis.com/token"
OAUTH_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
PAGE_SIZE = 1000          # SCC v2 findings.list maximum
REQUEST_TIMEOUT = (10, 60)
MAX_ATTEMPTS = 5
MAX_KEY_BYTES = 16_000
MAX_PAGES = 200           # per collection; stops a runaway pagination loop
MAX_BUCKET_IAM_READS = 1_000
MAX_SA_KEY_READS = 500

SCC_DOCS_URL = "https://cloud.google.com/security-command-center/docs/activate-scc-overview"

PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
NUMERIC_ID_RE = re.compile(r"^\d{1,20}$")
LOCATION_RE = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
SA_EMAIL_RE = re.compile(r"^[a-z0-9-]{1,63}@[a-z0-9.-]{1,120}\.gserviceaccount\.com$")
KEY_ID_RE = re.compile(r"^[a-f0-9]{40}$")
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")

SCOPE_TYPES = {"project": "projects", "organization": "organizations", "folder": "folders"}
SCOPE_SCC = "Security Command Center"

# ── Capability reasons (machine-readable, stable) ─────────────────────
API_DISABLED = "API_DISABLED"
SCC_NOT_ACTIVATED = "SCC_NOT_ACTIVATED"
PROJECT_NOT_ASSOCIATED_WITH_ORGANIZATION = "PROJECT_NOT_ASSOCIATED_WITH_ORGANIZATION"
INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
INVALID_SCOPE = "INVALID_SCOPE"
PROVIDER_ERROR = "PROVIDER_ERROR"
SCOPE_NOT_SUPPORTED = "SCOPE_NOT_SUPPORTED"

# Typed connector errors (CloudProviderError.reason).
GCP_AUTH_FAILED = "GCP_AUTH_FAILED"
GCP_PROJECT_NOT_FOUND = "GCP_PROJECT_NOT_FOUND"
GCP_PERMISSION_DENIED = "GCP_PERMISSION_DENIED"
GCP_API_DISABLED = "GCP_API_DISABLED"
GCP_RESOURCE_DISCOVERY_FAILED = "GCP_RESOURCE_DISCOVERY_FAILED"
SCC_NOT_AVAILABLE = "SCC_NOT_AVAILABLE"

AVAILABLE, UNAVAILABLE, ERROR = "available", "unavailable", "error"

# Read-only permissions for discovery + analysis (no data-plane access: no object reads).
DISCOVERY_PERMISSIONS = [
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "compute.instances.list",
    "compute.firewalls.list",
    "storage.buckets.list",
    "storage.buckets.getIamPolicy",
    "iam.serviceAccounts.list",
    "iam.serviceAccountKeys.list",
]
SCC_PERMISSIONS = ["securitycenter.findings.list"]
SCC_ROLE = "roles/securitycenter.findingsViewer"


def _parse_key(raw: Any) -> dict:
    if isinstance(raw, str):
        if len(raw.encode()) > MAX_KEY_BYTES:
            raise ConfigurationError("Service account key is too large.")
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raise ConfigurationError("Service account key must be the JSON key file downloaded from Google Cloud.")
    if not isinstance(raw, dict):
        raise ConfigurationError("Service account key must be a JSON object.")
    if raw.get("type") != "service_account":
        raise ConfigurationError("Key must be a service account key (type \"service_account\").")

    email = str(raw.get("client_email") or "")
    private_key = str(raw.get("private_key") or "")
    key_id = str(raw.get("private_key_id") or "")
    if not SA_EMAIL_RE.match(email):
        raise ConfigurationError("Service account key has an invalid client_email.")
    if not private_key.startswith("-----BEGIN PRIVATE KEY-----") or "-----END PRIVATE KEY-----" not in private_key:
        raise ConfigurationError("Service account key has an invalid private_key.")
    if not KEY_ID_RE.match(key_id):
        raise ConfigurationError("Service account key has an invalid private_key_id.")
    # SSRF / token-exfiltration guard: google-auth POSTs a signed assertion to
    # token_uri, so it must be Google's endpoint and nothing else.
    if raw.get("token_uri") not in (None, TOKEN_URI):
        raise ConfigurationError("Service account key has an unexpected token_uri.")
    if raw.get("universe_domain") not in (None, "googleapis.com"):
        raise ConfigurationError("Only keys for the googleapis.com universe are supported.")

    return {
        "type": "service_account",
        "project_id": str(raw.get("project_id") or "")[:100],
        "private_key_id": key_id,
        "private_key": private_key,
        "client_email": email,
        "client_id": str(raw.get("client_id") or "")[:40],
        "token_uri": TOKEN_URI,
    }


def _message_of(resp) -> tuple[str, str]:
    """(status, reason) from a Google error body, without echoing its text to users."""
    try:
        body = resp.json().get("error", {})
    except Exception:
        return "", ""
    reason = ""
    for d in body.get("details") or []:
        if isinstance(d, dict) and d.get("reason"):
            reason = str(d["reason"])
            break
    if not reason:
        for e in body.get("errors") or []:  # Compute / Storage JSON API error style
            if isinstance(e, dict) and e.get("reason") == "accessNotConfigured":
                reason = "SERVICE_DISABLED"
                break
    message = str(body.get("message") or "").lower()
    if not reason and ("has not been used" in message or "is disabled" in message):
        reason = "SERVICE_DISABLED"
    if not reason and "security command center" in message and ("not" in message and "activ" in message):
        reason = "SCC_NOT_ACTIVATED"
    return str(body.get("status") or ""), reason


def map_http_error(resp, context: str = "") -> CloudProviderError:
    where = f" ({context})" if context else ""
    code = resp.status_code
    _status, reason = _message_of(resp)
    if code == 401:
        err = CloudProviderError(CloudProviderError.INVALID_CREDENTIALS, "Google Cloud rejected the service account credentials.",
                                 "Check that the key has not been deleted or disabled, then reconnect.", GCP_AUTH_FAILED)
    elif code == 403 and reason in {"SERVICE_DISABLED", "SCC_NOT_ACTIVATED"}:
        err = CloudProviderError(CloudProviderError.SERVICE_NOT_ENABLED,
                                 f"Security Command Center is not available{where}.",
                                 "Enable the Security Command Center API and activate Security Command Center for this scope.",
                                 GCP_API_DISABLED if reason == "SERVICE_DISABLED" else SCC_NOT_ACTIVATED)
    elif code == 403:
        err = CloudProviderError(CloudProviderError.ACCESS_DENIED, f"Permission denied by Google Cloud{where}.",
                                 "Grant the service account roles/securitycenter.findingsViewer on this project, folder or organization.",
                                 GCP_PERMISSION_DENIED)
    elif code == 404:
        err = CloudProviderError(CloudProviderError.INVALID_CONFIGURATION, f"The project, folder or organization was not found{where}.",
                                 None, GCP_PROJECT_NOT_FOUND)
    elif code == 400:
        err = CloudProviderError(CloudProviderError.INVALID_CONFIGURATION, f"Google Cloud rejected the request{where}.",
                                 "Check the scope ID and location.", INVALID_SCOPE)
    elif code == 429:
        err = CloudProviderError(CloudProviderError.THROTTLED, f"Google Cloud quota exceeded{where}.", "Retry the sync later.")
    else:
        err = CloudProviderError(CloudProviderError.PROVIDER_ERROR, f"Google Cloud returned an error{where} (HTTP {code}).")
    err.http_status = code          # type: ignore[attr-defined]
    err.google_reason = reason      # type: ignore[attr-defined]
    return err


def _http_status(err: CloudProviderError) -> Optional[int]:
    return getattr(err, "http_status", None)


def _google_reason(err: CloudProviderError) -> str:
    return getattr(err, "google_reason", "") or ""


# ── Resource collections (discovery + analysis) ───────────────────────

class Collection:
    """One read-only resource type: its API, permission and resolution scope."""

    def __init__(self, key: str, label: str, scope: str, api: str, permissions: list[str]):
        self.key, self.label, self.scope, self.api, self.permissions = key, label, scope, api, permissions


COLLECTIONS = [
    Collection("compute_instances", "Compute Engine instances", config_checks.SCOPE_INSTANCES,
               "compute.googleapis.com", ["compute.instances.list"]),
    Collection("firewall_rules", "VPC firewall rules", config_checks.SCOPE_FIREWALLS,
               "compute.googleapis.com", ["compute.firewalls.list"]),
    Collection("storage_buckets", "Cloud Storage buckets", config_checks.SCOPE_STORAGE,
               "storage.googleapis.com", ["storage.buckets.list", "storage.buckets.getIamPolicy"]),
    Collection("project_iam", "Project IAM policy", config_checks.SCOPE_PROJECT_IAM,
               "cloudresourcemanager.googleapis.com", ["resourcemanager.projects.getIamPolicy"]),
    Collection("service_accounts", "Service accounts", config_checks.SCOPE_SERVICE_ACCOUNTS,
               "iam.googleapis.com", ["iam.serviceAccounts.list", "iam.serviceAccountKeys.list"]),
]


def _discovery_state(col: Collection, err: CloudProviderError) -> dict:
    """Capability state for a collection that could not be read."""
    status = _http_status(err)
    if err.code == CloudProviderError.SERVICE_NOT_ENABLED or _google_reason(err) == "SERVICE_DISABLED":
        return {"available": False, "status": UNAVAILABLE, "reason": API_DISABLED,
                "message": f"The {col.api} API is not enabled for this project, so {col.label.lower()} cannot be read.",
                "hint": f"Enable {col.api} if this project uses it."}
    if err.code == CloudProviderError.ACCESS_DENIED or status == 403:
        return {"available": False, "status": UNAVAILABLE, "reason": INSUFFICIENT_PERMISSIONS,
                "message": f"The service account cannot read {col.label.lower()}.",
                "hint": "Grant: " + ", ".join(col.permissions)}
    return {"available": False, "status": ERROR, "reason": PROVIDER_ERROR,
            "message": f"{col.label} could not be read right now.", "hint": err.hint or "Retry later."}


def _scc_state(err: CloudProviderError, has_organization: Optional[bool], scope_type: str) -> dict:
    """
    Classify an SCC failure. Transient errors stay errors: only conditions that
    make SCC genuinely unusable for this scope are reported as unavailable.
    """
    status, reason = _http_status(err), _google_reason(err)
    transient = err.code in (CloudProviderError.THROTTLED, CloudProviderError.TIMEOUT,
                             CloudProviderError.PROVIDER_ERROR, CloudProviderError.MALFORMED_RESPONSE)
    if transient:
        return {"available": False, "status": ERROR, "reason": PROVIDER_ERROR,
                "message": "Security Command Center could not be reached right now.", "hint": "Retry later."}

    if scope_type == "project" and has_organization is False:
        # SCC cannot be activated for a project outside an organization, so
        # enabling its API or granting roles would not help — say what would.
        return {"available": False, "status": UNAVAILABLE, "reason": PROJECT_NOT_ASSOCIATED_WITH_ORGANIZATION,
                "message": "Security Command Center is unavailable for this project because the project is not "
                           "associated with a Google Cloud Organization.",
                "hint": "Move the project into an organization and activate Security Command Center there. "
                        "Configuration analysis continues to work without it.",
                "docsUrl": SCC_DOCS_URL}
    if reason == "SERVICE_DISABLED":
        return {"available": False, "status": UNAVAILABLE, "reason": API_DISABLED,
                "message": "The Security Command Center API is not enabled.",
                "hint": "Enable securitycenter.googleapis.com and activate Security Command Center.", "docsUrl": SCC_DOCS_URL}
    if reason == "SCC_NOT_ACTIVATED":
        return {"available": False, "status": UNAVAILABLE, "reason": SCC_NOT_ACTIVATED,
                "message": "Security Command Center is not activated for this scope.",
                "hint": "Activate Security Command Center in the Google Cloud console.", "docsUrl": SCC_DOCS_URL}
    if err.code == CloudProviderError.ACCESS_DENIED or status == 403:
        return {"available": False, "status": UNAVAILABLE, "reason": INSUFFICIENT_PERMISSIONS,
                "message": "The service account cannot read Security Command Center findings.",
                "hint": f"Grant {SCC_ROLE} on the project, folder or organization.", "docsUrl": SCC_DOCS_URL}
    if status in (400, 404) or err.code == CloudProviderError.INVALID_CONFIGURATION:
        return {"available": False, "status": UNAVAILABLE, "reason": INVALID_SCOPE,
                "message": "Security Command Center rejected the configured scope.",
                "hint": "Check the scope ID and location."}
    if err.code == CloudProviderError.INVALID_CREDENTIALS:
        return {"available": False, "status": ERROR, "reason": PROVIDER_ERROR,
                "message": "Security Command Center rejected the credentials.", "hint": err.hint}
    return {"available": False, "status": ERROR, "reason": PROVIDER_ERROR,
            "message": "Security Command Center could not be reached right now.", "hint": "Retry later."}


def _nothing_readable(scope_type: str, collections: dict, scc: dict) -> CloudProviderError:
    if scope_type != "project":
        return CloudProviderError(CloudProviderError.SERVICE_NOT_ENABLED, scc.get("message") or "Security Command Center is unavailable.",
                                  scc.get("hint"), SCC_NOT_AVAILABLE)
    if collections and all(s.get("reason") == API_DISABLED for s in collections.values()):
        return CloudProviderError(CloudProviderError.SERVICE_NOT_ENABLED,
                                  "None of the Google Cloud APIs Vectra reads are enabled for this project.",
                                  "Enable the APIs for the services this project uses.", GCP_API_DISABLED)
    if any(s.get("status") == ERROR for s in collections.values()):
        return CloudProviderError(CloudProviderError.PROVIDER_ERROR, "Google Cloud resources could not be read right now.",
                                  "Retry later.", GCP_RESOURCE_DISCOVERY_FAILED)
    return CloudProviderError(CloudProviderError.ACCESS_DENIED,
                              "The service account authenticated but cannot read any resources in this project.",
                              "Grant read-only permissions: " + ", ".join(DISCOVERY_PERMISSIONS), GCP_PERMISSION_DENIED)


def _auth_failed_error() -> CloudProviderError:
    return CloudProviderError(CloudProviderError.INVALID_CREDENTIALS, "Google Cloud rejected the service account credentials.",
                              "Check that the key has not been deleted or disabled, then reconnect.", GCP_AUTH_FAILED)


class GCPProvider(CloudProvider):
    key = "gcp"
    display_name = "Google Cloud"
    security_service = "Configuration analysis · Security Command Center (optional)"
    auth_methods = [
        AuthMethod("service_account_key", "Service account key",
                   "JSON key of a dedicated read-only service account. Stored encrypted; never shown again.",
                   recommended=True, requires_secret=True),
    ]
    capabilities = {
        "findings": "available",
        "vulnerability_metadata": "available",
        "compliance": "available",
        "assets": "available",
        "asset_inventory": "available",
        "iam_analysis": "available",
        "configuration_analysis": "available",
    }

    # ── Config ────────────────────────────────────────────────────────

    def parse_config(self, auth_method, config, credentials):
        if auth_method != "service_account_key":
            raise ConfigurationError("Unsupported Google Cloud authentication method.")

        scope_type = str(config.get("scopeType") or "project").strip().lower()
        scope_id = str(config.get("scopeId") or "").strip()
        if scope_type not in SCOPE_TYPES:
            raise ConfigurationError("Scope must be a project, folder or organization.")
        if scope_type == "project":
            if not (PROJECT_ID_RE.match(scope_id) or NUMERIC_ID_RE.match(scope_id)):
                raise ConfigurationError("Project must be a valid project ID or project number.")
        elif not NUMERIC_ID_RE.match(scope_id):
            raise ConfigurationError(f"{scope_type.title()} ID must be numeric.")

        location = str(config.get("location") or "").strip().lower() or None
        if location and not LOCATION_RE.match(location):
            raise ConfigurationError("Location is not valid.")

        key = _parse_key((credentials or {}).get("serviceAccountKey"))
        return (
            {
                "scopeType": scope_type,
                "scopeId": scope_id,
                "location": location,
                "serviceAccountEmail": key["client_email"],
            },
            {"serviceAccountKey": key},
        )

    # ── HTTP ──────────────────────────────────────────────────────────

    def _authorized_session(self, session: ProviderSession):
        from google.auth.transport.requests import AuthorizedSession
        from google.oauth2 import service_account

        key = (session.credentials or {}).get("serviceAccountKey")
        if not isinstance(key, dict):
            raise CloudProviderError(CloudProviderError.INVALID_CREDENTIALS, "Stored Google Cloud credentials are missing.",
                                     "Reconnect the integration.", GCP_AUTH_FAILED)
        creds = service_account.Credentials.from_service_account_info(key, scopes=OAUTH_SCOPES)
        return AuthorizedSession(creds)

    def _authenticate(self, session: ProviderSession):
        """Authorized HTTP session with a fresh token, or CloudProviderError(GCP_AUTH_FAILED)."""
        try:
            http = self._authorized_session(session)
            creds = getattr(http, "credentials", None)
            if creds is not None and hasattr(creds, "refresh"):
                from google.auth.transport.requests import Request
                creds.refresh(Request())
        except CloudProviderError:
            raise
        except Exception:  # malformed key material or refused token grant; never echo details
            raise _auth_failed_error()
        return http

    def _findings_url(self, config: dict) -> str:
        parent = f"{SCOPE_TYPES[config['scopeType']]}/{config['scopeId']}"
        if config.get("location"):
            return f"{API_ROOT}/{parent}/sources/-/locations/{config['location']}/findings"
        return f"{API_ROOT}/{parent}/sources/-/findings"

    def _get(self, http, url: str, params: dict, context: str) -> dict:
        return self._request(http, "GET", url, params, None, context)

    def _post(self, http, url: str, body: dict, context: str) -> dict:
        return self._request(http, "POST", url, {}, body, context)

    def _request(self, http, method: str, url: str, params: dict, body: Optional[dict], context: str) -> dict:
        """Request with bounded exponential backoff on throttling / transient errors."""
        import requests
        from google.auth.exceptions import RefreshError, TransportError

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                if method == "POST":
                    resp = http.post(url, json=body or {}, timeout=REQUEST_TIMEOUT)
                else:
                    resp = http.get(url, params=params, timeout=REQUEST_TIMEOUT)
            except RefreshError:
                raise _auth_failed_error()
            except (requests.Timeout, requests.ConnectionError, TransportError):
                if attempt == MAX_ATTEMPTS:
                    raise CloudProviderError(CloudProviderError.TIMEOUT, f"Google Cloud did not respond in time ({context}).",
                                             "Retry the sync.")
                self._sleep(attempt, None)
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    raise CloudProviderError(CloudProviderError.MALFORMED_RESPONSE,
                                             f"Google Cloud returned an unexpected response ({context}).")
                if not isinstance(data, dict):
                    raise CloudProviderError(CloudProviderError.MALFORMED_RESPONSE,
                                             f"Google Cloud returned an unexpected response ({context}).")
                return data
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < MAX_ATTEMPTS:
                self._sleep(attempt, resp.headers.get("Retry-After"))
                continue
            raise map_http_error(resp, context)
        raise CloudProviderError(CloudProviderError.PROVIDER_ERROR, f"Google Cloud request failed ({context}).")

    def _paged(self, http, url: str, params: dict, items_key: str, context: str,
               token_param: str = "pageToken") -> list:
        out: list = []
        token: Optional[str] = None
        for _ in range(MAX_PAGES):
            page = dict(params, **({token_param: token} if token else {}))
            body = self._get(http, url, page, context)
            items = body.get(items_key, [])
            if not isinstance(items, (list, dict)):
                raise CloudProviderError(CloudProviderError.MALFORMED_RESPONSE,
                                         f"Google Cloud returned an unexpected response ({context}).")
            out.append(items)
            token = body.get("nextPageToken") or None
            if not token:
                return out
        # Never treat a cut-off listing as complete: its findings would be resolved.
        raise CloudProviderError(CloudProviderError.PROVIDER_ERROR,
                                 f"Too many results to analyze ({context}).", "Contact support to raise the limit.")

    @staticmethod
    def _sleep(attempt: int, retry_after: Optional[str]) -> None:
        delay = min(2 ** (attempt - 1), 20) + random.uniform(0, 0.5)
        if retry_after and retry_after.isdigit():
            delay = min(max(delay, int(retry_after)), 30)
        time.sleep(delay)

    # ── Project ───────────────────────────────────────────────────────

    def _project(self, http, scope_id: str) -> dict:
        return self._get(http, f"{CRM_ROOT}/projects/{scope_id}", {}, "project")

    @staticmethod
    def _organization_state(project: Optional[dict]) -> Optional[bool]:
        """True/False when the project's parent is known; None when the project could not be read."""
        if project is None:
            return None
        parent = str(project.get("parent") or "")
        return parent.startswith(("organizations/", "folders/"))  # a folder always sits in an organization

    @staticmethod
    def _project_id_for_apis(scope_id: str, project: Optional[dict]) -> str:
        pid = (project or {}).get("projectId")
        return pid if isinstance(pid, str) and PROJECT_ID_RE.match(pid) else scope_id

    # ── Collection readers (full, paginated) ──────────────────────────

    def _read(self, http, key: str, project_id: str, project: Optional[dict], integration_id: str,
              now: datetime) -> tuple[list[NormalizedFinding], list[NormalizedAsset], Optional[dict]]:
        """Returns (findings, assets, partial) — partial describes sub-resources that could not be assessed."""
        p = quote(project_id, safe="")
        if key == "compute_instances":
            findings, assets = [], []
            for page in self._paged(http, f"{COMPUTE_ROOT}/projects/{p}/aggregated/instances",
                                    {"maxResults": 500}, "items", "Compute Engine instances"):
                for scoped in (page.values() if isinstance(page, dict) else []):
                    for inst in (scoped or {}).get("instances") or []:
                        if isinstance(inst, dict) and inst.get("name"):
                            f, a = config_checks.analyze_instance(integration_id, project_id, inst)
                            findings += f
                            assets.append(a)
            return findings, assets, None

        if key == "firewall_rules":
            rules = [r for page in self._paged(http, f"{COMPUTE_ROOT}/projects/{p}/global/firewalls",
                                               {"maxResults": 500}, "items", "VPC firewall rules")
                     for r in (page if isinstance(page, list) else [])]
            f, a = config_checks.analyze_firewalls(integration_id, project_id, rules)
            return f, a, None

        if key == "storage_buckets":
            buckets = [b for page in self._paged(http, f"{STORAGE_ROOT}/b", {"project": project_id, "maxResults": 1000},
                                                 "items", "Cloud Storage buckets")
                       for b in (page if isinstance(page, list) else []) if isinstance(b, dict)]
            findings, assets, unassessed = [], [], 0
            for i, bucket in enumerate(buckets):
                name = str(bucket.get("name") or "")
                if not BUCKET_RE.match(name):
                    continue
                policy = None
                if i < MAX_BUCKET_IAM_READS:
                    try:
                        policy = self._get(http, f"{STORAGE_ROOT}/b/{quote(name, safe='')}/iam", {}, "bucket IAM policy")
                    except CloudProviderError as err:
                        if err.code not in (CloudProviderError.ACCESS_DENIED, CloudProviderError.INVALID_CONFIGURATION):
                            raise
                if policy is None:
                    unassessed += 1
                f, a = config_checks.analyze_bucket(integration_id, project_id, bucket, policy)
                findings += f
                assets.append(a)
            partial = None
            if unassessed:
                partial = {"reason": INSUFFICIENT_PERMISSIONS,
                           "message": f"Public access could not be assessed for {unassessed} bucket(s).",
                           "hint": "Grant storage.buckets.getIamPolicy."}
            return findings, assets, partial

        if key == "project_iam":
            if project is None:
                raise CloudProviderError(CloudProviderError.ACCESS_DENIED, "Project details could not be read.",
                                         "Grant resourcemanager.projects.get.", GCP_PERMISSION_DENIED)
            policy = self._post(http, f"{CRM_ROOT}/projects/{p}:getIamPolicy",
                                {"options": {"requestedPolicyVersion": 3}}, "project IAM policy")
            f, a = config_checks.analyze_project_iam(integration_id, project, policy)
            return f, [a], None

        if key == "service_accounts":
            accounts = [sa for page in self._paged(http, f"{IAM_ROOT}/projects/{p}/serviceAccounts",
                                                   {"pageSize": 100}, "accounts", "service accounts")
                        for sa in (page if isinstance(page, list) else []) if isinstance(sa, dict)]
            findings, assets, unassessed = [], [], 0
            for i, sa in enumerate(accounts):
                email = str(sa.get("email") or "")
                if not SA_EMAIL_RE.match(email):
                    continue
                keys = None
                if i < MAX_SA_KEY_READS and not sa.get("disabled"):
                    try:
                        body = self._get(http, f"{IAM_ROOT}/projects/{p}/serviceAccounts/{quote(email, safe='@')}/keys",
                                         {"keyTypes": "USER_MANAGED"}, "service account keys")
                        keys = body.get("keys") or []
                    except CloudProviderError as err:
                        if err.code not in (CloudProviderError.ACCESS_DENIED, CloudProviderError.INVALID_CONFIGURATION):
                            raise
                if keys is None and not sa.get("disabled"):
                    unassessed += 1
                f, a = config_checks.analyze_service_account(integration_id, project_id, sa, keys, now)
                findings += f
                assets.append(a)
            partial = None
            if unassessed:
                partial = {"reason": INSUFFICIENT_PERMISSIONS,
                           "message": f"Keys could not be listed for {unassessed} service account(s).",
                           "hint": "Grant iam.serviceAccountKeys.list."}
            return findings, assets, partial

        raise ValueError(key)

    def _probe(self, http, key: str, project_id: str, project: Optional[dict]) -> None:
        """Cheapest read proving a collection is readable. Raises CloudProviderError."""
        p = quote(project_id, safe="")
        if key == "compute_instances":
            self._get(http, f"{COMPUTE_ROOT}/projects/{p}/aggregated/instances", {"maxResults": 1}, "Compute Engine instances")
        elif key == "firewall_rules":
            self._get(http, f"{COMPUTE_ROOT}/projects/{p}/global/firewalls", {"maxResults": 1}, "VPC firewall rules")
        elif key == "storage_buckets":
            self._get(http, f"{STORAGE_ROOT}/b", {"project": project_id, "maxResults": 1}, "Cloud Storage buckets")
        elif key == "project_iam":
            if project is None:
                raise CloudProviderError(CloudProviderError.ACCESS_DENIED, "Project details could not be read.",
                                         "Grant resourcemanager.projects.get.", GCP_PERMISSION_DENIED)
            self._post(http, f"{CRM_ROOT}/projects/{p}:getIamPolicy", {"options": {"requestedPolicyVersion": 3}},
                       "project IAM policy")
        elif key == "service_accounts":
            self._get(http, f"{IAM_ROOT}/projects/{p}/serviceAccounts", {"pageSize": 1}, "service accounts")

    # ── Capability detection ──────────────────────────────────────────

    def _detect(self, session: ProviderSession, http, full: bool,
                on_collection: Optional[Callable[[Collection, str, Optional[dict]], None]] = None) -> dict:
        """
        Shared by validation (probes) and sync (full reads via on_collection).
        Returns {"project", "hasOrganization", "projectState", "collections", "scc", "fatal"}.
        """
        cfg = session.config
        scope_type, scope_id = cfg["scopeType"], cfg["scopeId"]
        out: dict[str, Any] = {"project": None, "hasOrganization": None, "projectState": None,
                               "collections": {}, "scc": None, "fatal": None}

        if scope_type == "project":
            try:
                project = self._project(http, scope_id)
                out["project"] = project
                out["hasOrganization"] = self._organization_state(project)
                if str(project.get("state") or "ACTIVE").upper() != "ACTIVE":
                    out["fatal"] = CloudProviderError(CloudProviderError.INVALID_CONFIGURATION,
                                                      f"Google Cloud project {scope_id} is not active.",
                                                      "Restore the project or connect another one.", GCP_PROJECT_NOT_FOUND)
                    return out
                out["projectState"] = {"available": True, "status": AVAILABLE}
            except CloudProviderError as err:
                if err.code == CloudProviderError.INVALID_CREDENTIALS:
                    out["fatal"] = err
                    return out
                if _http_status(err) == 404:
                    out["fatal"] = CloudProviderError(CloudProviderError.INVALID_CONFIGURATION,
                                                      f"Google Cloud project {scope_id} was not found.",
                                                      "Check the project ID.", GCP_PROJECT_NOT_FOUND)
                    return out
                state = _discovery_state(Collection("project", "Project details", "", "cloudresourcemanager.googleapis.com",
                                                    ["resourcemanager.projects.get"]), err)
                if state["reason"] == INSUFFICIENT_PERMISSIONS:
                    state["message"] = (f"Project {scope_id} could not be read: it may not exist, or the service account "
                                        "lacks resourcemanager.projects.get.")
                out["projectState"] = state

            api_project = self._project_id_for_apis(scope_id, out["project"])
            now = datetime.now(timezone.utc)
            for col in COLLECTIONS:
                try:
                    if full:
                        findings, assets, partial = self._read(http, col.key, api_project, out["project"],
                                                               session.integration_id, now)
                        state = {"available": True, "status": AVAILABLE, "resources": len(assets)}
                        if partial:
                            state.update({"partial": True, **partial})
                        out["collections"][col.key] = state
                        if on_collection:
                            on_collection(col, "completed", {"findings": findings, "assets": assets, "partial": partial})
                    else:
                        self._probe(http, col.key, api_project, out["project"])
                        out["collections"][col.key] = {"available": True, "status": AVAILABLE}
                except CloudProviderError as err:
                    if err.code == CloudProviderError.INVALID_CREDENTIALS:
                        out["fatal"] = err
                        return out
                    if _http_status(err) == 404 and out["project"] is None:
                        out["fatal"] = CloudProviderError(CloudProviderError.INVALID_CONFIGURATION,
                                                          f"Google Cloud project {scope_id} was not found.",
                                                          "Check the project ID.", GCP_PROJECT_NOT_FOUND)
                        return out
                    state = _discovery_state(col, err)
                    out["collections"][col.key] = state
                    if on_collection:
                        on_collection(col, "failed" if state["status"] == ERROR else "skipped", {"state": state, "error": err})
        else:
            for col in COLLECTIONS:
                out["collections"][col.key] = {
                    "available": False, "status": UNAVAILABLE, "reason": SCOPE_NOT_SUPPORTED,
                    "message": "Resource discovery runs per project. Connect individual projects to analyze their configuration.",
                }
        return out

    def _capabilities(self, session: ProviderSession, detected: dict, scc: dict) -> dict:
        cfg = session.config
        project = detected.get("project") or {}
        collections = detected["collections"]
        discovery_ok = any(c.get("available") for c in collections.values())
        return {
            "authenticated": True,
            "project_id": project.get("projectId") or (cfg["scopeId"] if cfg["scopeType"] == "project" else None),
            "scope": {"type": cfg["scopeType"], "id": cfg["scopeId"]},
            "authentication": {"available": True, "status": AVAILABLE},
            "project": {
                **(detected.get("projectState") or {"available": False, "status": UNAVAILABLE, "reason": SCOPE_NOT_SUPPORTED}),
                "projectId": project.get("projectId"),
                "projectNumber": (project.get("name") or "").rsplit("/", 1)[-1] or None,
                "displayName": project.get("displayName"),
                "hasOrganization": detected.get("hasOrganization"),
            },
            "resource_discovery": {
                "available": discovery_ok,
                "status": AVAILABLE if discovery_ok else UNAVAILABLE,
                "categories": {c.key: {"label": c.label, **collections.get(c.key, {})} for c in COLLECTIONS},
            },
            "configuration_analysis": {"available": discovery_ok, "status": AVAILABLE if discovery_ok else UNAVAILABLE},
            "scc": scc,
            "checkedAt": datetime.now(timezone.utc).isoformat(),
        }

    def _scc_probe(self, http, session: ProviderSession, has_org: Optional[bool]) -> dict:
        try:
            self._get(http, self._findings_url(session.config), {"pageSize": 1, "filter": 'state="ACTIVE"'}, "Security Command Center")
            return {"available": True, "status": AVAILABLE}
        except CloudProviderError as err:
            return _scc_state(err, has_org, session.config["scopeType"])

    # ── Validation ────────────────────────────────────────────────────

    def validate_connection(self, session: ProviderSession) -> ValidationResult:
        cfg = session.config
        scope_label = f"{cfg['scopeType']} {cfg['scopeId']}"
        result = ValidationResult(ok=False, accountId=cfg["scopeId"], accountLabel=f"Google Cloud {scope_label}")

        try:
            http = self._authenticate(session)
        except CloudProviderError as err:
            result.checks.append({"name": "Authentication", "ok": False, "state": "failed", "detail": err.message})
            result.error = err.to_dict()
            result.capabilities = {"authenticated": False, "authentication": {"available": False, "status": UNAVAILABLE,
                                                                              "reason": GCP_AUTH_FAILED}}
            return result
        result.checks.append({"name": "Authentication", "ok": True, "state": "ok",
                              "detail": f"Service account {cfg['serviceAccountEmail']} accepted"})

        detected = self._detect(session, http, full=False)
        if detected["fatal"] is not None:
            err = detected["fatal"]
            result.checks.append({"name": "Project", "ok": False, "state": "failed", "detail": err.message})
            result.error = err.to_dict()
            return result

        project = detected["project"]
        if project:
            result.accountId = project.get("projectId") or cfg["scopeId"]
            result.accountLabel = f"Google Cloud · {project.get('displayName') or result.accountId}"
            org_detail = ("in a Google Cloud Organization" if detected["hasOrganization"]
                          else "not associated with a Google Cloud Organization")
            result.checks.append({"name": "Project", "ok": True, "state": "ok",
                                  "detail": f"{result.accountId} is active, {org_detail}"})
        elif cfg["scopeType"] == "project":
            ps = detected["projectState"] or {}
            result.checks.append({"name": "Project", "ok": False, "state": "warning", "detail": ps.get("message", "")})

        for col in COLLECTIONS:
            st = detected["collections"].get(col.key, {})
            if st.get("reason") == SCOPE_NOT_SUPPORTED:
                continue
            result.checks.append({"name": col.label, "ok": bool(st.get("available")),
                                  "state": "ok" if st.get("available") else "warning",
                                  "detail": "Readable" if st.get("available") else st.get("message", "")})

        scc = self._scc_probe(http, session, detected["hasOrganization"])
        result.checks.append({"name": "Security Command Center", "ok": scc["available"],
                              "state": "ok" if scc["available"] else "warning",
                              "detail": "Findings are readable" if scc["available"] else scc["message"]})

        result.capabilities = self._capabilities(session, detected, scc)
        discovery_ok = result.capabilities["resource_discovery"]["available"]
        result.scopes = ([f"project {result.accountId}"] if discovery_ok else []) + ([SCOPE_SCC] if scc["available"] else [])

        if discovery_ok or scc["available"]:
            result.ok = True
            return result

        # Authenticated, but nothing is readable: not a useful connection.
        result.error = _nothing_readable(cfg["scopeType"], detected["collections"], scc).to_dict()
        return result

    # ── Fetch ─────────────────────────────────────────────────────────

    def fetch_findings(self, session: ProviderSession, max_findings: int) -> FetchResult:
        cfg = session.config
        scope_label = f"{cfg['scopeType']} {cfg['scopeId']}"
        out = FetchResult(scopedResolution=True)
        seen: set[str] = set()
        started = time.monotonic()

        def add(findings: list[NormalizedFinding], assets: list[NormalizedAsset]) -> None:
            for a in assets:
                out.assets.setdefault(a.assetId, a)
            for f in findings:
                if f.fingerprint in seen:
                    continue
                if len(out.findings) >= max_findings:
                    out.truncated = True
                    return
                seen.add(f.fingerprint)
                out.findings.append(f)

        try:
            http = self._authenticate(session)
        except CloudProviderError as err:
            out.failedScopes.append({"scope": "Authentication", **err.to_dict()})
            return out

        def on_collection(col: Collection, outcome: str, data: dict) -> None:
            if outcome == "completed":
                add(data["findings"], data["assets"])
                if data.get("partial"):
                    # Readable, but some resources were not assessed: keep their findings, skip resolution.
                    out.skippedScopes.append({"scope": col.scope, "code": data["partial"]["reason"],
                                              "message": data["partial"]["message"], "hint": data["partial"].get("hint")})
                else:
                    out.completedScopes.append(col.scope)
            else:
                state, err = data["state"], data["error"]
                entry = {"scope": col.scope, "code": err.code, "reason": state["reason"],
                         "message": state["message"], "hint": state.get("hint")}
                (out.failedScopes if outcome == "failed" else out.skippedScopes).append(entry)
                if outcome == "failed":
                    logger.warning(f"[CLOUD:gcp] integration={session.integration_id} {col.key} failed code={err.code}")

        try:
            detected = self._detect(session, http, full=True, on_collection=on_collection)
        except CloudProviderError as err:
            out.failedScopes.append({"scope": scope_label, **err.to_dict()})
            return out
        if detected["fatal"] is not None:
            out.failedScopes.append({"scope": scope_label, **detected["fatal"].to_dict()})
            return out
        if detected["project"]:
            add([], [config_checks.project_asset(session.integration_id, detected["project"])])

        scc = self._fetch_scc(session, http, out, add, detected["hasOrganization"])
        out.capabilities = self._capabilities(session, detected, scc)
        out.apiLatencyMs = int((time.monotonic() - started) * 1000)

        if not out.completedScopes and not out.failedScopes and not out.findings:
            # Every capability is unavailable: surface why instead of an empty "successful" sync.
            err = _nothing_readable(cfg["scopeType"], detected["collections"], scc)
            out.failedScopes.append({"scope": scope_label, **err.to_dict()})
        return out

    def _fetch_scc(self, session: ProviderSession, http, out: FetchResult, add, has_org: Optional[bool]) -> dict:
        malformed = 0
        try:
            url = self._findings_url(session.config)
            token: Optional[str] = None
            while True:
                params: dict[str, Any] = {"pageSize": PAGE_SIZE, "filter": 'state="ACTIVE"'}
                if token:
                    params["pageToken"] = token
                body = self._get(http, url, params, SCOPE_SCC)
                out.apiCalls += 1
                results = body.get("listFindingsResults", [])
                if not isinstance(results, list):
                    raise CloudProviderError(CloudProviderError.MALFORMED_RESPONSE,
                                             "Google Cloud returned an unexpected response (Security Command Center).")
                page_findings, page_assets = [], []
                for raw in results:
                    try:
                        finding, assets = normalizer.normalize(raw, session.integration_id)
                    except ValueError:
                        malformed += 1
                        continue
                    page_findings.append(finding)
                    page_assets += assets
                add(page_findings, page_assets)
                token = body.get("nextPageToken") or None
                if out.truncated or not token:
                    break
            if not out.truncated:
                out.completedScopes.append(SCOPE_SCC)
            state = {"available": True, "status": AVAILABLE}
        except CloudProviderError as err:
            state = _scc_state(err, has_org, session.config["scopeType"])
            entry = {"scope": SCOPE_SCC, "code": err.code, "reason": state["reason"],
                     "message": state["message"], "hint": state.get("hint")}
            if state["status"] == ERROR:
                out.failedScopes.append(entry)
                logger.warning(f"[CLOUD:gcp] integration={session.integration_id} scc fetch failed code={err.code}")
            else:
                out.skippedScopes.append(entry)
        if malformed:
            logger.warning(f"[CLOUD:gcp] integration={session.integration_id} skipped {malformed} malformed finding(s)")
        return state

    def setup_info(self, org_id: str) -> dict[str, Any]:
        permissions = ",".join(DISCOVERY_PERMISSIONS)
        return {
            "requiredRole": SCC_ROLE,  # kept for older clients; SCC is optional
            "requiredApi": "securitycenter.googleapis.com",
            "requiredPermissions": DISCOVERY_PERMISSIONS,
            "optionalPermissions": SCC_PERMISSIONS,
            "optionalRole": SCC_ROLE,
            "sccDocsUrl": SCC_DOCS_URL,
            "customRoleCommand": (
                "gcloud iam roles create vectraSecurityReader --project=PROJECT_ID \\\n"
                "  --title=\"Vectra Security Reader\" \\\n"
                f"  --permissions={permissions}\n\n"
                "gcloud projects add-iam-policy-binding PROJECT_ID \\\n"
                "  --member=serviceAccount:SERVICE_ACCOUNT_EMAIL \\\n"
                "  --role=projects/PROJECT_ID/roles/vectraSecurityReader"
            ),
        }
