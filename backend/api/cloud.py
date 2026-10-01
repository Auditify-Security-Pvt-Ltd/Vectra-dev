"""
Cloud Security API.

Every route resolves the caller server-side (verified Firebase token → user →
active membership → organization → org role) through cloud.access, and every
document path is built from that resolved organization — never from request
input — so one organization cannot address another's integrations, findings
or assets (IDOR / tenant escape).

Credentials are accepted only on create/update, encrypted immediately, and
never returned, logged or placed in client-readable documents.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from cloud import access, registry, secrets, store, sync
from cloud.access import OrgContext, require_permission
from cloud.errors import CloudProviderError, ConfigurationError
from cloud.models import SEVERITIES
from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/cloud", tags=["Cloud Security"])

MAX_BODY_JSON = 32_000
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f<>]")

SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Fields returned by list endpoints; descriptions and raw payloads only in detail.
LIST_FIELDS = [
    "fingerprint", "provider", "integrationId", "providerProduct", "title", "severity", "providerSeverity",
    "status", "findingType", "findingClass", "assetId", "resourceType", "resourceId", "resourceName",
    "accountId", "region", "cveId", "cveIds", "cvssScore", "firstSeenAt", "lastSeenAt", "updatedAt",
    "providerUpdatedAt", "resolvedAt", "source", "category",
]


# ── Helpers ───────────────────────────────────────────────────────────

def _error(code: int, error: str, message: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=code, detail={"code": error, "message": message, **extra})


def _provider_http_error(err: CloudProviderError) -> HTTPException:
    code = status.HTTP_503_SERVICE_UNAVAILABLE if err.code == CloudProviderError.NOT_CONFIGURED else status.HTTP_400_BAD_REQUEST
    return _error(code, err.code, err.message, hint=err.hint)


def _check_id(value: str, what: str) -> str:
    if not _ID_RE.match(value or ""):
        raise _error(status.HTTP_404_NOT_FOUND, "NOT_FOUND", f"{what} not found.")
    return value


def _integration_or_404(ctx: OrgContext, integration_id: str) -> dict:
    doc = store.get_integration(ctx.org_id, _check_id(integration_id, "Integration"))
    if not doc:
        raise _error(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Integration not found.")
    return doc


def _clean_display_name(value: Optional[str], fallback: str) -> str:
    name = _CONTROL_RE.sub("", (value or "").strip())[:80]
    return name or fallback


def _guard_size(*payloads: Any) -> None:
    try:
        size = sum(len(json.dumps(p, default=str)) for p in payloads)
    except (TypeError, ValueError):
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_INPUT", "Request body is not valid JSON.")
    if size > MAX_BODY_JSON:
        raise _error(413, "INVALID_INPUT", "Request body is too large.")


# ── Models (extra fields rejected: no mass assignment) ────────────────

class CreateIntegrationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(max_length=20)
    displayName: Optional[str] = Field(default=None, max_length=200)
    authMethod: str = Field(max_length=40)
    config: dict[str, Any] = Field(default_factory=dict)
    credentials: Optional[dict[str, Any]] = None


class UpdateIntegrationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    displayName: Optional[str] = Field(default=None, max_length=200)
    config: Optional[dict[str, Any]] = None
    credentials: Optional[dict[str, Any]] = None


# ── Providers ─────────────────────────────────────────────────────────

@router.get("/providers")
async def list_providers(ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_SECURITY))) -> dict:
    return {
        "providers": registry.catalogue(),
        "credentialStorageConfigured": secrets.is_configured(),
        "permissions": sorted(access.ROLE_PERMISSIONS.get(ctx.org_role, set())),
    }


@router.get("/providers/{provider}/setup")
async def provider_setup(
    provider: str,
    ctx: OrgContext = Depends(require_permission(access.MANAGE_CLOUD_INTEGRATIONS)),
) -> dict:
    impl = registry.get_provider(provider)
    if impl is None:
        raise _error(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Provider not supported.")
    return {"provider": provider, **impl.setup_info(ctx.org_id)}


# ── Integrations ──────────────────────────────────────────────────────

@router.get("/integrations")
async def list_integrations(
    includeDisconnected: bool = Query(False),
    ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_SECURITY)),
) -> dict:
    docs = await asyncio.to_thread(store.list_integrations, ctx.org_id, includeDisconnected)
    return {"integrations": [store.public_integration(d) for d in docs]}


@router.post("/integrations", status_code=status.HTTP_201_CREATED)
async def create_integration(
    body: CreateIntegrationBody,
    ctx: OrgContext = Depends(require_permission(access.MANAGE_CLOUD_INTEGRATIONS)),
) -> dict:
    _guard_size(body.config, body.credentials)
    impl = registry.get_provider(body.provider)
    if impl is None:
        raise _error(status.HTTP_400_BAD_REQUEST, "UNSUPPORTED_PROVIDER", "This cloud provider is not supported yet.")

    try:
        config, credentials = impl.parse_config(body.authMethod, body.config, body.credentials)
        if credentials and not secrets.is_configured():
            secrets.seal(ctx.org_id, "probe", {})  # raises NOT_CONFIGURED with a safe message
        if body.authMethod == "assume_role":
            secrets.aws_external_id(ctx.org_id)
    except ConfigurationError as exc:
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_CONFIGURATION", str(exc))
    except CloudProviderError as err:
        raise _provider_http_error(err)

    integration_id = store.new_id("cint")
    session = store.ProviderSession(org_id=ctx.org_id, integration_id=integration_id,
                                    auth_method=body.authMethod, config=config, credentials=credentials)
    validation = await asyncio.to_thread(impl.validate_connection, session)
    log = f"org={ctx.org_id} provider={body.provider} integration={integration_id}"

    if not validation.ok:
        logger.info(f"[CLOUD] connection validation failed {log} code={(validation.error or {}).get('code')}")
        store.audit(ctx, ctx.org_id, "cloud.integration.validation_failed",
                    {"integrationId": integration_id, "provider": body.provider}, "failed",
                    (validation.error or {}).get("message", ""))
        raise _error(status.HTTP_400_BAD_REQUEST, "VALIDATION_FAILED",
                     (validation.error or {}).get("message") or "The connection could not be validated.",
                     hint=(validation.error or {}).get("hint"), validation=validation.to_dict())

    doc = await asyncio.to_thread(
        store.create_integration, ctx, body.provider,
        _clean_display_name(body.displayName, validation.accountLabel or impl.display_name),
        body.authMethod, config, credentials, validation.to_dict(), integration_id,
    )
    store.audit(ctx, ctx.org_id, "cloud.integration.created", doc, "success",
                f"{impl.display_name} {validation.accountId or ''}".strip())
    logger.info(f"[CLOUD] integration created {log} account={validation.accountId}")
    return {"integration": store.public_integration(doc), "validation": validation.to_dict()}


@router.get("/integrations/{integration_id}")
async def get_integration(
    integration_id: str,
    ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_SECURITY)),
) -> dict:
    doc = _integration_or_404(ctx, integration_id)
    return {"integration": store.public_integration(doc)}


@router.patch("/integrations/{integration_id}")
async def update_integration(
    integration_id: str,
    body: UpdateIntegrationBody,
    ctx: OrgContext = Depends(require_permission(access.MANAGE_CLOUD_INTEGRATIONS)),
) -> dict:
    """Rename, change configuration or rotate credentials. Re-validates before saving."""
    _guard_size(body.config, body.credentials)
    doc = _integration_or_404(ctx, integration_id)
    if doc.get("status") == "disconnected":
        raise _error(status.HTTP_409_CONFLICT, "DISCONNECTED", "Reconnect by creating a new integration.")

    changes: dict[str, Any] = {}
    if body.displayName is not None:
        changes["displayName"] = _clean_display_name(body.displayName, doc.get("displayName") or "Cloud account")

    validation = None
    if body.config is not None or body.credentials is not None:
        impl = registry.get_provider(doc["provider"])
        try:
            current = await asyncio.to_thread(store.load_session, ctx.org_id, doc)
            merged_config = {**(doc.get("config") or {}), **(body.config or {})}
            config, credentials = impl.parse_config(
                doc["authMethod"], merged_config, body.credentials if body.credentials is not None else current.credentials,
            )
        except ConfigurationError as exc:
            raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_CONFIGURATION", str(exc))
        except CloudProviderError as err:
            raise _provider_http_error(err)

        session = store.ProviderSession(ctx.org_id, integration_id, doc["authMethod"], config, credentials)
        result = await asyncio.to_thread(impl.validate_connection, session)
        if not result.ok:
            raise _error(status.HTTP_400_BAD_REQUEST, "VALIDATION_FAILED",
                         (result.error or {}).get("message") or "The connection could not be validated.",
                         hint=(result.error or {}).get("hint"), validation=result.to_dict())
        validation = result.to_dict()
        changes.update({"config": config, "status": "connected", "accountId": result.accountId,
                        "accountLabel": result.accountLabel, "validation": {**validation, "validatedAt": store.now_iso()},
                        **({"capabilities": result.capabilities} if result.capabilities else {})})
        if credentials and body.credentials is not None:
            store.col(ctx.org_id, store.SECRETS).document(integration_id).set({
                "integrationId": integration_id,
                "envelope": secrets.seal(ctx.org_id, integration_id, credentials),
                "updatedAt": store.now_iso(),
            })
            store.audit(ctx, ctx.org_id, "cloud.integration.credentials_updated", doc, "success")

    if changes:
        store.update_integration(ctx.org_id, integration_id, changes)
        store.audit(ctx, ctx.org_id, "cloud.integration.updated", doc, "success", ", ".join(sorted(changes)))
    return {"integration": store.public_integration(store.get_integration(ctx.org_id, integration_id) or doc),
            "validation": validation}


@router.post("/integrations/{integration_id}/validate")
async def validate_integration(
    integration_id: str,
    ctx: OrgContext = Depends(require_permission(access.MANAGE_CLOUD_INTEGRATIONS)),
) -> dict:
    doc = _integration_or_404(ctx, integration_id)
    if doc.get("status") == "disconnected":
        raise _error(status.HTTP_409_CONFLICT, "DISCONNECTED", "This integration is disconnected.")
    impl = registry.get_provider(doc["provider"])
    try:
        session = await asyncio.to_thread(store.load_session, ctx.org_id, doc)
    except CloudProviderError as err:
        raise _provider_http_error(err)
    result = await asyncio.to_thread(impl.validate_connection, session)
    store.update_integration(ctx.org_id, integration_id, {
        "status": "connected" if result.ok else "error",
        "validation": {**result.to_dict(), "validatedAt": store.now_iso()},
        **({"accountId": result.accountId, "accountLabel": result.accountLabel} if result.ok else {}),
        **({"capabilities": result.capabilities} if result.capabilities else {}),
    })
    store.audit(ctx, ctx.org_id, "cloud.integration.validated", doc, "success" if result.ok else "failed",
                (result.error or {}).get("message", ""))
    return {"validation": result.to_dict()}


@router.post("/integrations/{integration_id}/sync", status_code=status.HTTP_202_ACCEPTED)
async def start_sync(
    integration_id: str,
    ctx: OrgContext = Depends(require_permission(access.SYNC_CLOUD_FINDINGS)),
) -> dict:
    _check_id(integration_id, "Integration")
    try:
        claimed = await asyncio.to_thread(sync.claim_sync, ctx, integration_id, "manual")
    except sync.IntegrationUnavailable as exc:
        if str(exc) == "disconnected":
            raise _error(status.HTTP_409_CONFLICT, "DISCONNECTED", "This integration is disconnected.")
        raise _error(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Integration not found.")
    except sync.SyncConflict as exc:
        raise _error(status.HTTP_409_CONFLICT, "SYNC_IN_PROGRESS", "A sync is already running for this integration.",
                     syncId=exc.sync_id)

    sync_doc = claimed["sync"]
    sync.launch(ctx.org_id, integration_id, sync_doc["syncId"], ctx)
    return {"syncId": sync_doc["syncId"], "status": sync_doc["status"], "provider": sync_doc["provider"]}


@router.get("/integrations/{integration_id}/syncs")
async def list_syncs(
    integration_id: str,
    limit: int = Query(20, ge=1, le=50),
    ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_SECURITY)),
) -> dict:
    _integration_or_404(ctx, integration_id)

    def _load() -> list[dict]:
        docs = [d.to_dict() or {} for d in store.col(ctx.org_id, store.SYNCS)
                .where(filter=store.field_eq("integrationId", integration_id)).stream()]
        docs.sort(key=lambda d: d.get("createdAt") or "", reverse=True)
        return [sync.reconcile_orphan(ctx.org_id, d) for d in docs[:limit]]

    return {"syncs": await asyncio.to_thread(_load)}


@router.get("/syncs/{sync_id}")
async def get_sync(
    sync_id: str,
    ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_SECURITY)),
) -> dict:
    snap = store.col(ctx.org_id, store.SYNCS).document(_check_id(sync_id, "Sync")).get()
    if not snap.exists:
        raise _error(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Sync not found.")
    return {"sync": sync.reconcile_orphan(ctx.org_id, snap.to_dict() or {})}


@router.delete("/integrations/{integration_id}")
async def disconnect_integration(
    integration_id: str,
    deleteFindings: bool = Query(False),
    ctx: OrgContext = Depends(require_permission(access.DELETE_CLOUD_INTEGRATION)),
) -> dict:
    doc = _integration_or_404(ctx, integration_id)
    removed = await asyncio.to_thread(store.disconnect_integration, ctx.org_id, integration_id, deleteFindings)
    store.audit(ctx, ctx.org_id, "cloud.integration.disconnected", doc, "success",
                "credentials destroyed" + (f"; {removed['findings']} findings removed" if deleteFindings else "; findings kept"))
    logger.info(f"[CLOUD] integration disconnected org={ctx.org_id} integration={integration_id} delete_findings={deleteFindings}")
    return {"integrationId": integration_id, "status": "disconnected", "removed": removed}


# ── Findings ──────────────────────────────────────────────────────────

def _load_findings(org_id: str, fields: Optional[list[str]] = LIST_FIELDS) -> list[dict]:
    query = store.col(org_id, store.FINDINGS)
    if fields is not None:
        query = query.select(fields)
    return [d.to_dict() or {} for d in query.stream()]


def _csv(value: Optional[str]) -> set[str]:
    return {v.strip().lower() for v in (value or "").split(",") if v.strip()}


@router.get("/findings")
async def list_findings(
    search: str = Query("", max_length=200),
    provider: str = Query("", max_length=60),
    severity: str = Query("", max_length=60),
    status_f: str = Query("", alias="status", max_length=60),
    resourceType: str = Query("", max_length=200),
    region: str = Query("", max_length=64),
    cve: str = Query("", max_length=40),
    findingType: str = Query("", max_length=300),
    integrationId: str = Query("", max_length=80),
    sort: Literal["severity", "newest", "updated"] = Query("severity"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100_000),
    ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_FINDINGS)),
) -> dict:
    """
    Server-side filtered, sorted and paginated list. Only one page is returned
    to the browser; facets describe the whole organization for filter menus.
    """
    rows = await asyncio.to_thread(_load_findings, ctx.org_id)

    facets = {
        "providers": sorted({r.get("provider") for r in rows if r.get("provider")}),
        "regions": sorted({r.get("region") for r in rows if r.get("region")}),
        "resourceTypes": sorted({r.get("resourceType") for r in rows if r.get("resourceType")}),
        "findingTypes": sorted({r.get("findingType") for r in rows if r.get("findingType")})[:200],
        "integrationIds": sorted({r.get("integrationId") for r in rows if r.get("integrationId")}),
    }

    providers, severities, statuses = _csv(provider), _csv(severity), _csv(status_f)
    needle, cve_needle = search.strip().lower(), cve.strip().upper()

    def keep(r: dict) -> bool:
        if providers and r.get("provider") not in providers: return False
        if severities and r.get("severity") not in severities: return False
        if statuses and r.get("status") not in statuses: return False
        if integrationId and r.get("integrationId") != integrationId: return False
        if resourceType and r.get("resourceType") != resourceType: return False
        if region and r.get("region") != region: return False
        if findingType and r.get("findingType") != findingType: return False
        if cve_needle and not any(cve_needle in c for c in (r.get("cveIds") or [])): return False
        if needle:
            hay = " ".join(str(r.get(k) or "") for k in
                           ("title", "resourceId", "resourceName", "accountId", "findingType", "cveId", "providerProduct")).lower()
            if needle not in hay: return False
        return True

    filtered = [r for r in rows if keep(r)]
    if sort == "newest":
        filtered.sort(key=lambda r: r.get("firstSeenAt") or "", reverse=True)
    elif sort == "updated":
        filtered.sort(key=lambda r: r.get("providerUpdatedAt") or r.get("updatedAt") or "", reverse=True)
    else:
        # Most severe first; ties broken by CVSS, then most recently seen (stable sorts).
        filtered.sort(key=lambda r: r.get("lastSeenAt") or "", reverse=True)
        filtered.sort(key=lambda r: (SEVERITY_RANK.get(r.get("severity"), 9), -(r.get("cvssScore") or 0)))

    return {"total": len(filtered), "limit": limit, "offset": offset,
            "findings": filtered[offset:offset + limit], "facets": facets}


@router.get("/findings/{fingerprint}")
async def get_finding(
    fingerprint: str,
    ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_FINDINGS)),
) -> dict:
    if not re.match(r"^[a-f0-9]{40}$", fingerprint or ""):
        raise _error(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Finding not found.")
    snap = store.col(ctx.org_id, store.FINDINGS).document(fingerprint).get()
    if not snap.exists:
        raise _error(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Finding not found.")
    finding = snap.to_dict() or {}
    raw = finding.pop("rawProviderMetadata", "") or ""
    try:
        finding["providerMetadata"] = json.loads(raw) if raw else None
    except ValueError:
        finding["providerMetadata"] = None

    asset = None
    if finding.get("assetId"):
        a = store.col(ctx.org_id, store.ASSETS).document(finding["assetId"]).get()
        asset = a.to_dict() if a.exists else None
    integ = store.get_integration(ctx.org_id, finding.get("integrationId") or "") if finding.get("integrationId") else None
    return {
        "finding": finding,
        "asset": asset,
        "integration": {k: (integ or {}).get(k) for k in ("integrationId", "displayName", "provider", "status", "accountLabel")} if integ else None,
    }


# ── Assets ────────────────────────────────────────────────────────────

@router.get("/assets")
async def list_assets(
    search: str = Query("", max_length=200),
    provider: str = Query("", max_length=60),
    resourceType: str = Query("", max_length=200),
    integrationId: str = Query("", max_length=80),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100_000),
    ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_SECURITY)),
) -> dict:
    rows = await asyncio.to_thread(lambda: [d.to_dict() or {} for d in store.col(ctx.org_id, store.ASSETS).stream()])
    providers, needle = _csv(provider), search.strip().lower()
    filtered = [
        r for r in rows
        if (not providers or r.get("provider") in providers)
        and (not resourceType or r.get("resourceType") == resourceType)
        and (not integrationId or r.get("integrationId") == integrationId)
        and (not needle or needle in " ".join(str(r.get(k) or "") for k in ("resourceId", "resourceName", "accountId", "resourceType")).lower())
    ]
    filtered.sort(key=lambda r: (-(r.get("openFindingCount") or 0), r.get("resourceType") or "", r.get("resourceId") or ""))
    return {
        "total": len(filtered), "limit": limit, "offset": offset, "assets": filtered[offset:offset + limit],
        "facets": {"resourceTypes": sorted({r.get("resourceType") for r in rows if r.get("resourceType")})},
    }


# ── Summary (dashboard) ───────────────────────────────────────────────

@router.get("/summary")
async def summary(ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_SECURITY))) -> dict:
    """Aggregates from per-integration counters written at sync time — no full scan."""
    integrations = await asyncio.to_thread(store.list_integrations, ctx.org_id, False)
    totals = dict(store.EMPTY_COUNTS)
    by_provider: dict[str, dict] = {}
    health = {"connected": 0, "error": 0, "syncing": 0, "failedLastSync": 0}
    last_sync = None
    for i in integrations:
        counts = i.get("counts") or {}
        for k in totals:
            totals[k] += int(counts.get(k) or 0)
        p = by_provider.setdefault(i["provider"], {"integrations": 0, "findings": 0, "open": 0, "assets": 0})
        p["integrations"] += 1
        p["findings"] += int(counts.get("findings") or 0)
        p["open"] += int(counts.get("open") or 0)
        p["assets"] += int(counts.get("assets") or 0)
        health["connected" if i.get("status") == "connected" else "error"] += 1
        if i.get("syncStatus") in ("queued", "running"):
            health["syncing"] += 1
        if i.get("lastSyncStatus") == "failed":
            health["failedLastSync"] += 1
        if i.get("lastSyncAt") and (last_sync is None or i["lastSyncAt"] > last_sync):
            last_sync = i["lastSyncAt"]

    def _recent() -> list[dict]:
        rows = _load_findings(ctx.org_id)
        rows = [r for r in rows if r.get("status") == "open"]
        rows.sort(key=lambda r: (r.get("lastSeenAt") or "", -SEVERITY_RANK.get(r.get("severity"), 9)), reverse=True)
        return rows[:10]

    return {
        "integrations": [store.public_integration(i) for i in integrations],
        "totals": totals,
        "byProvider": by_provider,
        "health": {**health, "lastSyncAt": last_sync},
        "recentFindings": await asyncio.to_thread(_recent) if integrations else [],
    }


# ── Report data ───────────────────────────────────────────────────────

REPORT_LIMIT = 5_000


@router.get("/report-data")
async def report_data(
    integrationId: str = Query("all", max_length=80),
    includeResolved: bool = Query(False),
    ctx: OrgContext = Depends(require_permission(access.VIEW_CLOUD_FINDINGS)),
) -> dict:
    """Everything the existing client-side report generator needs, org-scoped."""
    integrations = await asyncio.to_thread(store.list_integrations, ctx.org_id, True)
    if integrationId != "all":
        integrations = [i for i in integrations if i.get("integrationId") == integrationId]
        if not integrations:
            raise _error(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Integration not found.")
    ids = {i["integrationId"] for i in integrations}

    def _load() -> tuple[list[dict], list[dict]]:
        findings = [f for f in _load_findings(ctx.org_id, None) if f.get("integrationId") in ids
                    and (includeResolved or f.get("status") != "resolved")]
        for f in findings:
            f.pop("rawProviderMetadata", None)
        findings.sort(key=lambda r: (SEVERITY_RANK.get(r.get("severity"), 9), r.get("title") or ""))
        assets = [a for a in (d.to_dict() or {} for d in store.col(ctx.org_id, store.ASSETS).stream())
                  if a.get("integrationId") in ids]
        assets.sort(key=lambda a: -(a.get("openFindingCount") or 0))
        return findings, assets

    findings, assets = await asyncio.to_thread(_load)
    return {
        "integrations": [store.public_integration(i) for i in integrations],
        "findings": findings[:REPORT_LIMIT],
        "assets": assets[:REPORT_LIMIT],
        "truncated": len(findings) > REPORT_LIMIT or len(assets) > REPORT_LIMIT,
        "totalFindings": len(findings),
    }
