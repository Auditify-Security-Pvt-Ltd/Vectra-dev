"""
Cloud synchronization engine.

    POST /cloud/integrations/{id}/sync
        → start_sync(): atomically claim the integration (one sync at a time),
          create organizations/{orgId}/cloud_syncs/{syncId} as "queued"
        → background task run_sync(): fetch (paged) → normalize → dedupe →
          upsert findings/assets → resolve findings no longer reported →
          update counters and sync metadata → audit

Provider SDK calls and Firestore writes are blocking, so they run in a worker
thread; the HTTP request returns immediately with the sync id, and the UI polls
GET /cloud/syncs/{syncId}.

Resolution rule: a stored open/suppressed finding that the provider did not
return is marked resolved ("no longer reported") only when the scope it belongs
to was fetched completely. Nothing is resolved after a truncated fetch, and
findings are never deleted by a sync.

Cloud syncs do NOT consume the organization scan quota: the quota covers
scanner executions (web, network, SAST); a sync imports results the customer's
own cloud security service already produced.

Deployment note: the running-task registry is in-process, matching the
existing single-instance scan architecture. A sync interrupted by a restart is
detected and marked failed the next time its status is read.
"""
from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from cloud import registry, store
from cloud.access import OrgContext
from cloud.errors import CloudProviderError
from cloud.models import SEVERITIES, STATUS_OPEN, STATUS_RESOLVED, FetchResult
from services import firebase
from utils.logger import get_logger

logger = get_logger(__name__)

MAX_FINDINGS_PER_SYNC = int(os.getenv("CLOUD_SYNC_MAX_FINDINGS", "25000"))
ORPHAN_GRACE_SECONDS = 120
MAX_STATUS_HISTORY = 20

_TASKS: dict[str, asyncio.Task] = {}


class SyncConflict(Exception):
    """A sync is already queued or running for this integration."""

    def __init__(self, sync_id: Optional[str]):
        super().__init__("SYNC_IN_PROGRESS")
        self.sync_id = sync_id


class IntegrationUnavailable(Exception):
    pass


def _age_seconds(iso: Optional[str]) -> float:
    if not iso:
        return float("inf")
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds()
    except ValueError:
        return float("inf")


# ── Start ─────────────────────────────────────────────────────────────

def claim_sync(ctx: OrgContext, integration_id: str, trigger: str) -> dict:
    """Transactionally create a queued sync, or raise SyncConflict / IntegrationUnavailable."""
    from firebase_admin import firestore as fb_firestore

    db = firebase.db()
    integ_ref = store.col(ctx.org_id, store.INTEGRATIONS).document(integration_id)
    sync_id = store.new_id("sync")
    sync_ref = store.col(ctx.org_id, store.SYNCS).document(sync_id)

    @fb_firestore.transactional
    def _claim(txn) -> dict:
        snap = integ_ref.get(transaction=txn)
        if not snap.exists:
            raise IntegrationUnavailable("not_found")
        integ = snap.to_dict() or {}
        if integ.get("status") == "disconnected":
            raise IntegrationUnavailable("disconnected")

        current = integ.get("currentSyncId")
        if integ.get("syncStatus") in ("queued", "running") and current:
            task = _TASKS.get(current)
            if task and not task.done():
                raise SyncConflict(current)
            cur_snap = store.col(ctx.org_id, store.SYNCS).document(current).get(transaction=txn)
            cur = (cur_snap.to_dict() or {}) if cur_snap.exists else {}
            if cur.get("status") in ("queued", "running"):
                if _age_seconds(cur.get("startedAt") or cur.get("createdAt")) < ORPHAN_GRACE_SECONDS:
                    raise SyncConflict(current)
                # No live task owns it (e.g. backend restarted): record the interruption.
                txn.update(cur_snap.reference, {
                    "status": "failed", "completedAt": store.now_iso(),
                    "error": {"code": "INTERRUPTED", "message": "The sync was interrupted before it finished."},
                })

        ts = store.now_iso()
        sync_doc = {
            "syncId": sync_id,
            "integrationId": integration_id,
            "provider": integ.get("provider"),
            "status": "queued",
            "trigger": trigger,
            "requestedBy": ctx.uid,
            "createdAt": ts,
            "startedAt": None,
            "completedAt": None,
            "durationMs": None,
            "stats": None,
            "failedScopes": [],
            "truncated": False,
            "error": None,
        }
        txn.set(sync_ref, sync_doc)
        txn.update(integ_ref, {"syncStatus": "queued", "currentSyncId": sync_id, "updatedAt": ts})
        return {"sync": sync_doc, "integration": integ}

    return _claim(db.transaction())


def launch(org_id: str, integration_id: str, sync_id: str, ctx: OrgContext) -> None:
    task = asyncio.create_task(_run_async(org_id, integration_id, sync_id, ctx))
    _TASKS[sync_id] = task
    task.add_done_callback(lambda _t: _TASKS.pop(sync_id, None))


async def _run_async(org_id: str, integration_id: str, sync_id: str, ctx: OrgContext) -> None:
    try:
        await asyncio.to_thread(run_sync, org_id, integration_id, sync_id, ctx)
    except Exception as exc:  # run_sync records its own failures; this is a last resort
        logger.error(f"[CLOUD] sync={sync_id} crashed: {type(exc).__name__}")


def reconcile_orphan(org_id: str, sync: dict) -> dict:
    """Mark a queued/running sync failed if no task in this process owns it."""
    if sync.get("status") not in ("queued", "running"):
        return sync
    task = _TASKS.get(sync["syncId"])
    if task and not task.done():
        return sync
    if _age_seconds(sync.get("startedAt") or sync.get("createdAt")) < ORPHAN_GRACE_SECONDS:
        return sync
    error = {"code": "INTERRUPTED", "message": "The sync was interrupted before it finished. Retry the sync."}
    store.col(org_id, store.SYNCS).document(sync["syncId"]).set(
        {"status": "failed", "completedAt": store.now_iso(), "error": error}, merge=True)
    integ = store.get_integration(org_id, sync["integrationId"]) or {}
    if integ.get("currentSyncId") == sync["syncId"]:
        store.update_integration(org_id, sync["integrationId"], {
            "syncStatus": "idle", "lastSyncStatus": "failed", "lastSyncError": error,
        })
    return {**sync, "status": "failed", "error": error}


# ── Run ───────────────────────────────────────────────────────────────

def run_sync(org_id: str, integration_id: str, sync_id: str, ctx: Optional[OrgContext] = None) -> dict:
    started = time.monotonic()
    started_at = store.now_iso()
    sync_ref = store.col(org_id, store.SYNCS).document(sync_id)
    integration = store.get_integration(org_id, integration_id) or {}
    provider_key = integration.get("provider")
    log = f"org={org_id} integration={integration_id} provider={provider_key} sync={sync_id}"

    sync_ref.set({"status": "running", "startedAt": started_at}, merge=True)
    store.update_integration(org_id, integration_id, {"syncStatus": "running"})
    store.audit(ctx, org_id, "cloud.sync.started", integration, "started")
    logger.info(f"[CLOUD] sync started {log}")

    try:
        provider = registry.get_provider(provider_key or "")
        if provider is None:
            raise CloudProviderError(CloudProviderError.INVALID_CONFIGURATION, "This cloud provider is not supported.")
        session = store.load_session(org_id, integration)
        fetched = provider.fetch_findings(session, MAX_FINDINGS_PER_SYNC)

        if not fetched.completedScopes and fetched.failedScopes:
            first = fetched.failedScopes[0]
            raise CloudProviderError(first.get("code") or CloudProviderError.PROVIDER_ERROR,
                                     first.get("message") or "The provider could not be reached.", first.get("hint"))

        stats = persist(org_id, integration_id, sync_id, fetched)
        status = "partial" if (fetched.failedScopes or fetched.truncated) else "completed"
        duration = int((time.monotonic() - started) * 1000)
        error = None
        if fetched.failedScopes:
            error = {"code": "PARTIAL_FAILURE",
                     "message": f"{len(fetched.failedScopes)} scope(s) could not be synced.",
                     "scopes": fetched.failedScopes}
        elif fetched.truncated:
            error = {"code": "TRUNCATED",
                     "message": f"Sync stopped at {MAX_FINDINGS_PER_SYNC} findings; resolution was skipped."}

        completed_at = store.now_iso()
        sync_ref.set({
            "status": status, "completedAt": completed_at, "durationMs": duration, "stats": stats,
            "failedScopes": fetched.failedScopes, "skippedScopes": fetched.skippedScopes,
            "truncated": fetched.truncated, "error": error,
            **({"capabilities": fetched.capabilities} if fetched.capabilities else {}),
        }, merge=True)
        still_connected = (store.get_integration(org_id, integration_id) or {}).get("status") != "disconnected"
        store.update_integration(org_id, integration_id, {
            "syncStatus": "idle", "lastSyncAt": completed_at, "lastSyncStatus": status,
            "lastSyncError": error, "lastSuccessfulSyncAt": completed_at, "lastSyncStats": stats,
            "counts": stats["counts"], **({"status": "connected"} if still_connected else {}),
            **({"capabilities": fetched.capabilities} if fetched.capabilities else {}),
        })
        store.audit(ctx, org_id, "cloud.sync.completed", integration, status,
                    f"{stats['findingsDiscovered']} findings, {stats['newFindings']} new, "
                    f"{stats['resolvedFindings']} resolved")
        logger.info(
            f"[CLOUD] sync {status} {log} findings={stats['findingsDiscovered']} new={stats['newFindings']} "
            f"updated={stats['updatedFindings']} resolved={stats['resolvedFindings']} "
            f"assets={stats['assetsDiscovered']} api_calls={fetched.apiCalls} "
            f"api_latency_ms={fetched.apiLatencyMs} duration_ms={duration}"
        )
        return {"status": status, "provider": provider_key, **{k: v for k, v in stats.items() if k != "counts"}}

    except Exception as exc:
        err = exc if isinstance(exc, CloudProviderError) else CloudProviderError(
            CloudProviderError.PROVIDER_ERROR, "The sync failed unexpectedly.")
        duration = int((time.monotonic() - started) * 1000)
        completed_at = store.now_iso()
        sync_ref.set({"status": "failed", "completedAt": completed_at, "durationMs": duration,
                      "error": err.to_dict()}, merge=True)
        changes: dict[str, Any] = {
            "syncStatus": "idle", "lastSyncAt": completed_at, "lastSyncStatus": "failed",
            "lastSyncError": err.to_dict(),
        }
        disconnected = (store.get_integration(org_id, integration_id) or {}).get("status") == "disconnected"
        if not disconnected and err.code in (CloudProviderError.INVALID_CREDENTIALS, CloudProviderError.ACCESS_DENIED,
                                             CloudProviderError.SERVICE_NOT_ENABLED):
            changes["status"] = "error"
        store.update_integration(org_id, integration_id, changes)
        store.audit(ctx, org_id, "cloud.sync.failed", integration, "failed", err.message)
        logger.warning(f"[CLOUD] sync failed {log} code={err.code} duration_ms={duration}"
                       + ("" if isinstance(exc, CloudProviderError) else f" exception={type(exc).__name__}"))
        return {"status": "failed", "provider": provider_key, "error": err.to_dict()}


# ── Persist ───────────────────────────────────────────────────────────

def _resolution_scope(prior: dict) -> str | None:
    if prior.get("scope"):
        return prior["scope"]
    # GCP findings stored before scopes existed all came from Security Command Center.
    return "Security Command Center" if prior.get("provider") == "gcp" else None


def persist(org_id: str, integration_id: str, sync_id: str, fetched: FetchResult) -> dict:
    ts = store.now_iso()
    findings_col = store.col(org_id, store.FINDINGS)
    assets_col = store.col(org_id, store.ASSETS)

    existing: dict[str, dict] = {
        d.id: d.to_dict() or {}
        for d in findings_col.where(filter=store.field_eq("integrationId", integration_id))
        .select(["status", "firstSeenAt", "statusHistory", "region", "scope", "provider", "createdAt", "severity",
                 "assetId"]).stream()
    }
    existing_assets = {
        d.id: d.to_dict() or {}
        for d in assets_col.where(filter=store.field_eq("integrationId", integration_id)).select(["firstSeenAt"]).stream()
    }

    ops: list[tuple[str, Any, dict]] = []
    new = updated = resolved = 0
    seen: set[str] = set()
    final: dict[str, dict] = {fp: {"status": d.get("status"), "severity": d.get("severity"),
                                   "assetId": d.get("assetId")} for fp, d in existing.items()}

    for f in fetched.findings:
        seen.add(f.fingerprint)
        data = f.to_dict()
        data.update({"organizationId": org_id, "lastSeenAt": ts, "updatedAt": ts, "lastSyncId": sync_id,
                     "resolvedReason": None})
        prior = existing.get(f.fingerprint)
        if prior is None:
            new += 1
            data.update({"firstSeenAt": ts, "createdAt": ts, "resolvedAt": ts if f.status == STATUS_RESOLVED else None,
                         "statusHistory": [{"status": f.status, "at": ts, "source": "provider"}]})
            ops.append(("set", findings_col.document(f.fingerprint), data))
        else:
            updated += 1
            history = list(prior.get("statusHistory") or [])
            if prior.get("status") != f.status:
                history.append({"status": f.status, "at": ts, "source": "provider"})
                data["resolvedAt"] = ts if f.status == STATUS_RESOLVED else None
            data["statusHistory"] = history[-MAX_STATUS_HISTORY:]
            ops.append(("merge", findings_col.document(f.fingerprint), data))
        final[f.fingerprint] = {"status": f.status, "severity": f.severity, "assetId": f.assetId}

    # Findings the provider stopped reporting.
    if not fetched.truncated:
        complete_all = not fetched.failedScopes and not fetched.skippedScopes
        completed = set(fetched.completedScopes)
        for fp, prior in existing.items():
            if fp in seen or prior.get("status") == STATUS_RESOLVED:
                continue
            if fetched.scopedResolution:
                # Only a scope read completely in this sync may resolve its findings;
                # an unavailable capability (e.g. SCC) never resolves anything.
                if _resolution_scope(prior) not in completed:
                    continue
            elif not complete_all and prior.get("region") not in completed:
                continue
            resolved += 1
            history = list(prior.get("statusHistory") or [])
            history.append({"status": STATUS_RESOLVED, "at": ts, "source": "no_longer_reported"})
            ops.append(("merge", findings_col.document(fp), {
                "status": STATUS_RESOLVED, "resolvedAt": ts, "resolvedReason": "no_longer_reported",
                "updatedAt": ts, "lastSyncId": sync_id, "statusHistory": history[-MAX_STATUS_HISTORY:],
            }))
            final[fp]["status"] = STATUS_RESOLVED

    # Assets referenced by this sync's findings.
    per_asset: dict[str, dict[str, int]] = {}
    for f in fetched.findings:
        if f.assetId:
            c = per_asset.setdefault(f.assetId, {"findingCount": 0, "openFindingCount": 0})
            c["findingCount"] += 1
            if f.status == STATUS_OPEN:
                c["openFindingCount"] += 1
    for asset_id, asset in fetched.assets.items():
        data = asset.to_dict()
        data.update({"organizationId": org_id, "lastSeenAt": ts, "updatedAt": ts, "lastSyncId": sync_id,
                     **per_asset.get(asset_id, {"findingCount": 0, "openFindingCount": 0})})
        if asset_id not in existing_assets:
            data["firstSeenAt"] = ts
            ops.append(("set", assets_col.document(asset_id), data))
        else:
            ops.append(("merge", assets_col.document(asset_id), data))

    batched_writes = store.batched_writes(ops)

    counts = dict(store.EMPTY_COUNTS)
    for item in final.values():
        counts["findings"] += 1
        status = item.get("status") or STATUS_OPEN
        if status in counts:
            counts[status] += 1
        if status == STATUS_OPEN and item.get("severity") in SEVERITIES:
            counts[item["severity"]] += 1  # severity counters track OPEN findings
    counts["assets"] = len(set(existing_assets) | set(fetched.assets))

    return {
        "findingsDiscovered": len(fetched.findings),
        "newFindings": new,
        "updatedFindings": updated,
        "resolvedFindings": resolved,
        "assetsDiscovered": len(fetched.assets),
        "apiCalls": fetched.apiCalls,
        "apiLatencyMs": fetched.apiLatencyMs,
        "writes": batched_writes,
        "counts": counts,
    }
