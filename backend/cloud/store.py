"""
Firestore persistence for Cloud Security.

All documents live under the organization and are written only through the
Admin SDK (firestore.rules denies every client read and write), so the
backend's RBAC is the single entry point and credentials never sit in a
client-readable document.

    organizations/{orgId}/cloud_integrations/{integrationId}   metadata, status, counters
    organizations/{orgId}/cloud_secrets/{integrationId}        encrypted credentials only
    organizations/{orgId}/cloud_findings/{fingerprint}         normalized findings
    organizations/{orgId}/cloud_assets/{assetId}               resources referenced by findings
    organizations/{orgId}/cloud_syncs/{syncId}                 sync jobs and statistics
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from cloud import secrets
from cloud.access import OrgContext
from cloud.providers.base import ProviderSession  # noqa: F401  (re-exported for api.cloud)
from services import firebase
from utils.logger import get_logger

logger = get_logger(__name__)

INTEGRATIONS = "cloud_integrations"
SECRETS = "cloud_secrets"
FINDINGS = "cloud_findings"
ASSETS = "cloud_assets"
SYNCS = "cloud_syncs"

BATCH_SIZE = 400  # Firestore batches allow 500 writes


def field_eq(field: str, value: Any):
    from google.cloud.firestore_v1.base_query import FieldFilter
    return FieldFilter(field, "==", value)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


def org_ref(org_id: str):
    return firebase.db().collection("organizations").document(org_id)


def col(org_id: str, name: str):
    return org_ref(org_id).collection(name)


def batched_writes(ops: Iterable[tuple[str, Any, dict]]) -> int:
    """ops: (kind, docref, data) with kind in {'set', 'merge'}. Returns writes committed."""
    db = firebase.db()
    batch, pending, total = db.batch(), 0, 0
    for kind, ref, data in ops:
        if kind == "merge":
            batch.set(ref, data, merge=True)
        else:
            batch.set(ref, data)
        pending += 1
        if pending >= BATCH_SIZE:
            batch.commit()
            total += pending
            batch, pending = db.batch(), 0
    if pending:
        batch.commit()
        total += pending
    return total


# ── Integrations ──────────────────────────────────────────────────────

EMPTY_COUNTS = {
    "findings": 0, "open": 0, "resolved": 0, "suppressed": 0,
    "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "assets": 0,
}

# Fields a client may see. Anything else (including future fields) is not
# returned unless added here deliberately.
PUBLIC_INTEGRATION_FIELDS = (
    "integrationId", "provider", "displayName", "authMethod", "config", "accountId", "accountLabel",
    "status", "validation", "syncStatus", "currentSyncId", "lastSyncAt", "lastSyncStatus",
    "lastSyncError", "lastSuccessfulSyncAt", "lastSyncStats", "counts", "createdBy", "createdAt",
    "updatedAt", "disconnectedAt", "capabilities",
)


def public_integration(doc: dict) -> dict:
    return {k: doc.get(k) for k in PUBLIC_INTEGRATION_FIELDS}


def create_integration(
    ctx: OrgContext, provider: str, display_name: str, auth_method: str,
    config: dict, credentials: Optional[dict], validation: dict, integration_id: str,
) -> dict:
    ts = now_iso()
    doc = {
        "integrationId": integration_id,
        "organizationId": ctx.org_id,
        "provider": provider,
        "displayName": display_name,
        "authMethod": auth_method,
        "config": config,
        "accountId": validation.get("accountId"),
        "accountLabel": validation.get("accountLabel"),
        "status": "connected" if validation.get("ok") else "error",
        "validation": {**validation, "validatedAt": ts},
        "capabilities": validation.get("capabilities") or None,
        "syncStatus": "idle",
        "currentSyncId": None,
        "lastSyncAt": None,
        "lastSyncStatus": None,
        "lastSyncError": None,
        "lastSuccessfulSyncAt": None,
        "lastSyncStats": None,
        "counts": dict(EMPTY_COUNTS),
        "createdBy": ctx.uid,
        "createdAt": ts,
        "updatedAt": ts,
        "disconnectedAt": None,
    }
    batch = firebase.db().batch()
    batch.set(col(ctx.org_id, INTEGRATIONS).document(integration_id), doc)
    if credentials:
        batch.set(col(ctx.org_id, SECRETS).document(integration_id), {
            "integrationId": integration_id,
            "envelope": secrets.seal(ctx.org_id, integration_id, credentials),
            "updatedAt": ts,
        })
    batch.commit()
    return doc


def get_integration(org_id: str, integration_id: str) -> Optional[dict]:
    snap = col(org_id, INTEGRATIONS).document(integration_id).get()
    return (snap.to_dict() or {}) if snap.exists else None


def list_integrations(org_id: str, include_disconnected: bool = False) -> list[dict]:
    docs = [d.to_dict() or {} for d in col(org_id, INTEGRATIONS).stream()]
    if not include_disconnected:
        docs = [d for d in docs if d.get("status") != "disconnected"]
    return sorted(docs, key=lambda d: d.get("createdAt") or "")


def update_integration(org_id: str, integration_id: str, changes: dict) -> None:
    col(org_id, INTEGRATIONS).document(integration_id).set({**changes, "updatedAt": now_iso()}, merge=True)


def load_session(org_id: str, integration: dict) -> ProviderSession:
    credentials = None
    snap = col(org_id, SECRETS).document(integration["integrationId"]).get()
    if snap.exists:
        envelope = (snap.to_dict() or {}).get("envelope")
        if envelope:
            credentials = secrets.open_sealed(org_id, integration["integrationId"], envelope)
    return ProviderSession(
        org_id=org_id,
        integration_id=integration["integrationId"],
        auth_method=integration["authMethod"],
        config=integration.get("config") or {},
        credentials=credentials,
    )


def disconnect_integration(org_id: str, integration_id: str, delete_findings: bool) -> dict:
    """Destroy credentials. Findings and assets are kept for history unless asked otherwise."""
    col(org_id, SECRETS).document(integration_id).delete()
    removed = {"findings": 0, "assets": 0}
    if delete_findings:
        for name, key in ((FINDINGS, "findings"), (ASSETS, "assets")):
            refs = [d.reference for d in col(org_id, name).where(filter=field_eq("integrationId", integration_id)).select([]).stream()]
            db = firebase.db()
            for i in range(0, len(refs), BATCH_SIZE):
                batch = db.batch()
                for ref in refs[i:i + BATCH_SIZE]:
                    batch.delete(ref)
                batch.commit()
            removed[key] = len(refs)
    changes: dict[str, Any] = {
        "status": "disconnected", "syncStatus": "idle", "currentSyncId": None, "disconnectedAt": now_iso(),
    }
    if delete_findings:
        changes["counts"] = dict(EMPTY_COUNTS)
    update_integration(org_id, integration_id, changes)
    return removed


# ── Audit ─────────────────────────────────────────────────────────────

def audit(ctx: OrgContext | None, org_id: str, action: str, integration: dict | None,
          result: str, details: str = "") -> None:
    """
    Organization audit log entry (organizations/{orgId}/auditLogs), the same
    trail Team Management shows. Best-effort; never contains credentials.
    """
    try:
        from firebase_admin import firestore as fb_firestore
        log_id = new_id("log")
        col(org_id, "auditLogs").document(log_id).set({
            "logId": log_id,
            "category": "cloud",
            "actorId": ctx.uid if ctx else "system",
            "actorName": (ctx.email if ctx else None) or ("Vectra" if not ctx else ctx.uid),
            "action": action,
            "targetId": (integration or {}).get("integrationId"),
            "provider": (integration or {}).get("provider"),
            "integrationId": (integration or {}).get("integrationId"),
            "organizationId": org_id,
            "result": result,
            "details": details[:500],
            "timestamp": fb_firestore.SERVER_TIMESTAMP,
        })
    except Exception as exc:
        logger.warning(f"[CLOUD] audit write failed action={action}: {type(exc).__name__}")
