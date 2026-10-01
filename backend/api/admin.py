"""
Platform administration API.

Every route here depends on `require_platform_admin`, which needs a verified
Firebase ID token *and* a platform role stored server-side. Organization admins
(orgRole 'admin') are deliberately not sufficient — that role scopes a user
inside their own organization only.

Task data is read from the live in-memory scan registries the schedulers
already maintain, so this adds visibility without introducing a second source
of truth for scan state.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from services import firebase, organization, quota
from services.auth import Identity, require_platform_admin
from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin"])

_AUDIT_COLLECTION = "platform_audit_logs"


# ── Helpers ───────────────────────────────────────────────────────────

def _iso(value: Any) -> Optional[str]:
    """Normalise Firestore timestamps / strings to ISO-8601."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    for attr in ("isoformat",):
        if hasattr(value, attr):
            try:
                return value.isoformat()
            except Exception:
                return None
    return None


def _audit(actor: Identity, action: str, target_uid: str, before: Any = None, after: Any = None) -> None:
    """
    Record an administrative action. Best-effort: an audit write must never
    block the operation the admin actually requested.
    """
    try:
        firebase.db().collection(_AUDIT_COLLECTION).add({
            "action":     action,
            "actorUid":   actor.uid,
            "actorEmail": actor.email,
            "targetUid":  target_uid,
            "before":     before,
            "after":      after,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:
        logger.warning(f"[ADMIN] Audit write failed for {action}: {exc}")


def _live_scans() -> list[dict]:
    """
    Snapshot every scan the backend currently knows about, across scan types.
    Imported lazily so this module does not create import cycles at startup.
    """
    tasks: list[dict] = []

    def add(registry: dict, scan_type: str, target_key: str) -> None:
        for scan_id, scan in list(registry.items()):
            if not isinstance(scan, dict):
                continue
            tasks.append({
                "scanId":      scan_id,
                "scanType":    scan_type,
                "userId":      scan.get("userId") or scan.get("user_id") or "unknown",
                "target":      scan.get(target_key) or scan.get("target"),
                "status":      scan.get("status"),
                "progress":    scan.get("progress"),
                "currentStep": scan.get("currentStep"),
                "createdAt":   _iso(scan.get("createdAt") or scan.get("created_at")),
                "completedAt": _iso(scan.get("completedAt") or scan.get("completed_at")),
                "error":       scan.get("error"),
                "findings":    scan.get("total_findings") or scan.get("totalFindings") or 0,
                "cves":        scan.get("total_cves") or scan.get("totalCves") or 0,
            })

    try:
        from api.scans import _SCANS as WEB_SCANS
        add(WEB_SCANS, "web", "target")
    except Exception as exc:
        logger.debug(f"[ADMIN] web scan registry unavailable: {exc}")

    try:
        from api.network_scans import _SCANS as NET_SCANS
        add(NET_SCANS, "network", "target")
    except Exception as exc:
        logger.debug(f"[ADMIN] network scan registry unavailable: {exc}")

    try:
        from api.sast_scans import _SAST_SCANS as SAST_SCANS
        add(SAST_SCANS, "sast", "projectName")
    except Exception as exc:
        logger.debug(f"[ADMIN] sast scan registry unavailable: {exc}")

    return tasks


_ACTIVE_STATUSES = {
    "queued", "initializing", "running", "processing", "saving",
    "discovering_assets", "validating_assets", "scanning_assets",
    "detecting_technologies", "cve_analysis", "host_discovery",
    "port_scan", "service_detection",
}
_FAILED_STATUSES = {"failed", "error"}


# ── Request models ────────────────────────────────────────────────────

class UpdateUserBody(BaseModel):
    status:      Optional[str] = None
    # Legacy per-user quota fields. Quota now belongs to the organization, so
    # these are refused rather than silently ignored.
    plan:        Optional[str] = None
    bonusScans:  Optional[int] = None
    scansUsed:   Optional[int] = None


class UpdateOrganizationBody(BaseModel):
    name:       Optional[str] = None
    website:    Optional[str] = None
    phone:      Optional[str] = None
    status:     Optional[str] = None
    plan:       Optional[str] = None
    bonusScans: Optional[int] = Field(default=None, ge=0)


class PlanAllowanceBody(BaseModel):
    plan:      str
    allowance: int = Field(ge=-1, description="-1 means unlimited")


# ── Overview ──────────────────────────────────────────────────────────

@router.get("/overview")
async def overview(admin: Identity = Depends(require_platform_admin)) -> dict:
    """Platform-wide counts, computed from real user/organization records and live scans."""
    db = firebase.db()

    total_users = active_users = inactive_users = 0
    for doc in db.collection("users").stream():
        data = doc.to_dict() or {}
        total_users += 1
        if (data.get("status") or "active") == "active":
            active_users += 1
        else:
            inactive_users += 1

    allowances = quota.get_plan_allowances()
    total_orgs = free_orgs = near_limit = disabled_orgs = 0
    for doc in db.collection("organizations").stream():
        data = doc.to_dict() or {}
        total_orgs += 1
        snapshot = quota.snapshot_from_doc(data, allowances)
        if snapshot.plan == quota.DEFAULT_PLAN:
            free_orgs += 1
        if not snapshot.unlimited and snapshot.remaining <= 1:
            near_limit += 1
        if quota.org_status(data) != "active":
            disabled_orgs += 1

    tasks = _live_scans()
    by_status: dict[str, int] = {}
    for t in tasks:
        key = (t.get("status") or "unknown").lower()
        by_status[key] = by_status.get(key, 0) + 1

    running = sum(n for s, n in by_status.items() if s in _ACTIVE_STATUSES and s != "queued")
    queued  = by_status.get("queued", 0)
    failed  = sum(n for s, n in by_status.items() if s in _FAILED_STATUSES)

    return {
        "users": {
            "total":    total_users,
            "active":   active_users,
            "inactive": inactive_users,
        },
        "organizations": {
            "total":     total_orgs,
            "free":      free_orgs,
            "nearLimit": near_limit,
            "disabled":  disabled_orgs,
        },
        "scans": {
            "totalTracked": len(tasks),
            "running":      running,
            "queued":       queued,
            "completed":    by_status.get("completed", 0),
            "failed":       failed,
            "cancelled":    by_status.get("cancelled", 0),
        },
        "quota": {
            "planAllowances": allowances,
            "consumptionRule": quota.SCAN_CONSUMPTION_RULE,
        },
    }


# ── Users ─────────────────────────────────────────────────────────────

def _org_context() -> tuple[dict[str, dict], dict[tuple[str, str], dict]]:
    """All organizations, and memberships keyed by (orgId, uid)."""
    db = firebase.db()
    orgs = {d.id: (d.to_dict() or {}) for d in db.collection("organizations").stream()}
    members: dict[tuple[str, str], dict] = {}
    for d in db.collection_group("members").stream():
        parent = d.reference.parent.parent
        if parent is not None and parent.parent.id == "organizations":
            members[(parent.id, d.id)] = d.to_dict() or {}
    return orgs, members


def _user_row(uid: str, data: dict, orgs: dict, members: dict, allowances: dict) -> dict:
    org_id = data.get("organizationId")
    org = orgs.get(org_id) if org_id else None
    member = members.get((org_id, uid)) if org_id else None
    return {
        "uid":              uid,
        "name":             data.get("name"),
        "email":            data.get("email"),
        "role":             data.get("role"),
        "status":           data.get("status") or "active",
        "organizationId":   org_id if org else None,
        "organizationName": (org or {}).get("name"),
        "orgRole":          (member or {}).get("orgRole"),
        "orgPlan":          quota.snapshot_from_doc(org, allowances).plan if org else None,
        "createdAt":        _iso(data.get("createdAt")),
        "lastLogin":        _iso(data.get("lastLogin")),
    }


@router.get("/users")
async def list_users(
    admin:  Identity = Depends(require_platform_admin),
    search: str = Query("", description="Match against name, email, uid or organization"),
    limit:  int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    """
    Individual accounts with their organization context. Scan quota is not a
    user property any more — it lives on the organization.
    """
    db = firebase.db()
    allowances = quota.get_plan_allowances()
    orgs, members = _org_context()
    needle = search.strip().lower()

    rows: list[dict] = []
    for doc in db.collection("users").stream():
        row = _user_row(doc.id, doc.to_dict() or {}, orgs, members, allowances)
        if needle:
            haystack = " ".join(str(row.get(k) or "") for k in
                                ("name", "email", "uid", "organizationName")).lower()
            if needle not in haystack:
                continue
        rows.append(row)

    rows.sort(key=lambda r: (r.get("email") or "").lower())
    total = len(rows)
    return {"total": total, "limit": limit, "offset": offset, "users": rows[offset:offset + limit]}


@router.get("/users/{uid}")
async def get_user(uid: str, admin: Identity = Depends(require_platform_admin)) -> dict:
    snap = firebase.db().collection("users").document(uid).get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="User not found")

    orgs, members = _org_context()
    row = _user_row(uid, snap.to_dict() or {}, orgs, members, quota.get_plan_allowances())
    row["tasks"] = [t for t in _live_scans() if t.get("userId") == uid]
    return row


@router.patch("/users/{uid}")
async def update_user(
    uid: str,
    body: UpdateUserBody,
    admin: Identity = Depends(require_platform_admin),
) -> dict:
    """Account status changes. Plan and scan quota are managed per organization."""
    if body.plan is not None or body.bonusScans is not None or body.scansUsed is not None:
        raise HTTPException(
            status_code=400,
            detail="Plan and scan quota are managed per organization: PATCH /admin/organizations/{orgId}",
        )

    ref = firebase.db().collection("users").document(uid)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="User not found")

    before = {"status": (snap.to_dict() or {}).get("status") or "active"}
    if body.status is not None:
        if body.status not in {"active", "disabled", "suspended"}:
            raise HTTPException(status_code=400, detail="status must be active, disabled or suspended")
        # Soft state change only — scans, findings and reports are untouched.
        ref.set({"status": body.status}, merge=True)

    after = {"status": body.status or before["status"]}
    _audit(admin, "user.update", uid, before, after)
    return {"uid": uid, "status": after["status"]}


# ── Organizations ─────────────────────────────────────────────────────

# Organization data lives under users/{orgId}/… (see firestore.rules).
_SCAN_COLLECTIONS    = ("scans", "network_scans", "sast_scans")
_FINDING_COLLECTIONS = ("findings", "network_findings", "sast_findings")
_ASSET_COLLECTIONS   = ("assets", "network_assets")
_SCAN_TYPE_BY_COLLECTION = {"scans": "web", "network_scans": "network", "sast_scans": "sast"}


def _count(query) -> Optional[int]:
    """Server-side count aggregation; None when it cannot be computed."""
    try:
        result = query.count().get()
        return int(result[0][0].value)
    except Exception as exc:
        logger.debug(f"[ADMIN] count failed: {exc}")
        return None


def _sum_counts(org_id: str, collections: tuple[str, ...], status_in: Optional[list[str]] = None) -> Optional[int]:
    total = 0
    base = firebase.db().collection("users").document(org_id)
    for name in collections:
        query = base.collection(name)
        if status_in:
            query = query.where("status", "in", status_in)
        n = _count(query)
        if n is None:
            return None
        total += n
    return total


def _org_summary(org_id: str, data: dict, allowances: dict) -> dict:
    snapshot = quota.snapshot_from_doc(data, allowances)
    return {
        "orgId":      org_id,
        "name":       data.get("name"),
        "website":    data.get("website"),
        "phone":      data.get("phone"),
        "status":     quota.org_status(data),
        "ownerId":    data.get("ownerId"),
        "ownerName":  data.get("ownerName"),
        "ownerEmail": data.get("ownerEmail"),
        "createdAt":  _iso(data.get("createdAt")),
        "updatedAt":  _iso(data.get("updatedAt")),
        "quota":      snapshot.to_dict(),
    }


def _org_counts(org_id: str) -> dict:
    members_ref = firebase.db().collection("organizations").document(org_id).collection("members")
    return {
        "users":    _count(members_ref),
        "assets":   _sum_counts(org_id, _ASSET_COLLECTIONS),
        "scans":    _sum_counts(org_id, _SCAN_COLLECTIONS),
        "findings": _sum_counts(org_id, _FINDING_COLLECTIONS),
    }


def _get_org_or_404(org_id: str) -> dict:
    snap = firebase.db().collection("organizations").document(org_id).get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Organization not found")
    return snap.to_dict() or {}


@router.get("/organizations")
async def list_organizations(
    admin:  Identity = Depends(require_platform_admin),
    search: str = Query("", description="Match against name, website, owner or id"),
    plan:   str = Query("all"),
    status_f: str = Query("all", alias="status"),
    limit:  int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> dict:
    """Organizations with plan, shared quota and real usage counts."""
    allowances = quota.get_plan_allowances()
    needle = search.strip().lower()

    rows: list[dict] = []
    for doc in firebase.db().collection("organizations").stream():
        row = _org_summary(doc.id, doc.to_dict() or {}, allowances)
        if plan != "all" and row["quota"]["plan"] != plan:
            continue
        if status_f != "all" and row["status"] != status_f:
            continue
        if needle:
            haystack = " ".join(str(row.get(k) or "") for k in
                                ("name", "website", "ownerName", "ownerEmail", "orgId")).lower()
            if needle not in haystack:
                continue
        rows.append(row)

    rows.sort(key=lambda r: (r.get("name") or "").lower())
    page = rows[offset:offset + limit]

    # Counts are aggregation queries; run them only for the visible page, in parallel.
    counts = await asyncio.gather(*(asyncio.to_thread(_org_counts, r["orgId"]) for r in page))
    for row, c in zip(page, counts):
        row["counts"] = c

    return {
        "total": len(rows), "limit": limit, "offset": offset,
        "plans": sorted(allowances), "organizations": page,
    }


def _recent_scans(org_id: str, per_type: int = 10) -> list[dict]:
    base = firebase.db().collection("users").document(org_id)
    scans: list[dict] = []
    for name in _SCAN_COLLECTIONS:
        try:
            docs = base.collection(name).order_by("createdAt", direction="DESCENDING").limit(per_type).stream()
            for d in docs:
                data = d.to_dict() or {}
                scans.append({
                    "scanId":      data.get("scanId") or d.id,
                    "scanType":    _SCAN_TYPE_BY_COLLECTION[name],
                    "target":      data.get("target") or data.get("projectName"),
                    "status":      data.get("status"),
                    "userId":      data.get("userId"),
                    "createdAt":   _iso(data.get("createdAt")),
                    "completedAt": _iso(data.get("completedAt")),
                    "findings":    data.get("totalFindings") or 0,
                })
        except Exception as exc:
            logger.debug(f"[ADMIN] recent {name} for {org_id} unavailable: {exc}")
    scans.sort(key=lambda x: x.get("createdAt") or "", reverse=True)
    return scans[: per_type * 2]


@router.get("/organizations/{org_id}")
async def get_organization(org_id: str, admin: Identity = Depends(require_platform_admin)) -> dict:
    """Profile, plan/quota, members, and scan activity for one organization."""
    db = firebase.db()
    data = _get_org_or_404(org_id)
    result = _org_summary(org_id, data, quota.get_plan_allowances())
    result["counts"] = await asyncio.to_thread(_org_counts, org_id)

    members: list[dict] = []
    for d in db.collection("organizations").document(org_id).collection("members").stream():
        m = d.to_dict() or {}
        user_snap = db.collection("users").document(d.id).get()
        user = (user_snap.to_dict() or {}) if user_snap.exists else {}
        members.append({
            "uid":           d.id,
            "name":          m.get("name") or user.get("name"),
            "email":         m.get("email") or user.get("email"),
            "orgRole":       m.get("orgRole"),
            "memberStatus":  m.get("status") or "active",
            "platformRole":  user.get("role"),
            "accountStatus": user.get("status") or "active",
            "joinedAt":      _iso(m.get("joinedAt")),
        })
    members.sort(key=lambda m: (m["orgRole"] != "admin", (m.get("email") or "").lower()))
    result["members"] = members

    member_ids = {m["uid"] for m in members} | {org_id}
    live = [t for t in _live_scans() if t.get("userId") in member_ids]
    result["activity"] = {
        "running":   len([t for t in live if (t.get("status") or "").lower() in _ACTIVE_STATUSES]),
        "completed": await asyncio.to_thread(_sum_counts, org_id, _SCAN_COLLECTIONS, ["completed", "completed_timeout"]),
        "failed":    await asyncio.to_thread(_sum_counts, org_id, _SCAN_COLLECTIONS, ["failed", "error"]),
        "live":      sorted(live, key=lambda t: t.get("createdAt") or "", reverse=True)[:20],
        "recent":    await asyncio.to_thread(_recent_scans, org_id),
    }
    return result


@router.patch("/organizations/{org_id}")
async def update_organization(
    org_id: str,
    body: UpdateOrganizationBody,
    admin: Identity = Depends(require_platform_admin),
) -> dict:
    """
    Edit profile, status, plan and bonus scans. The id, owner and recorded usage
    (scansUsed) are not editable here, so changing an allowance never resets
    what the organization has already consumed.
    """
    ref = firebase.db().collection("organizations").document(org_id)
    data = _get_org_or_404(org_id)
    allowances = quota.get_plan_allowances()
    before = _org_summary(org_id, data, allowances)

    profile: dict[str, Any] = {}
    try:
        if body.name is not None:
            profile["name"] = organization.clean_name(body.name)
        if body.website is not None:
            profile["website"] = organization.clean_website(body.website)
        if body.phone is not None:
            profile["phone"] = organization.clean_phone(body.phone)
        if body.status is not None:
            if body.status not in quota.ORG_STATUSES:
                raise ValueError(f"status must be one of: {', '.join(sorted(quota.ORG_STATUSES))}")
            profile["status"] = body.status
        if body.plan is not None or body.bonusScans is not None:
            quota.update_org_plan_and_bonus(org_id, body.plan, body.bonusScans)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if profile:
        profile["updatedAt"] = datetime.now(timezone.utc).isoformat()
        ref.update(profile)

    after = _org_summary(org_id, _get_org_or_404(org_id), allowances)
    _audit(admin, "organization.update", org_id,
           {k: before.get(k) for k in ("name", "website", "phone", "status")} | before["quota"],
           {k: after.get(k) for k in ("name", "website", "phone", "status")} | after["quota"])
    return after


# ── Plans & quotas ────────────────────────────────────────────────────

@router.get("/quota/config")
async def get_quota_config(admin: Identity = Depends(require_platform_admin)) -> dict:
    return {
        "planAllowances":  quota.get_plan_allowances(),
        "defaultPlan":     quota.DEFAULT_PLAN,
        "consumptionRule": quota.SCAN_CONSUMPTION_RULE,
    }


@router.put("/quota/config")
async def set_quota_config(
    body: PlanAllowanceBody,
    admin: Identity = Depends(require_platform_admin),
) -> dict:
    """
    Change a plan's default allowance. Existing usage is deliberately left
    alone, so raising the free default grants headroom to everyone rather than
    resetting anyone's history.
    """
    before = quota.get_plan_allowances()
    try:
        after = quota.set_plan_allowance(body.plan, body.allowance)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _audit(admin, "quota.config", body.plan, before, after)
    return {"planAllowances": after}


# ── Cloud Security ────────────────────────────────────────────────────

@router.get("/cloud/integrations")
async def list_cloud_integrations(admin: Identity = Depends(require_platform_admin)) -> dict:
    """
    Cloud integration health across organizations. Returns only the public
    integration fields — credentials live in a separate encrypted document that
    is never read here.
    """
    from cloud import store as cloud_store

    def _load() -> list[dict]:
        db = firebase.db()
        orgs = {d.id: (d.to_dict() or {}).get("name") for d in db.collection("organizations").stream()}
        rows = []
        for d in db.collection_group(cloud_store.INTEGRATIONS).stream():
            parent = d.reference.parent.parent
            if parent is None or parent.parent.id != "organizations":
                continue
            data = cloud_store.public_integration(d.to_dict() or {})
            rows.append({**data, "organizationId": parent.id, "organizationName": orgs.get(parent.id)})
        rows.sort(key=lambda r: (r.get("organizationName") or "", r.get("createdAt") or ""))
        return rows

    rows = await asyncio.to_thread(_load)
    return {
        "total": len(rows),
        "integrations": rows,
        "health": {
            "connected": sum(1 for r in rows if r.get("status") == "connected"),
            "error": sum(1 for r in rows if r.get("status") == "error"),
            "disconnected": sum(1 for r in rows if r.get("status") == "disconnected"),
            "failedLastSync": sum(1 for r in rows if r.get("lastSyncStatus") == "failed"),
        },
    }


# ── Tasks ─────────────────────────────────────────────────────────────

@router.get("/tasks")
async def list_tasks(
    admin:    Identity = Depends(require_platform_admin),
    status_f: str = Query("all", alias="status"),
    scanType: str = Query("all"),
    userId:   str = Query(""),
    search:   str = Query(""),
    limit:    int = Query(100, ge=1, le=500),
) -> dict:
    """Live and recent scans across every scan type, with server-side filters."""
    tasks = _live_scans()

    if scanType != "all":
        tasks = [t for t in tasks if t.get("scanType") == scanType]
    if userId:
        tasks = [t for t in tasks if t.get("userId") == userId]

    if status_f != "all":
        if status_f == "running":
            tasks = [t for t in tasks if (t.get("status") or "").lower() in _ACTIVE_STATUSES
                     and (t.get("status") or "").lower() != "queued"]
        elif status_f == "failed":
            tasks = [t for t in tasks if (t.get("status") or "").lower() in _FAILED_STATUSES]
        else:
            tasks = [t for t in tasks if (t.get("status") or "").lower() == status_f]

    needle = search.strip().lower()
    if needle:
        tasks = [
            t for t in tasks
            if needle in " ".join([
                str(t.get("target") or ""), str(t.get("scanId") or ""), str(t.get("userId") or ""),
            ]).lower()
        ]

    tasks.sort(key=lambda t: t.get("createdAt") or "", reverse=True)
    return {"total": len(tasks), "tasks": tasks[:limit]}


@router.get("/tasks/{scan_id}")
async def get_task(scan_id: str, admin: Identity = Depends(require_platform_admin)) -> dict:
    for task in _live_scans():
        if task.get("scanId") == scan_id:
            return task
    raise HTTPException(status_code=404, detail="Task not found")


# ── Audit log ─────────────────────────────────────────────────────────

@router.get("/audit-logs")
async def audit_logs(
    admin: Identity = Depends(require_platform_admin),
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    db = firebase.db()
    entries: list[dict] = []
    try:
        query = db.collection(_AUDIT_COLLECTION).order_by(
            "timestamp", direction="DESCENDING",
        ).limit(limit)
        for doc in query.stream():
            entries.append({"id": doc.id, **(doc.to_dict() or {})})
    except Exception as exc:
        logger.warning(f"[ADMIN] Could not read audit logs: {exc}")
    return {"total": len(entries), "logs": entries}
