"""
Centralized organization scan quota.

The ORGANIZATION owns the plan and the scan budget. Every member draws from
the same pool, and every scan type (web, network, SAST — and any future module)
claims through `claim_scan()`, so there is exactly one allowance per
organization rather than per user or per scanner.

Model — stored on organizations/{orgId}
---------------------------------------
    plan          plan name; missing → DEFAULT_PLAN
    bonusScans    extra scans granted to the organization by a platform admin
    scansUsed     scans consumed by all members combined
    status        'active' | 'disabled'; disabled organizations cannot scan

    effective allowance = plan default + bonusScans
    remaining           = effective allowance - scansUsed

`plan default` is configurable per plan in platform_config/quota. Remaining is
always derived, never stored, so it cannot drift. Paid plans use an allowance
of -1, meaning unlimited.

The legacy per-user fields (users/{uid}.plan / bonusScans / scansUsed) are no
longer read for enforcement. scripts/migrate_org_quota.py folds them into the
organization once.

Counting rule
-------------
A slot is consumed exactly once, when the backend accepts a scan. Opening a
modal costs nothing; a request that fails before its scan exists is refunded
via `release_claim()`; cancelling a started scan does not refund the slot.

Organization resolution is always server-side:
    verified uid → users/{uid}.organizationId → active membership → organization
Nothing the client sends (orgId, plan, counts) is ever trusted.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

from services import firebase
from utils.logger import get_logger

logger = get_logger(__name__)

SCAN_CONSUMPTION_RULE = (
    "A scan is consumed from your organization's shared allowance when the backend "
    "accepts and creates it. Failed submissions do not consume a scan; cancelling "
    "a started scan does not restore it."
)

UNLIMITED = -1

# Fallback when platform_config/quota has not been written yet.
DEFAULT_PLAN_ALLOWANCES: dict[str, int] = {
    "free": 3,
    "pro": UNLIMITED,
    "enterprise": UNLIMITED,
}
DEFAULT_PLAN = "free"

ORG_STATUSES = {"active", "disabled"}

_CONFIG_COLLECTION = "platform_config"
_CONFIG_DOC = "quota"
_CLAIMS = "scanClaims"

# Client-supplied idempotency keys are scoped to one organization and must look
# like an opaque id; anything else is ignored and a fresh id is generated.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,100}$")


# ── Errors ────────────────────────────────────────────────────────────

class QuotaExceeded(Exception):
    """The organization has no scan allowance left."""

    def __init__(self, snapshot: "QuotaSnapshot"):
        self.snapshot = snapshot
        super().__init__("SCAN_LIMIT_REACHED")


class ScanNotAllowed(Exception):
    """The caller cannot scan for a reason other than quota (no org, disabled…)."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(code)


# ── Snapshot ──────────────────────────────────────────────────────────

@dataclass
class QuotaSnapshot:
    plan: str
    planAllowance: int      # from plan config; -1 = unlimited
    bonusScans: int         # organization-level grant
    effectiveAllowance: int # planAllowance + bonusScans; -1 = unlimited
    used: int
    remaining: int          # -1 = unlimited
    unlimited: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _non_negative_int(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def snapshot_from_doc(data: dict, allowances: dict[str, int]) -> QuotaSnapshot:
    """Quota for an organization document. Missing fields mean plan defaults."""
    plan = data.get("plan") or DEFAULT_PLAN
    plan_allowance = allowances.get(plan, allowances.get(DEFAULT_PLAN, 0))
    bonus = _non_negative_int(data.get("bonusScans"))
    used = _non_negative_int(data.get("scansUsed"))

    unlimited = plan_allowance == UNLIMITED
    effective = UNLIMITED if unlimited else plan_allowance + bonus
    remaining = UNLIMITED if unlimited else max(effective - used, 0)

    return QuotaSnapshot(
        plan=plan,
        planAllowance=plan_allowance,
        bonusScans=bonus,
        effectiveAllowance=effective,
        used=used,
        remaining=remaining,
        unlimited=unlimited,
    )


def org_status(data: dict) -> str:
    return data.get("status") if data.get("status") in ORG_STATUSES else "active"


# ── Plan config ───────────────────────────────────────────────────────

def get_plan_allowances() -> dict[str, int]:
    """Configured per-plan defaults, falling back to the built-ins."""
    allowances = dict(DEFAULT_PLAN_ALLOWANCES)
    if not firebase.is_configured():
        return allowances
    try:
        snap = firebase.db().collection(_CONFIG_COLLECTION).document(_CONFIG_DOC).get()
        if snap.exists:
            stored = (snap.to_dict() or {}).get("planAllowances") or {}
            for plan, value in stored.items():
                if isinstance(value, int) and (value >= 0 or value == UNLIMITED):
                    allowances[plan] = value
    except Exception as exc:
        logger.warning(f"[QUOTA] Could not read quota config, using defaults: {exc}")
    return allowances


def set_plan_allowance(plan: str, allowance: int) -> dict[str, int]:
    """
    Update one plan's default allowance. No organization's recorded usage is
    touched, so raising the default grants headroom rather than resetting history.
    """
    if allowance != UNLIMITED and allowance < 0:
        raise ValueError("Allowance must be >= 0, or -1 for unlimited")

    allowances = get_plan_allowances()
    allowances[plan] = allowance
    firebase.db().collection(_CONFIG_COLLECTION).document(_CONFIG_DOC).set(
        {"planAllowances": allowances}, merge=True,
    )
    logger.info(f"[QUOTA] Plan '{plan}' default allowance set to {allowance}")
    return allowances


# ── Organization resolution ───────────────────────────────────────────

def _refs(uid: str, org_id: Optional[str] = None):
    db = firebase.db()
    user_ref = db.collection("users").document(uid)
    if org_id is None:
        return user_ref
    org_ref = db.collection("organizations").document(org_id)
    return user_ref, org_ref, org_ref.collection("members").document(uid)


def _check_membership(uid: str, user: dict, org_id: Optional[str], member: dict | None, org: dict | None) -> None:
    """Raise ScanNotAllowed unless uid is an active member of an active org."""
    if (user.get("status") or "active") != "active":
        raise ScanNotAllowed("ACCOUNT_DISABLED", "Your account is disabled.")
    if not org_id or org is None:
        raise ScanNotAllowed("NO_ORGANIZATION", "Your account is not part of an organization.")
    if member is None or (member.get("status") or "active") != "active":
        raise ScanNotAllowed("NOT_ORG_MEMBER", "You are not an active member of this organization.")
    if org_status(org) != "active":
        raise ScanNotAllowed("ORGANIZATION_DISABLED", "Your organization is disabled.")


def resolve_org_id(uid: str) -> Optional[str]:
    """The organization a user belongs to, from their server-side user record."""
    snap = _refs(uid).get()
    data = (snap.to_dict() or {}) if snap.exists else {}
    org_id = data.get("organizationId")
    return org_id if isinstance(org_id, str) and org_id else None


def get_org_quota(org_id: str) -> tuple[dict, QuotaSnapshot]:
    """(organization document, quota snapshot). Raises KeyError when missing."""
    snap = firebase.db().collection("organizations").document(org_id).get()
    if not snap.exists:
        raise KeyError(org_id)
    data = snap.to_dict() or {}
    return data, snapshot_from_doc(data, get_plan_allowances())


def get_quota_for_user(uid: str) -> dict:
    """Read-only view of the caller's organization quota for the app UI."""
    allowances = get_plan_allowances()
    if not firebase.is_configured():
        return {"organizationId": None, "organizationName": None, "status": "active",
                "quota": snapshot_from_doc({}, allowances).to_dict()}

    org_id = resolve_org_id(uid)
    org: dict = {}
    if org_id:
        snap = firebase.db().collection("organizations").document(org_id).get()
        org = (snap.to_dict() or {}) if snap.exists else {}
    return {
        "organizationId":   org_id if org else None,
        "organizationName": org.get("name"),
        "status":           org_status(org) if org else None,
        "quota":            snapshot_from_doc(org, allowances).to_dict(),
    }


# ── Claim / release ───────────────────────────────────────────────────

@dataclass
class ScanClaim:
    uid: str
    orgId: str
    scanId: str
    requestId: str
    duplicate: bool          # True when this request id was already claimed
    snapshot: QuotaSnapshot


def normalize_request_id(raw: Optional[str]) -> tuple[str, bool]:
    """(request id, client_supplied). Invalid or missing ids get a fresh one."""
    if raw and _REQUEST_ID_RE.match(raw):
        return raw, True
    return uuid.uuid4().hex, False


def claim_scan(
    uid: str,
    scan_type: str,
    scan_id: str,
    request_id: Optional[str] = None,
) -> ScanClaim:
    """
    Atomically claim one scan from the caller's organization, or raise.

    A single Firestore transaction re-reads the user, membership, organization
    and claim record, then increments organizations/{orgId}.scansUsed and writes
    organizations/{orgId}/scanClaims/{requestId}. Firestore retries the whole
    function if any read document changes before commit, so two concurrent
    requests can never both spend the final slot.

    A request id seen before returns the original claim without consuming
    anything, which makes client retries safe.
    """
    from firebase_admin import firestore as fb_firestore

    request_id, _ = normalize_request_id(request_id)
    allowances = get_plan_allowances()
    db = firebase.db()

    # Organization id comes from the server-side user record. It is re-checked
    # inside the transaction in case the user switches organization meanwhile.
    org_id = resolve_org_id(uid)
    if not org_id:
        raise ScanNotAllowed("NO_ORGANIZATION", "Your account is not part of an organization.")

    user_ref, org_ref, member_ref = _refs(uid, org_id)
    claim_ref = org_ref.collection(_CLAIMS).document(request_id)

    @fb_firestore.transactional
    def _claim(txn) -> ScanClaim:
        user_snap   = user_ref.get(transaction=txn)
        org_snap    = org_ref.get(transaction=txn)
        member_snap = member_ref.get(transaction=txn)
        claim_snap  = claim_ref.get(transaction=txn)

        user   = (user_snap.to_dict() or {}) if user_snap.exists else {}
        org    = (org_snap.to_dict() or {}) if org_snap.exists else None
        member = (member_snap.to_dict() or {}) if member_snap.exists else None

        if user.get("organizationId") != org_id:
            raise ScanNotAllowed("ORGANIZATION_CHANGED", "Your organization changed. Please retry.")
        _check_membership(uid, user, org_id, member, org)

        current = snapshot_from_doc(org, allowances)

        if claim_snap.exists:
            existing = claim_snap.to_dict() or {}
            if existing.get("uid") != uid:
                raise ScanNotAllowed("REQUEST_ID_CONFLICT", "Duplicate request id.")
            return ScanClaim(uid, org_id, existing.get("scanId") or scan_id,
                             request_id, True, current)

        if not current.unlimited and current.remaining <= 0:
            raise QuotaExceeded(current)

        now = datetime.now(timezone.utc).isoformat()
        txn.update(org_ref, {"scansUsed": current.used + 1, "updatedAt": now})
        txn.set(claim_ref, {
            "uid": uid, "scanId": scan_id, "scanType": scan_type, "createdAt": now,
        })
        updated = snapshot_from_doc({**org, "scansUsed": current.used + 1}, allowances)
        return ScanClaim(uid, org_id, scan_id, request_id, False, updated)

    result = _claim(db.transaction(max_attempts=10))
    if result.duplicate:
        logger.info(f"[QUOTA] Duplicate {scan_type} request {request_id} for org={org_id} — not charged")
    else:
        logger.info(
            f"[QUOTA] {scan_type} scan {scan_id} charged to org={org_id} by uid={uid} — "
            f"used={result.snapshot.used} "
            f"remaining={'unlimited' if result.snapshot.unlimited else result.snapshot.remaining}",
        )
    return result


def release_claim(claim: ScanClaim) -> None:
    """
    Refund a claim whose scan was never created (e.g. an invalid upload).
    Only the claim that consumed the slot can release it, and only once —
    the claim document is deleted in the same transaction as the decrement.
    """
    if claim.duplicate:
        return
    from firebase_admin import firestore as fb_firestore

    db = firebase.db()
    org_ref = db.collection("organizations").document(claim.orgId)
    claim_ref = org_ref.collection(_CLAIMS).document(claim.requestId)

    @fb_firestore.transactional
    def _release(txn) -> bool:
        claim_snap = claim_ref.get(transaction=txn)
        org_snap = org_ref.get(transaction=txn)
        if not claim_snap.exists or not org_snap.exists:
            return False
        used = _non_negative_int((org_snap.to_dict() or {}).get("scansUsed"))
        txn.update(org_ref, {"scansUsed": max(used - 1, 0),
                             "updatedAt": datetime.now(timezone.utc).isoformat()})
        txn.delete(claim_ref)
        return True

    try:
        if _release(db.transaction(max_attempts=10)):
            logger.info(f"[QUOTA] Refunded scan {claim.scanId} to org={claim.orgId} (not created)")
    except Exception as exc:
        logger.error(f"[QUOTA] Refund failed for org={claim.orgId} request={claim.requestId}: {exc}")


# ── Administrative mutations (platform admin only; see api/admin.py) ──

def update_org_plan_and_bonus(
    org_id: str,
    plan: Optional[str] = None,
    bonus: Optional[int] = None,
) -> QuotaSnapshot:
    """
    Change an organization's plan and/or bonus grant. scansUsed is never
    written here, so changing the allowance never resets consumption.
    """
    changes: dict = {}
    if plan is not None:
        allowances = get_plan_allowances()
        if plan not in allowances:
            raise ValueError(f"Unknown plan '{plan}'. Known plans: {', '.join(sorted(allowances))}")
        changes["plan"] = plan
    if bonus is not None:
        if not isinstance(bonus, int) or isinstance(bonus, bool) or bonus < 0:
            raise ValueError("bonusScans must be an integer >= 0")
        changes["bonusScans"] = bonus
    if changes:
        changes["updatedAt"] = datetime.now(timezone.utc).isoformat()
        firebase.db().collection("organizations").document(org_id).update(changes)
        logger.info(f"[QUOTA] org={org_id} updated: {changes}")
    return get_org_quota(org_id)[1]
