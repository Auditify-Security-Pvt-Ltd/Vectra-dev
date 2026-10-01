"""
Scan admission control.

The single place every scan type calls before creating a scan, so Web, Network
and SAST share one organization budget and one failure response instead of
re-implementing the rule three times.
"""
from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Request, status

from services import firebase, quota
from services.auth import Identity
from utils.logger import get_logger

logger = get_logger(__name__)

SCAN_LIMIT_CODE = "SCAN_LIMIT_REACHED"
IDEMPOTENCY_HEADER = "Idempotency-Key"


def effective_uid(identity: Identity, claimed_user_id: str | None) -> str:
    """
    The uid a scan is attributed to.

    A verified token always wins. The claimed id is only used while the backend
    has no service account configured, and is never trusted for authorization.
    """
    if identity.verified:
        return identity.uid
    return (claimed_user_id or identity.uid or "anonymous").strip() or "anonymous"


def request_id_from(request: Optional[Request]) -> Optional[str]:
    return request.headers.get(IDEMPOTENCY_HEADER) if request is not None else None


def enforce_scan_quota(
    identity: Identity,
    claimed_user_id: str | None,
    scan_type: str,
    scan_id: str,
    request_id: Optional[str] = None,
) -> quota.ScanClaim:
    """
    Claim one scan from the caller's organization and return the claim.

    Called immediately before scan creation. Callers must check
    `claim.duplicate`: a retried request returns the original scan id and must
    not create a second scan. If the scan cannot be created after a successful
    claim, call `quota.release_claim(claim)`.

    Fails closed — an unverified caller or a quota-backend error refuses the
    scan rather than letting it through uncounted.
    """
    if not firebase.is_configured():
        # Development without a service account: nothing can be verified or
        # counted. Unchanged from the previous behaviour.
        uid = effective_uid(identity, claimed_user_id)
        logger.warning(f"[QUOTA] Not enforced for {scan_type} scan (uid={uid}): Firebase Admin is not configured")
        rid, _ = quota.normalize_request_id(request_id)
        return quota.ScanClaim(uid, uid, scan_id, rid, False,
                               quota.snapshot_from_doc({}, quota.DEFAULT_PLAN_ALLOWANCES))

    if not identity.verified:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required to start a scan")

    try:
        return quota.claim_scan(identity.uid, scan_type, scan_id, request_id)
    except quota.QuotaExceeded as exc:
        logger.info(f"[QUOTA] {scan_type} scan refused for uid={identity.uid} — organization allowance exhausted")
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "code": SCAN_LIMIT_CODE,
                "message": "Your organization has reached its available scan limit.",
                "quota": exc.snapshot.to_dict(),
            },
        )
    except quota.ScanNotAllowed as exc:
        logger.info(f"[QUOTA] {scan_type} scan refused for uid={identity.uid} — {exc.code}")
        code = status.HTTP_409_CONFLICT if exc.code in {"ORGANIZATION_CHANGED", "REQUEST_ID_CONFLICT"} \
            else status.HTTP_403_FORBIDDEN
        raise HTTPException(status_code=code, detail={"code": exc.code, "message": exc.message})
    except Exception as exc:
        logger.error(f"[QUOTA] Quota check failed for uid={identity.uid}: {type(exc).__name__}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "QUOTA_UNAVAILABLE",
                    "message": "Scan allowance could not be verified. Please try again."},
        )


def claim_for_uid(uid: str, scan_type: str, scan_id: str) -> tuple[Optional[quota.ScanClaim], Optional[str]]:
    """
    Server-initiated scans (schedules). The uid was bound from a verified token
    when the schedule was created. Returns (claim, None) when the scan may run,
    or (None, reason) when it must be skipped.
    """
    if not firebase.is_configured():
        return quota.ScanClaim(uid, uid, scan_id, scan_id, False,
                               quota.snapshot_from_doc({}, quota.DEFAULT_PLAN_ALLOWANCES)), None
    try:
        return quota.claim_scan(uid, scan_type, scan_id, None), None
    except quota.QuotaExceeded:
        reason = "Your organization has reached its available scan limit."
    except quota.ScanNotAllowed as exc:
        reason = exc.message
    except Exception as exc:
        logger.error(f"[QUOTA] quota unavailable for scheduled scan uid={uid}: {exc}")
        reason = "Scan allowance could not be verified."
    logger.info(f"[QUOTA] Scheduled {scan_type} scan skipped for uid={uid} — {reason}")
    return None, reason
