"""
Request authentication and authorization.

Two identities matter here and must not be confused:

  * organization role (admin/editor/viewer) — scopes a user inside their own
    organization. Already enforced in the frontend via lib/rbac.ts.
  * platform role (super_admin/platform_admin) — operates the whole Vectra
    platform. Only this may reach /admin endpoints.

`require_user` resolves the caller from a verified Firebase ID token, so the
uid can no longer be chosen by the client. `require_platform_admin` then checks
the platform role from Firestore — never from anything the client sent.

Transitional behaviour: when no service account is configured the SDK cannot
verify anything. Rather than breaking every existing endpoint, the resolvers
fall back to the legacy client-supplied userId and mark the identity
unverified. Admin endpoints always refuse an unverified identity, so an
unconfigured deployment simply has no admin access rather than an open one.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Query, Request, status

from services import firebase
from utils.logger import get_logger

logger = get_logger(__name__)

PLATFORM_ADMIN_ROLES = {"super_admin", "platform_admin"}

# Force-reject unverified identities everywhere, not just on /admin.
# Enable once every client sends an ID token.
AUTH_STRICT = os.getenv("AUTH_STRICT", "false").strip().lower() in {"1", "true", "yes"}


@dataclass
class Identity:
    uid: str
    email: Optional[str] = None
    #

    # False when the uid came from the client instead of a verified token.
    verified: bool = False

    def require_verified(self) -> None:
        if not self.verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )


def _bearer_token(request: Request) -> Optional[str]:
    header = request.headers.get("Authorization") or ""
    if header.lower().startswith("bearer "):
        token = header[7:].strip()
        return token or None
    return None


def resolve_identity(
    request: Request,
    userId: str = Query("", description="Legacy caller-supplied UID (ignored when a token is present)"),
) -> Identity:
    """
    Resolve the caller. A verified Bearer token always wins over any userId in
    the query string, so a client cannot act as another user by editing a URL.
    """
    token = _bearer_token(request)

    if token and firebase.is_configured():
        try:
            claims = firebase.verify_id_token(token)
            return Identity(uid=claims["uid"], email=claims.get("email"), verified=True)
        except Exception as exc:
            # Firebase's message names the failed check (e.g. "Token used too early …
            # check your clock") without echoing the token, which is what makes
            # host clock skew diagnosable.
            logger.warning(f"[AUTH] Rejected ID token: {type(exc).__name__}: {exc}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired authentication token",
            )

    if AUTH_STRICT:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    # Legacy path — identity is asserted by the client and cannot be trusted.
    return Identity(uid=userId or "anonymous", email=None, verified=False)


def require_user(identity: Identity = Depends(resolve_identity)) -> Identity:
    """Any caller. Use where an endpoint needs to know *who* is asking."""
    return identity


def require_verified_user(identity: Identity = Depends(resolve_identity)) -> Identity:
    """
    A caller proven by a Firebase token whenever the backend can verify one.

    Use for anything that returns organization data. Without it, the legacy
    fallback would let `?userId=<someone else>` read another organization.
    """
    if firebase.is_configured():
        identity.require_verified()
    return identity


def require_platform_admin(identity: Identity = Depends(resolve_identity)) -> Identity:
    """
    Platform administrators only.

    Deliberately strict: an unverified identity is refused even when
    AUTH_STRICT is off, so admin APIs can never be reached by asserting a uid.
    """
    if not firebase.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Admin API unavailable: the backend has no Firebase service account "
                "configured, so administrator identity cannot be verified."
            ),
        )

    identity.require_verified()

    try:
        snap = firebase.db().collection("users").document(identity.uid).get()
    except Exception as exc:
        logger.error(f"[AUTH] Could not read user record for admin check: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not verify administrator role",
        )

    role = (snap.to_dict() or {}).get("role") if snap.exists else None
    if role not in PLATFORM_ADMIN_ROLES:
        logger.warning(f"[AUTH] Denied admin access to uid={identity.uid} role={role}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform administrator role required",
        )

    return identity
