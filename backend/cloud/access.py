"""
Server-side organization resolution and Cloud Security RBAC.

    verified Firebase uid → users/{uid}.organizationId → active membership
    → organizations/{orgId} → orgRole → permission

The organization id, user id and role are never taken from the request. Org
roles mirror frontend/lib/rbac.ts (admin / editor / viewer); platform roles
are a separate system and grant nothing here.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, status

from services import firebase, quota
from services.auth import Identity, require_user

VIEW_CLOUD_SECURITY      = "VIEW_CLOUD_SECURITY"
VIEW_CLOUD_FINDINGS      = "VIEW_CLOUD_FINDINGS"
SYNC_CLOUD_FINDINGS      = "SYNC_CLOUD_FINDINGS"
MANAGE_CLOUD_INTEGRATIONS = "MANAGE_CLOUD_INTEGRATIONS"
DELETE_CLOUD_INTEGRATION = "DELETE_CLOUD_INTEGRATION"

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin":  {VIEW_CLOUD_SECURITY, VIEW_CLOUD_FINDINGS, SYNC_CLOUD_FINDINGS,
               MANAGE_CLOUD_INTEGRATIONS, DELETE_CLOUD_INTEGRATION},
    "editor": {VIEW_CLOUD_SECURITY, VIEW_CLOUD_FINDINGS, SYNC_CLOUD_FINDINGS},
    "viewer": {VIEW_CLOUD_SECURITY, VIEW_CLOUD_FINDINGS},
}

# Changing cloud state requires an active organization; reading history does not.
_WRITE_PERMISSIONS = {SYNC_CLOUD_FINDINGS, MANAGE_CLOUD_INTEGRATIONS, DELETE_CLOUD_INTEGRATION}


@dataclass(frozen=True)
class OrgContext:
    uid: str
    email: str | None
    org_id: str
    org_role: str
    org_active: bool

    def can(self, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.org_role, set())


def _deny(code: int, error: str, message: str) -> HTTPException:
    return HTTPException(status_code=code, detail={"code": error, "message": message})


def resolve_org_context(identity: Identity) -> OrgContext:
    if not firebase.is_configured():
        raise _deny(status.HTTP_503_SERVICE_UNAVAILABLE, "BACKEND_NOT_CONFIGURED",
                    "Cloud Security requires the backend Firebase service account.")
    identity.require_verified()

    db = firebase.db()
    user_snap = db.collection("users").document(identity.uid).get()
    user = (user_snap.to_dict() or {}) if user_snap.exists else {}
    if (user.get("status") or "active") != "active":
        raise _deny(status.HTTP_403_FORBIDDEN, "ACCOUNT_DISABLED", "Your account is disabled.")

    org_id = user.get("organizationId")
    if not isinstance(org_id, str) or not org_id:
        raise _deny(status.HTTP_403_FORBIDDEN, "NO_ORGANIZATION", "Your account is not part of an organization.")

    org_snap = db.collection("organizations").document(org_id).get()
    member_snap = db.collection("organizations").document(org_id).collection("members").document(identity.uid).get()
    member = (member_snap.to_dict() or {}) if member_snap.exists else None
    if not org_snap.exists or member is None or (member.get("status") or "active") != "active":
        raise _deny(status.HTTP_403_FORBIDDEN, "NOT_ORG_MEMBER", "You are not an active member of this organization.")

    role = member.get("orgRole") if member.get("orgRole") in ROLE_PERMISSIONS else "viewer"
    return OrgContext(
        uid=identity.uid,
        email=identity.email,
        org_id=org_id,
        org_role=role,
        org_active=quota.org_status(org_snap.to_dict() or {}) == "active",
    )


def require_permission(permission: str):
    """FastAPI dependency: the caller's OrgContext, if they hold `permission`."""

    def dependency(identity: Identity = Depends(require_user)) -> OrgContext:
        ctx = resolve_org_context(identity)
        if not ctx.can(permission):
            raise _deny(status.HTTP_403_FORBIDDEN, "FORBIDDEN",
                        "Your organization role does not allow this Cloud Security action.")
        if permission in _WRITE_PERMISSIONS and not ctx.org_active:
            raise _deny(status.HTTP_403_FORBIDDEN, "ORGANIZATION_DISABLED", "Your organization is disabled.")
        return ctx

    return dependency
