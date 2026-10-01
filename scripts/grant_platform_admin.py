#!/usr/bin/env python3
"""
Grant (or revoke) the Vectra platform-administrator role.

Platform admin is deliberately not self-serve: signup always creates a
`team_admin`, who administers only their own workspace. Reaching /admin
requires `role` on the user's Firestore document to be `platform_admin` or
`super_admin`, which is what this script sets.

Usage
-----
    # from the repo root, using the backend venv
    backend/.venv/bin/python scripts/grant_platform_admin.py you@example.com
    backend/.venv/bin/python scripts/grant_platform_admin.py you@example.com --role super_admin
    backend/.venv/bin/python scripts/grant_platform_admin.py you@example.com --revoke
    backend/.venv/bin/python scripts/grant_platform_admin.py --list

The account must already exist — sign up in the app first.

Requires FIREBASE_CREDENTIALS (or GOOGLE_APPLICATION_CREDENTIALS) to point at a
Firebase service-account JSON. The file is read locally and never printed.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PLATFORM_ROLES = ("platform_admin", "super_admin")
DEFAULT_ROLE = "team_admin"


def _load_env() -> None:
    """Pick up backend/.env so the script works with the same config as the API."""
    env_file = Path(__file__).resolve().parent.parent / "backend" / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def _credentials_path() -> str | None:
    for var in ("FIREBASE_CREDENTIALS", "GOOGLE_APPLICATION_CREDENTIALS"):
        path = os.getenv(var, "").strip()
        if path:
            return os.path.expanduser(path)
    return None


def _connect():
    path = _credentials_path()
    if not path:
        sys.exit(
            "No service account configured.\n"
            "  Firebase Console -> Project Settings -> Service Accounts -> Generate new private key\n"
            "  Save it OUTSIDE the repo, then add to backend/.env:\n"
            "    FIREBASE_CREDENTIALS=/absolute/path/to/serviceAccount.json"
        )
    if not os.path.isfile(path):
        sys.exit(f"Service account file not found: {path}")

    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
    except ImportError:
        sys.exit(
            "firebase-admin is not installed in this interpreter.\n"
            "  Run with the backend venv: backend/.venv/bin/python scripts/grant_platform_admin.py ..."
        )

    firebase_admin.initialize_app(credentials.Certificate(path))
    return firestore.client()


def list_admins(db) -> None:
    rows = [
        (doc.id, doc.to_dict() or {})
        for doc in db.collection("users").stream()
        if (doc.to_dict() or {}).get("role") in PLATFORM_ROLES
    ]
    if not rows:
        print("No platform administrators exist yet.")
        return
    print(f"{len(rows)} platform administrator(s):\n")
    for uid, data in rows:
        print(f"  {data.get('email') or '(no email)':<40} {data.get('role'):<16} {uid}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Grant or revoke the Vectra platform-admin role")
    parser.add_argument("email", nargs="?", help="Email of an existing Vectra account")
    parser.add_argument("--role", default="platform_admin", choices=PLATFORM_ROLES,
                        help="Role to grant (default: platform_admin)")
    parser.add_argument("--revoke", action="store_true",
                        help=f"Demote back to '{DEFAULT_ROLE}'")
    parser.add_argument("--list", action="store_true", help="List current platform administrators")
    parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    args = parser.parse_args()

    if not args.list and not args.email:
        parser.error("provide an email, or use --list")

    _load_env()
    db = _connect()

    if args.list:
        list_admins(db)
        return

    # Resolve the account. Firestore is the authority for role, but we match on
    # the email recorded there so a typo fails loudly instead of silently
    # creating a document for a user that does not exist.
    matches = [
        (doc.id, doc.to_dict() or {})
        for doc in db.collection("users").stream()
        if ((doc.to_dict() or {}).get("email") or "").lower() == args.email.lower()
    ]

    if not matches:
        sys.exit(
            f"No Vectra account found for {args.email}.\n"
            "Sign up in the app first (/auth/signup), then re-run this script."
        )
    if len(matches) > 1:
        sys.exit(f"Multiple accounts share {args.email}; resolve the duplicate before granting admin.")

    uid, data = matches[0]
    current = data.get("role") or "(unset)"
    target = DEFAULT_ROLE if args.revoke else args.role

    if current == target:
        print(f"{args.email} already has role '{target}'. Nothing to do.")
        return

    print("About to change a platform privilege:\n")
    print(f"  account : {args.email}")
    print(f"  uid     : {uid}")
    print(f"  role    : {current}  ->  {target}\n")

    if not args.yes:
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted. No changes made.")
            return

    # merge=True so only `role` changes; org membership and quota fields survive.
    db.collection("users").document(uid).set({"role": target}, merge=True)

    written = (db.collection("users").document(uid).get().to_dict() or {}).get("role")
    if written != target:
        sys.exit(f"Verification failed: role is '{written}', expected '{target}'.")

    print(f"\nDone. {args.email} is now '{target}'.")
    if target in PLATFORM_ROLES:
        print("Sign in at /auth/admin-login to reach the admin panel.")
    else:
        print("Platform admin access has been revoked.")


if __name__ == "__main__":
    main()
