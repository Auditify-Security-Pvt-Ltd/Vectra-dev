#!/usr/bin/env python3
"""
Move plan and scan quota from users to organizations.

Before: users/{uid}.plan / bonusScans / scansUsed  (one budget per user)
After:  organizations/{orgId}.plan / bonusScans / scansUsed  (one shared budget)

For every organization that has not been migrated yet, in one transaction:

    plan        keep the organization's value if already set, else the
                owner's legacy plan, else unset (= default plan)
    bonusScans  keep the organization's value if already set, else the
                owner's legacy bonus
    scansUsed   organization's current value (scans already charged by the new
                backend, normally 0) + SUM of legacy scansUsed of every user
                whose users/{uid}.organizationId is this organization
    status      'active' unless already set
    quotaMigratedAt  timestamp — the idempotency marker

Usage recorded by the legacy counters is preserved, never reset. Scan
documents are counted in the report for comparison but are not used as the
source, because the counters are what was actually charged (scans created
before quotas existed were never counted).

SAFETY
  * Dry run by default; pass --apply to write.
  * Idempotent: organizations with quotaMigratedAt are skipped, so re-running
    never double-counts, and never overwrites usage added after migration.
  * Non-destructive: user documents and scan data are never modified; legacy
    user fields stay in place (they are no longer read for enforcement).

Usage
-----
    backend/.venv/bin/python scripts/migrate_org_quota.py            # report only
    backend/.venv/bin/python scripts/migrate_org_quota.py --apply    # write

Uses FIREBASE_CREDENTIALS from backend/.env. Honours FIRESTORE_EMULATOR_HOST
(with GOOGLE_CLOUD_PROJECT) for testing against the emulator.
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCAN_COLLECTIONS = ("scans", "network_scans", "sast_scans")


def _load_env() -> None:
    env_file = Path(__file__).resolve().parent.parent / "backend" / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def _connect():
    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
    except ImportError:
        sys.exit("firebase-admin is not installed. Run with backend/.venv/bin/python.")

    if os.getenv("FIRESTORE_EMULATOR_HOST"):
        # The emulator needs no credentials; the plain client connects to it directly.
        from google.cloud import firestore as gcf
        project = os.getenv("GOOGLE_CLOUD_PROJECT") or "demo-vectra"
        print(f"Using Firestore emulator at {os.environ['FIRESTORE_EMULATOR_HOST']} (project {project})\n")
        return gcf.Client(project=project)

    path = os.getenv("FIREBASE_CREDENTIALS") or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if not path or not os.path.isfile(os.path.expanduser(path)):
        sys.exit("No service account configured (FIREBASE_CREDENTIALS in backend/.env).")
    firebase_admin.initialize_app(credentials.Certificate(os.path.expanduser(path)))
    return firestore.client()


def _int(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def plan_migration(db) -> tuple[list[dict], list[str]]:
    users = {d.id: (d.to_dict() or {}) for d in db.collection("users").stream()}
    orgs = {d.id: (d.to_dict() or {}) for d in db.collection("organizations").stream()}

    legacy_used: dict[str, int] = defaultdict(int)
    contributors: dict[str, list[str]] = defaultdict(list)
    warnings: list[str] = []

    for uid, user in users.items():
        org_id = user.get("organizationId")
        used = _int(user.get("scansUsed"))
        if not org_id:
            if used or user.get("bonusScans") or user.get("plan"):
                warnings.append(f"user {uid} has legacy quota fields but no organization — left unchanged")
            else:
                warnings.append(f"user {uid} has no organization — left unchanged")
            continue
        if org_id not in orgs:
            warnings.append(f"user {uid} points at missing organization {org_id} — usage {used} not migrated")
            continue
        legacy_used[org_id] += used
        if used:
            contributors[org_id].append(f"{uid}:{used}")

    plans: list[dict] = []
    for org_id, org in sorted(orgs.items(), key=lambda kv: (kv[1].get("name") or "").lower()):
        owner = users.get(org.get("ownerId") or org_id, {})
        history = 0
        for name in SCAN_COLLECTIONS:
            try:
                history += int(db.collection("users").document(org_id).collection(name).count().get()[0][0].value)
            except Exception:
                pass
        plans.append({
            "orgId":        org_id,
            "name":         org.get("name"),
            "migrated":     bool(org.get("quotaMigratedAt")),
            "currentUsed":  _int(org.get("scansUsed")),
            "legacyUsed":   legacy_used.get(org_id, 0),
            "contributors": contributors.get(org_id, []),
            "plan":         org.get("plan") or owner.get("plan"),
            "bonusScans":   org["bonusScans"] if "bonusScans" in org else _int(owner.get("bonusScans")),
            "scanDocs":     history,
        })
    return plans, warnings


def apply_one(db, org_id: str) -> str:
    """Migrate one organization atomically. Returns what happened."""
    from google.cloud import firestore

    org_ref = db.collection("organizations").document(org_id)

    @firestore.transactional
    def _run(txn) -> str:
        snap = org_ref.get(transaction=txn)
        if not snap.exists:
            return "missing"
        org = snap.to_dict() or {}
        if org.get("quotaMigratedAt"):
            return "already migrated"

        # Re-read legacy counters inside the transaction boundary so a
        # concurrent run cannot migrate stale values.
        members = list(db.collection("users").where("organizationId", "==", org_id).stream(transaction=txn))
        legacy = sum(_int((m.to_dict() or {}).get("scansUsed")) for m in members)
        owner_snap = db.collection("users").document(org.get("ownerId") or org_id).get(transaction=txn)
        owner = (owner_snap.to_dict() or {}) if owner_snap.exists else {}

        update = {
            "scansUsed":       _int(org.get("scansUsed")) + legacy,
            "quotaMigratedAt": datetime.now(timezone.utc).isoformat(),
            "updatedAt":       datetime.now(timezone.utc).isoformat(),
        }
        if not org.get("plan") and owner.get("plan"):
            update["plan"] = owner["plan"]
        if "bonusScans" not in org:
            update["bonusScans"] = _int(owner.get("bonusScans"))
        if org.get("status") not in ("active", "disabled"):
            update["status"] = "active"
        txn.update(org_ref, update)
        return f"migrated: scansUsed={update['scansUsed']}"

    return _run(db.transaction())


def main() -> None:
    parser = argparse.ArgumentParser(description="Move scan quota from users to organizations")
    parser.add_argument("--apply", action="store_true", help="Write changes (default is a dry run)")
    args = parser.parse_args()

    _load_env()
    db = _connect()
    plans, warnings = plan_migration(db)

    print(f"{'ORGANIZATION':<34} {'STATE':<10} {'PLAN':<10} {'BONUS':>5} {'USED(org+legacy)':>17} {'SCAN DOCS':>9}")
    for p in plans:
        state = "done" if p["migrated"] else "pending"
        used = f"{p['currentUsed']}" if p["migrated"] else f"{p['currentUsed']}+{p['legacyUsed']}={p['currentUsed'] + p['legacyUsed']}"
        label = f"{(p['name'] or '(unnamed)')[:22]} {p['orgId'][:10]}"
        print(f"{label:<34} {state:<10} {(p['plan'] or 'default'):<10} {p['bonusScans']:>5} {used:>17} {p['scanDocs']:>9}")
    for w in warnings:
        print(f"  ! {w}")

    pending = [p for p in plans if not p["migrated"]]
    print(f"\n{len(plans)} organization(s), {len(pending)} pending migration.")

    if not args.apply:
        print("Dry run — nothing written. Re-run with --apply to migrate.")
        return

    for p in pending:
        print(f"  {p['orgId']}: {apply_one(db, p['orgId'])}")
    print("Done.")


if __name__ == "__main__":
    main()
