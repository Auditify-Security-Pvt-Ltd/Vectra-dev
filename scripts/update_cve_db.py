#!/usr/bin/env python3
"""
update_cve_db.py — Vectra CVE database maintenance tool.

Usage:
    python scripts/update_cve_db.py [--fix]

Without --fix: report only (no writes)
With    --fix: deduplicate and rewrite JSON files
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "backend" / "data" / "cves"

REQUIRED_FIELDS = {"cveId", "technology", "severity", "cvss", "description"}

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE",
                    "critical", "high", "medium", "low", "none"}


def validate(entry: dict, fname: str, idx: int) -> list[str]:
    errors = []
    for field in REQUIRED_FIELDS:
        if field not in entry:
            errors.append(f"  [{fname}][{idx}] Missing field: {field!r}")
    cve_id = entry.get("cveId", "")
    if cve_id and not cve_id.startswith("CVE-"):
        errors.append(f"  [{fname}][{idx}] Invalid cveId: {cve_id!r}")
    sev = str(entry.get("severity", ""))
    if sev and sev not in VALID_SEVERITIES:
        errors.append(f"  [{fname}][{idx}] Invalid severity: {sev!r}")
    cvss = entry.get("cvss")
    if cvss is not None and not isinstance(cvss, (int, float)):
        errors.append(f"  [{fname}][{idx}] cvss must be a number, got {type(cvss).__name__}")
    return errors


def process_file(fpath: Path, fix: bool) -> tuple[int, int, int, list[str]]:
    """Returns (total, dupes_removed, invalid_removed, errors)."""
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except Exception as exc:
        return 0, 0, 0, [f"  [{fpath.name}] Parse error: {exc}"]

    if not isinstance(entries, list):
        return 0, 0, 0, [f"  [{fpath.name}] Expected JSON array, got {type(entries).__name__}"]

    errors: list[str] = []
    seen_ids: set[str] = set()
    clean: list[dict] = []
    dupes = 0
    invalid = 0

    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            invalid += 1
            errors.append(f"  [{fpath.name}][{idx}] Not an object")
            continue

        entry_errors = validate(entry, fpath.name, idx)
        if entry_errors:
            errors.extend(entry_errors)
            invalid += 1
            continue

        dedup_key = f"{entry['cveId']}::{entry['technology']}"
        if dedup_key in seen_ids:
            dupes += 1
            continue

        seen_ids.add(dedup_key)
        clean.append(entry)

    if fix and (dupes > 0 or invalid > 0):
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2, ensure_ascii=False)
            f.write("\n")

    return len(entries), dupes, invalid, errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Vectra CVE database maintenance")
    parser.add_argument("--fix", action="store_true", help="Write cleaned files")
    args = parser.parse_args()

    if not DATA_DIR.exists():
        print(f"ERROR: Data directory not found: {DATA_DIR}", file=sys.stderr)
        sys.exit(1)

    json_files = sorted(DATA_DIR.glob("*.json"))
    if not json_files:
        print(f"No JSON files found in {DATA_DIR}", file=sys.stderr)
        sys.exit(1)

    grand_total = 0
    grand_dupes = 0
    grand_invalid = 0
    all_errors: list[str] = []

    print(f"\nVectra CVE Database Maintenance")
    print(f"{'=' * 50}")
    print(f"Mode: {'FIX (rewriting files)' if args.fix else 'REPORT ONLY'}")
    print(f"Directory: {DATA_DIR}")
    print()

    for fpath in json_files:
        total, dupes, invalid, errors = process_file(fpath, args.fix)
        clean = total - dupes - invalid
        status = "OK" if not errors and dupes == 0 else "ISSUES"
        print(f"  {fpath.name:<35} {total:>4} entries  {clean:>4} clean  {dupes:>3} dupes  {invalid:>3} invalid  [{status}]")
        grand_total   += total
        grand_dupes   += dupes
        grand_invalid += invalid
        all_errors.extend(errors)

    print()
    print(f"{'─' * 50}")
    print(f"  Total CVEs:        {grand_total}")
    print(f"  Valid (clean):     {grand_total - grand_dupes - grand_invalid}")
    print(f"  Duplicates:        {grand_dupes}")
    print(f"  Invalid:           {grand_invalid}")
    print(f"  Files processed:   {len(json_files)}")

    if all_errors:
        print(f"\nValidation issues ({len(all_errors)}):")
        for err in all_errors[:50]:
            print(err)
        if len(all_errors) > 50:
            print(f"  ... and {len(all_errors) - 50} more")

    if args.fix and (grand_dupes > 0 or grand_invalid > 0):
        print(f"\nFixed: removed {grand_dupes} duplicates and {grand_invalid} invalid entries.")
    elif not args.fix and (grand_dupes > 0 or grand_invalid > 0):
        print(f"\nRun with --fix to remove duplicates and invalid entries.")

    print()


if __name__ == "__main__":
    main()
