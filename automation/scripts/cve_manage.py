#!/usr/bin/env python3
"""Add, discard, undiscard or list CVEs in the SDLC store."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib import cve_store  # noqa: E402


def cmd_list(args: argparse.Namespace) -> int:
    for bucket in ("pending", "manual", "discarded"):
        if args.bucket and args.bucket != bucket:
            continue
        items = cve_store.list_items(bucket)
        print(f"\n## {bucket} ({len(items)})")
        for item in items:
            print(
                f"  {item.get('id')}  {item.get('severity')}  "
                f"{item.get('package') or '-'}  {item.get('repository') or '-'}  "
                f"[{item.get('status')}]"
            )
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    item = cve_store.add_cve(
        args.cve_id,
        severity=args.severity,
        package=args.package or "",
        repository=args.repository or "",
        epic=args.epic or "",
        notes=args.notes or "",
        manual=args.manual,
        source="manual" if args.manual else "cli",
    )
    print(json.dumps(item, indent=2))
    return 0


def cmd_discard(args: argparse.Namespace) -> int:
    item = cve_store.discard_cve(args.cve_id, reason=args.reason or "")
    print(json.dumps(item, indent=2))
    return 0


def cmd_undiscard(args: argparse.Namespace) -> int:
    item = cve_store.undiscard_cve(args.cve_id)
    print(json.dumps(item, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Manage SDLC CVEs (pending / discarded / manual).")
    sub = p.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list", help="List CVEs by bucket")
    list_p.add_argument("--bucket", choices=["pending", "manual", "discarded"])
    list_p.set_defaults(func=cmd_list)

    add_p = sub.add_parser("add", help="Add a CVE (optionally --manual)")
    add_p.add_argument("cve_id")
    add_p.add_argument("--severity", default="UNKNOWN")
    add_p.add_argument("--package", default="")
    add_p.add_argument("--repository", default="")
    add_p.add_argument("--epic", default="")
    add_p.add_argument("--notes", default="")
    add_p.add_argument("--manual", action="store_true", help="Mark as manually added")
    add_p.set_defaults(func=cmd_add)

    disc_p = sub.add_parser("discard", help="Discard a CVE (exclude from digests)")
    disc_p.add_argument("cve_id")
    disc_p.add_argument("--reason", default="")
    disc_p.set_defaults(func=cmd_discard)

    und_p = sub.add_parser("undiscard", help="Move a discarded CVE back to pending")
    und_p.add_argument("cve_id")
    und_p.set_defaults(func=cmd_undiscard)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
