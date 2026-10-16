#!/usr/bin/env python3
"""Add, discard, accept, fix, undiscard or list CVEs in the SDLC store."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib import audit, cve_store  # noqa: E402


def cmd_list(args: argparse.Namespace) -> int:
    buckets = ("pending", "manual", "accepted", "discarded", "fixed")
    for bucket in buckets:
        if args.bucket and args.bucket != bucket:
            continue
        items = cve_store.list_items(bucket)
        print(f"\n## {bucket} ({len(items)})")
        for item in items:
            extra = ""
            if item.get("expires_at"):
                extra = f" expires={item['expires_at']}"
            if item.get("jira_key"):
                extra += f" jira={item['jira_key']}"
            print(
                f"  {item.get('id')}  {item.get('severity')}  "
                f"{item.get('package') or '-'}  {item.get('repository') or '-'}  "
                f"[{item.get('status')}]{extra}"
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
        actor=args.actor,
    )
    print(json.dumps(item, indent=2))
    return 0


def cmd_discard(args: argparse.Namespace) -> int:
    item = cve_store.discard_cve(
        args.cve_id,
        reason=args.reason or "",
        actor=args.actor,
        approver=args.approver,
        expires=args.expires,
    )
    print(json.dumps(item, indent=2))
    return 0


def cmd_undiscard(args: argparse.Namespace) -> int:
    item = cve_store.undiscard_cve(args.cve_id, actor=args.actor)
    print(json.dumps(item, indent=2))
    return 0


def cmd_accept(args: argparse.Namespace) -> int:
    item = cve_store.accept_cve(
        args.cve_id,
        reason=args.reason,
        expires_days=args.expires_days,
        actor=args.actor,
        approver=args.approver,
    )
    print(json.dumps(item, indent=2))
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    item = cve_store.fix_cve(
        args.cve_id,
        notes=args.notes or "",
        pr_url=args.pr or "",
        actor=args.actor,
    )
    print(json.dumps(item, indent=2))
    return 0


def cmd_expire(args: argparse.Namespace) -> int:
    items = cve_store.expire_exceptions(actor=args.actor or "system")
    print(json.dumps({"reinstated": len(items), "items": items}, indent=2))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    entries = audit.list_entries(cve_id=args.cve_id, limit=args.limit)
    print(json.dumps(entries, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--actor", default=None, help="Who performs the action (audit)")

    p = argparse.ArgumentParser(description="Manage SDLC CVEs.", parents=[common])
    sub = p.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list", parents=[common], help="List CVEs by bucket")
    list_p.add_argument("--bucket", choices=["pending", "manual", "accepted", "discarded", "fixed"])
    list_p.set_defaults(func=cmd_list)

    add_p = sub.add_parser("add", parents=[common], help="Add a CVE (optionally --manual)")
    add_p.add_argument("cve_id")
    add_p.add_argument("--severity", default="UNKNOWN")
    add_p.add_argument("--package", default="")
    add_p.add_argument("--repository", default="")
    add_p.add_argument("--epic", default="")
    add_p.add_argument("--notes", default="")
    add_p.add_argument("--manual", action="store_true")
    add_p.set_defaults(func=cmd_add)

    disc_p = sub.add_parser("discard", parents=[common], help="Discard a CVE")
    disc_p.add_argument("cve_id")
    disc_p.add_argument("--reason", default="")
    disc_p.add_argument("--approver", default=None)
    disc_p.add_argument("--expires", default=None, help="ISO timestamp to auto-reopen")
    disc_p.set_defaults(func=cmd_discard)

    und_p = sub.add_parser("undiscard", parents=[common], help="Move discarded CVE back to pending")
    und_p.add_argument("cve_id")
    und_p.set_defaults(func=cmd_undiscard)

    acc_p = sub.add_parser("accept", parents=[common], help="Accept risk with expiry (days)")
    acc_p.add_argument("cve_id")
    acc_p.add_argument("--reason", required=True)
    acc_p.add_argument("--expires-days", type=int, required=True)
    acc_p.add_argument("--approver", default=None, help="Required for CRITICAL (four-eyes)")
    acc_p.set_defaults(func=cmd_accept)

    fix_p = sub.add_parser("fix", parents=[common], help="Mark CVE as fixed")
    fix_p.add_argument("cve_id")
    fix_p.add_argument("--notes", default="")
    fix_p.add_argument("--pr", default="")
    fix_p.set_defaults(func=cmd_fix)

    exp_p = sub.add_parser("expire", parents=[common], help="Reopen expired accept/discard exceptions")
    exp_p.set_defaults(func=cmd_expire)

    aud_p = sub.add_parser("audit", parents=[common], help="Show audit log entries")
    aud_p.add_argument("--cve-id", default=None)
    aud_p.add_argument("--limit", type=int, default=50)
    aud_p.set_defaults(func=cmd_audit)

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
