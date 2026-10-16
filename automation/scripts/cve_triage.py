#!/usr/bin/env python3
"""Assisted CVE triage: suggest fix | mitigate | accept | discard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib import cve_store  # noqa: E402
from scripts.lib.triage import suggest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Assisted CVE triage")
    parser.add_argument("cve_id", nargs="?", help="Triage one CVE (default: all pending)")
    parser.add_argument("--apply", action="store_true", help="Persist triage suggestion on the CVE")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.cve_id:
        found = cve_store.find_cve(args.cve_id)
        if not found:
            print(f"error: {args.cve_id} not found", file=sys.stderr)
            return 1
        items = [found[1]]
    else:
        items = cve_store.pending_for_digest()

    results = [suggest(i) for i in items]
    if args.apply:
        for r in results:
            cve_store.set_triage(
                str(r["id"]),
                {
                    "suggestion": r["suggestion"],
                    "confidence": r["confidence"],
                    "reasons": r["reasons"],
                    "sla_breached": r["sla_breached"],
                },
            )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(
                f"{r['id']} [{r['severity']}] → {r['suggestion']} "
                f"(confidence={r['confidence']}, sla_breached={r['sla_breached']})"
            )
            for reason in r["reasons"]:
                print(f"  - {reason}")
            print("  checklist:")
            for step in r["checklist"]:
                print(f"    [ ] {step}")
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
