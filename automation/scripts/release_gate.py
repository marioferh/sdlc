#!/usr/bin/env python3
"""Block release when pending CVEs violate the release gate policy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib import cve_store  # noqa: E402
from scripts.lib.policy import release_blocking_severities, release_gate_enabled  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="CVE release gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--allow-disabled", action="store_true", help="Exit 0 if gate disabled in config")
    args = parser.parse_args()

    # Reopen expired exceptions before evaluating the gate
    reinstated = cve_store.expire_exceptions(actor="release_gate")

    if not release_gate_enabled():
        msg = {"ok": True, "enabled": False, "blocking": [], "reinstated": len(reinstated)}
        if args.json:
            print(json.dumps(msg, indent=2))
        else:
            print("release gate disabled in config")
        return 0 if args.allow_disabled or True else 0

    severities = release_blocking_severities()
    blocking = cve_store.blocking_for_release(severities)
    payload = {
        "ok": len(blocking) == 0,
        "enabled": True,
        "block_severities": severities,
        "blocking": [
            {
                "id": i.get("id"),
                "severity": i.get("severity"),
                "package": i.get("package"),
                "repository": i.get("repository"),
            }
            for i in blocking
        ],
        "reinstated_expired": len(reinstated),
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        if payload["ok"]:
            print(f"release gate PASS (checked {', '.join(severities)})")
        else:
            print(f"release gate FAIL — {len(blocking)} blocking CVE(s):", file=sys.stderr)
            for b in payload["blocking"]:
                print(f"  - {b['id']} [{b['severity']}] {b['package']} @ {b['repository']}", file=sys.stderr)
            print("Accept with expiry or fix before releasing.", file=sys.stderr)

    return 0 if payload["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
