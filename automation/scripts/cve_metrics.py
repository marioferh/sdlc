#!/usr/bin/env python3
"""CVE metrics: aging, SLA breaches, MTTR; write markdown dashboard."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib import audit, cve_store  # noqa: E402
from scripts.lib.config import ROOT, load_config  # noqa: E402
from scripts.lib.policy import age_hours, parse_ts, sla_breached, sla_hours_for  # noqa: E402

DASHBOARD = ROOT / "reports" / "cve-dashboard.md"


def _mttr_hours() -> list[float]:
    """MTTR from audit add→fix pairs."""
    entries = audit.list_entries()
    added: dict[str, datetime] = {}
    durations: list[float] = []
    for e in entries:
        cid = str(e.get("cve_id", "")).upper()
        at = parse_ts(e.get("at"))
        if not cid or not at:
            continue
        action = e.get("action")
        if action == "add":
            added[cid] = at
        elif action == "fix" and cid in added:
            durations.append((at - added[cid]).total_seconds() / 3600.0)
            del added[cid]
    # Also use fixed.yaml added_at → fixed_at when audit incomplete
    for item in cve_store.list_items("fixed"):
        a = parse_ts(item.get("added_at"))
        f = parse_ts(item.get("fixed_at"))
        if a and f and f >= a:
            durations.append((f - a).total_seconds() / 3600.0)
    return durations


def collect() -> dict:
    pending = cve_store.pending_for_digest()
    accepted = cve_store.list_items("accepted")
    discarded = cve_store.list_items("discarded")
    fixed = cve_store.list_items("fixed")

    by_sev = Counter(str(i.get("severity", "UNKNOWN")).upper() for i in pending)
    breached = [i for i in pending if sla_breached(i)]
    aging = {"0-24h": 0, "1-7d": 0, "7-30d": 0, "30d+": 0}
    for i in pending:
        h = age_hours(i) or 0
        if h < 24:
            aging["0-24h"] += 1
        elif h < 168:
            aging["1-7d"] += 1
        elif h < 720:
            aging["7-30d"] += 1
        else:
            aging["30d+"] += 1

    mttrs = _mttr_hours()
    expiring_soon = []
    now = datetime.now(timezone.utc)
    for i in accepted:
        exp = parse_ts(i.get("expires_at"))
        if exp and 0 <= (exp - now).total_seconds() <= 7 * 86400:
            expiring_soon.append(i)

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "pending": len(pending),
            "accepted": len(accepted),
            "discarded": len(discarded),
            "fixed": len(fixed),
        },
        "pending_by_severity": dict(by_sev),
        "sla_breached": [
            {"id": i.get("id"), "severity": i.get("severity"), "age_hours": round(age_hours(i) or 0, 1)}
            for i in breached
        ],
        "aging": aging,
        "mttr_hours_avg": round(mean(mttrs), 1) if mttrs else None,
        "mttr_samples": len(mttrs),
        "accepted_expiring_7d": [
            {"id": i.get("id"), "expires_at": i.get("expires_at"), "severity": i.get("severity")}
            for i in expiring_soon
        ],
        "top_packages": [
            {"package": p, "count": c}
            for p, c in Counter(i.get("package") or "unknown" for i in pending).most_common(10)
        ],
    }


def render_md(stats: dict) -> str:
    lines = [
        "# CVE Dashboard",
        "",
        f"Generated: `{stats['generated_at']}`",
        "",
        "## Counts",
        "",
        f"| Status | Count |",
        f"|--------|------:|",
    ]
    for k, v in stats["counts"].items():
        lines.append(f"| {k} | {v} |")
    lines.extend(["", "## Pending by severity", ""])
    for sev, n in sorted(stats["pending_by_severity"].items()):
        limit = sla_hours_for(sev)
        lines.append(f"- **{sev}**: {n} (SLA {limit}h)" if limit else f"- **{sev}**: {n}")
    lines.extend(
        [
            "",
            "## Aging (pending)",
            "",
            *(f"- {bucket}: {n}" for bucket, n in stats["aging"].items()),
            "",
            f"## SLA breaches ({len(stats['sla_breached'])})",
            "",
        ]
    )
    if not stats["sla_breached"]:
        lines.append("_None_")
    else:
        for b in stats["sla_breached"]:
            lines.append(f"- {b['id']} [{b['severity']}] age={b['age_hours']}h")
    mttr = stats["mttr_hours_avg"]
    lines.extend(
        [
            "",
            "## MTTR",
            "",
            f"- Average: **{mttr}h** across {stats['mttr_samples']} samples"
            if mttr is not None
            else "- Average: _n/a_ (no fixed CVEs yet)",
            "",
            "## Accepted expiring in 7 days",
            "",
        ]
    )
    if not stats["accepted_expiring_7d"]:
        lines.append("_None_")
    else:
        for i in stats["accepted_expiring_7d"]:
            lines.append(f"- {i['id']} [{i['severity']}] expires {i['expires_at']}")
    lines.extend(["", "## Top packages (pending)", ""])
    for row in stats["top_packages"]:
        lines.append(f"- `{row['package']}` × {row['count']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="CVE metrics and dashboard")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--write", action="store_true", help=f"Write {DASHBOARD}")
    parser.add_argument("--email", action="store_true", help="Email dashboard summary")
    args = parser.parse_args()

    cve_store.expire_exceptions(actor="metrics")
    stats = collect()

    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        print(render_md(stats))

    if args.write:
        DASHBOARD.parent.mkdir(parents=True, exist_ok=True)
        DASHBOARD.write_text(render_md(stats), encoding="utf-8")
        # also dump raw json next to it
        (DASHBOARD.parent / "cve-metrics.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {DASHBOARD}", file=sys.stderr)

    if args.email:
        from scripts.lib import email_client

        cfg = load_config()
        prefix = (cfg.get("email") or {}).get("subject_prefix") or "[SDLC]"
        email_client.send_mail(
            f"{prefix} CVE dashboard — {stats['counts']['pending']} pending",
            render_md(stats),
        )
        print("dashboard emailed", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
