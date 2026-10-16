#!/usr/bin/env python3
"""Sync scanner findings, build morning CVE digest, optionally email + open Jira."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib.config import load_config  # noqa: E402
from scripts.lib import cve_store, email_client, github_client, jira_client  # noqa: E402
from scripts.lib.policy import age_hours, sla_breached, sla_hours_for  # noqa: E402
from scripts.lib.triage import suggest  # noqa: E402


SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def sync_github_advisories(cfg: dict) -> int:
    if "github_advisories" not in (cfg.get("cve") or {}).get("sources", []):
        return 0
    gh = github_client.GitHubClient()
    added = 0
    for repo in (cfg.get("github") or {}).get("repositories") or []:
        owner, name = repo["owner"], repo["name"]
        for alert in gh.dependabot_alerts(owner, name, state="open"):
            advisory = alert.get("security_advisory") or {}
            cve_ids = [c.get("value") for c in (advisory.get("identifiers") or []) if c.get("type") == "CVE"]
            if not cve_ids:
                ghsa = advisory.get("ghsa_id") or alert.get("number")
                cve_ids = [f"GHSA-{ghsa}"] if ghsa else []
            pkg = ((alert.get("dependency") or {}).get("package") or {}).get("name", "")
            sev = SEVERITY_MAP.get(str(advisory.get("severity", "")).lower(), "UNKNOWN")
            for cid in cve_ids:
                if cve_store.find_cve(str(cid)):
                    continue
                try:
                    cve_store.upsert_from_scanner(
                        {
                            "id": cid,
                            "severity": sev,
                            "package": pkg,
                            "repository": f"{owner}/{name}",
                            "notes": advisory.get("summary") or "",
                            "source": "github_advisories",
                        }
                    )
                    added += 1
                except ValueError:
                    pass
    return added


def build_body(items: list[dict], cfg: dict, reinstated: int) -> str:
    tz = ZoneInfo((cfg.get("email") or {}).get("timezone") or "UTC")
    today = datetime.now(tz).strftime("%Y-%m-%d")
    breached = [i for i in items if sla_breached(i)]
    lines = [
        f"SDLC morning CVE digest — {today}",
        "",
        f"Pending CVEs: {len(items)}",
        f"SLA breaches: {len(breached)}",
        f"Expired exceptions reinstated: {reinstated}",
        "",
    ]
    if breached:
        lines.append("## SLA breaches")
        for item in breached:
            limit = sla_hours_for(str(item.get("severity", "")))
            lines.append(
                f"- {item.get('id')} [{item.get('severity')}] "
                f"age~{int(age_hours(item) or 0)}h (SLA {limit}h)"
            )
        lines.append("")

    if not items:
        lines.append("No pending CVEs matching digest severities. Good morning.")
        return "\n".join(lines)

    lines.append("## Pending")
    for item in items:
        triage = suggest(item)
        lines.append(
            f"- {item.get('id')} [{item.get('severity')}] "
            f"pkg={item.get('package') or '-'} repo={item.get('repository') or '-'} "
            f"→ {triage['suggestion']} "
            f"jira={item.get('jira_key') or '-'}"
        )
        if item.get("notes"):
            lines.append(f"    {item['notes']}")
    lines.extend(
        [
            "",
            "Manage:",
            "  python automation/scripts/cve_manage.py list",
            "  python automation/scripts/cve_triage.py",
            "  python automation/scripts/cve_remediate.py CVE-XXXX",
            "  python automation/scripts/cve_manage.py discard CVE-XXXX --reason '...'",
            "  python automation/scripts/cve_manage.py accept CVE-XXXX --reason '...' --expires-days 30",
            "  python automation/scripts/release_gate.py",
            "",
        ]
    )
    return "\n".join(lines)


def maybe_open_jira(items: list[dict], cfg: dict) -> None:
    jira_cfg = cfg.get("jira") or {}
    project = jira_cfg.get("project_key")
    auto = (cfg.get("cve") or {}).get("auto_jira_on_critical", True)
    if not project or not items or not auto:
        return
    critical = [i for i in items if str(i.get("severity", "")).upper() == "CRITICAL" and not i.get("jira_key")]
    if not critical:
        return
    client = jira_client.JiraClient()
    for item in critical:
        summary = f"[CVE] {item['id']} — {item.get('package') or 'dependency'} ({item.get('repository') or 'unknown repo'})"
        fields = {
            "project": {"key": project},
            "summary": summary[:255],
            "issuetype": {"name": "Task"},
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": item.get("notes") or "Critical CVE from SDLC digest."}],
                    }
                ],
            },
            "labels": ["cve", "security", "critical"],
        }
        try:
            created = client.create_issue(fields)
            key = created.get("key", "")
            if key:
                cve_store.set_jira_key(str(item["id"]), key, actor="digest")
            print(f"jira: created {key} for {item['id']}")
        except Exception as exc:  # noqa: BLE001
            print(f"jira: skip {item['id']}: {exc}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Morning CVE digest")
    parser.add_argument("--dry-run", action="store_true", help="Print email body, do not send")
    parser.add_argument("--no-sync", action="store_true", help="Skip GitHub Dependabot sync")
    parser.add_argument("--no-jira", action="store_true", help="Do not create Jira issues")
    parser.add_argument("--no-email", action="store_true", help="Do not send email")
    args = parser.parse_args()

    cfg = load_config()
    reinstated = cve_store.expire_exceptions(actor="digest")
    if reinstated:
        print(f"reinstated {len(reinstated)} expired exception(s)")

    if not args.no_sync:
        n = sync_github_advisories(cfg)
        print(f"synced {n} new advisories from GitHub")

    severities = (cfg.get("cve") or {}).get("digest_severities") or ["CRITICAL", "HIGH", "MEDIUM"]
    items = cve_store.pending_for_digest(severities)
    prefix = (cfg.get("email") or {}).get("subject_prefix") or "[SDLC]"
    breached_n = sum(1 for i in items if sla_breached(i))
    subject = f"{prefix} CVE digest — {len(items)} pending ({breached_n} SLA breach)"
    body = build_body(items, cfg, len(reinstated))

    if args.dry_run or args.no_email:
        print(subject)
        print(body)
    else:
        email_client.send_mail(subject, body)
        print(f"email sent to digest recipient ({len(items)} CVEs)")

    if not args.no_jira and not args.dry_run:
        maybe_open_jira(items, cfg)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
