#!/usr/bin/env python3
"""Create a Jira remediation task with checklist for a CVE."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib import cve_store, jira_client  # noqa: E402
from scripts.lib.config import load_config  # noqa: E402
from scripts.lib.triage import suggest  # noqa: E402


def _adf_checklist(steps: list[str], notes: str) -> dict:
    content: list[dict] = [
        {
            "type": "paragraph",
            "content": [{"type": "text", "text": notes or "Remediation plan from SDLC CVE ops."}],
        },
        {"type": "paragraph", "content": [{"type": "text", "text": "Checklist:", "marks": [{"type": "strong"}]}]},
    ]
    for step in steps:
        content.append(
            {
                "type": "taskList",
                "content": [
                    {
                        "type": "taskItem",
                        "attrs": {"state": "TODO"},
                        "content": [{"type": "text", "text": step}],
                    }
                ],
            }
        )
    return {"type": "doc", "version": 1, "content": content}


def main() -> int:
    parser = argparse.ArgumentParser(description="Open Jira remediation for a CVE")
    parser.add_argument("cve_id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--epic", default="", help="Optional epic key to mention in description")
    args = parser.parse_args()

    found = cve_store.find_cve(args.cve_id)
    if not found:
        print(f"error: {args.cve_id} not found", file=sys.stderr)
        return 1
    _bucket, item = found
    if item.get("jira_key"):
        print(f"already linked to {item['jira_key']}")
        return 0

    triage = suggest(item)
    cfg = load_config()
    project = (cfg.get("jira") or {}).get("project_key")
    if not project:
        print("error: jira.project_key missing in config", file=sys.stderr)
        return 1

    summary = (
        f"[CVE] {item['id']} — {item.get('package') or 'dependency'} "
        f"({item.get('repository') or 'unknown repo'}) [{item.get('severity')}]"
    )
    notes = (
        f"CVE: {item.get('id')}\n"
        f"Severity: {item.get('severity')}\n"
        f"Package: {item.get('package')}\n"
        f"Repository: {item.get('repository')}\n"
        f"Suggestion: {triage['suggestion']}\n"
        f"Epic: {args.epic or item.get('epic') or '-'}\n"
        f"Notes: {item.get('notes') or '-'}"
    )
    steps = triage["checklist"] or [
        "Investigate advisory",
        "Upgrade dependency",
        "Open PR",
        "Run tests",
        "Mark CVE fixed in SDLC",
    ]

    fields = {
        "project": {"key": project},
        "summary": summary[:255],
        "issuetype": {"name": "Task"},
        "description": _adf_checklist(steps, notes),
        "labels": ["cve", "security", str(item.get("severity", "unknown")).lower()],
    }

    if args.dry_run:
        print(json.dumps({"fields_summary": summary, "checklist": steps, "notes": notes}, indent=2))
        return 0

    client = jira_client.JiraClient()
    created = client.create_issue(fields)
    key = created.get("key", "")
    cve_store.set_jira_key(str(item["id"]), key)
    print(json.dumps({"jira_key": key, "cve": item["id"], "suggestion": triage["suggestion"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
