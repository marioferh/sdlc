# SDLC

A lightweight SDLC focused on project orchestration — especially **CVE operations** — instead of heavy documentation.

See [FEATURES.md](FEATURES.md) for the full capability list.

## Quick start

```bash
cp .env.example .env
cp automation/config.example.yaml automation/config.yaml
# fill Jira, GitHub and SMTP credentials + watched repos
pip install -r automation/requirements.txt
python automation/scripts/check_connections.py
```

## CVE ops cheatsheet

```bash
# Morning digest (dry-run)
python automation/scripts/cve_digest.py --dry-run --no-sync

# Triage suggestions
python automation/scripts/cve_triage.py
python automation/scripts/cve_triage.py CVE-2024-1234 --apply

# Add / discard / accept / fix
python automation/scripts/cve_manage.py add CVE-2024-9999 --manual --severity HIGH --package foo --repository org/api
python automation/scripts/cve_manage.py discard CVE-2024-1234 --reason "not reachable"
python automation/scripts/cve_manage.py accept CVE-2024-1234 --reason "change freeze" --expires-days 14 --approver you@example.com
python automation/scripts/cve_manage.py fix CVE-2024-1234 --pr https://github.com/org/api/pull/1

# Open Jira remediation checklist
python automation/scripts/cve_remediate.py CVE-2024-1234 --dry-run

# Block release if CRITICAL/HIGH pending
python automation/scripts/release_gate.py

# Metrics dashboard
python automation/scripts/cve_metrics.py --write

# Library changes
python automation/scripts/library_watch.py --init
python automation/scripts/library_watch.py --dry-run
```

## Structure

- `docs/` — project documentation
- `trackers/` — integration definitions
- `data/cves/` — pending / accepted / discarded / fixed + audit log
- `data/libraries/` — dependency baselines
- `reports/` — generated CVE dashboard
- `epics/` — one folder per epic
- `ai/` — prompts and context
- `automation/` — config example + Python scripts
- `templates/` — reusable templates
- `.github/workflows/` — daily digest, library watch, weekly metrics
