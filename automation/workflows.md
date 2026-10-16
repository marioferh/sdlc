# Automations

## Epic Status
Jira -> GitHub -> Security -> AI Summary

## CVE Watch
Scanner / Dependabot -> `data/cves/pending.yaml` -> Epic -> Jira Ticket

## Morning CVE digest (email)
1. Sync open Dependabot alerts from watched GitHub repos
2. Filter out discarded CVEs
3. Email pending CVEs to `MAIL_TO`
4. Optionally open Jira tasks for CRITICAL items

```bash
python automation/scripts/cve_digest.py
```

CI: `.github/workflows/daily-cve-digest.yml` (daily ~08:00 Europe/Madrid)

## CVE triage
- Discard: `cve_manage.py discard CVE-… --reason '…'`
- Add manual: `cve_manage.py add CVE-… --manual --severity HIGH`
- Undiscard: `cve_manage.py undiscard CVE-…`

## Library change alerts
Compare GitHub dependency graph / SBOM against `data/libraries/baseline.yaml`, email diffs.

```bash
python automation/scripts/library_watch.py --init   # once
python automation/scripts/library_watch.py          # alert on changes
```

CI: `.github/workflows/library-watch.yml`

## Daily Report
Jira + GitHub + CVEs -> Markdown report
