# Features

Main capabilities of this SDLC (CVE-first):

1. **Account connections** — Jira, GitHub and email (SMTP) via `.env` + `check_connections.py`
2. **Morning CVE digest** — daily email of pending CVEs with triage hints and SLA breaches
3. **CVE intake** — sync Dependabot advisories; add CVEs manually
4. **Discard / undiscard** — remove false positives from digests (with optional expiry)
5. **Accept risk** — time-bounded exceptions; auto-reopen when they expire
6. **Mark fixed** — close CVEs with optional PR link
7. **Audit log** — who did what (add/discard/accept/fix/triage/jira) in `data/cves/audit.yaml`
8. **Assisted triage** — suggests `fix | mitigate | accept | discard` + checklist
9. **Jira remediation** — open a Task with checklist; auto-link CRITICAL from digest
10. **Release gate** — fail CI/release if CRITICAL/HIGH pending (accepted exceptions allowed)
11. **SLA tracking** — per-severity timers (e.g. CRITICAL 48h, HIGH 7d)
12. **Four-eyes policy** — CRITICAL accept/discard can require an approver
13. **Library change alerts** — email when dependency graph / SBOM changes
14. **CVE metrics dashboard** — aging, MTTR, top packages → `reports/cve-dashboard.md`
15. **Epic / repo trackers** — markdown orchestration for delivery context
