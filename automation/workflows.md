# Automations

## Epic Status
Jira -> GitHub -> Security -> AI Summary

## CVE Watch
Scanner / Dependabot -> pending store -> triage -> Jira / fix / accept

## Morning CVE digest (email)
1. Expire accepted/discarded exceptions past `expires_at`
2. Sync Dependabot alerts
3. Email pending CVEs + SLA breaches + triage hints
4. Optionally open Jira for CRITICAL

```bash
python automation/scripts/cve_digest.py
```

CI: `.github/workflows/daily-cve-digest.yml`

## Triage & remediation
```bash
python automation/scripts/cve_triage.py --apply
python automation/scripts/cve_remediate.py CVE-XXXX
```

## Release gate
```bash
python automation/scripts/release_gate.py   # exit 2 if blocking CVEs
```

## Metrics
```bash
python automation/scripts/cve_metrics.py --write --email
```

CI: `.github/workflows/weekly-cve-metrics.yml`

## Library change alerts
```bash
python automation/scripts/library_watch.py --init
python automation/scripts/library_watch.py
```

CI: `.github/workflows/library-watch.yml`
