# CVE Tracker

Track:
- CVE ID
- Severity
- Package
- Repository
- Epic
- Mitigation
- Status (`pending` | `discarded` | `manual`)

Critical CVEs should block release.

## Store

| File | Meaning |
|------|---------|
| `data/cves/pending.yaml` | Open / awaiting triage (included in morning digest) |
| `data/cves/discarded.yaml` | Discarded (false positive, N/A, accepted risk) |
| `data/cves/manual.yaml` | Manually added entries |

## Morning digest

Every morning (CI cron or local), sync Dependabot advisories from GitHub, then email pending CVEs:

```bash
python automation/scripts/cve_digest.py --dry-run
python automation/scripts/cve_digest.py
```

## Discard / add manually

```bash
# List
python automation/scripts/cve_manage.py list

# Discard (excluded from digests)
python automation/scripts/cve_manage.py discard CVE-2024-1234 --reason "not reachable"

# Add manually
python automation/scripts/cve_manage.py add CVE-2024-9999 --manual --severity HIGH \
  --package lodash --repository org/api --notes "found in audit"

# Restore discarded
python automation/scripts/cve_manage.py undiscard CVE-2024-1234
```
