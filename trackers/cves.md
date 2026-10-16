# CVE Tracker

## Lifecycle

`pending` → (`accepted` | `discarded` | `fixed`)

| Store | Meaning |
|-------|---------|
| `data/cves/pending.yaml` | Open / awaiting triage (digest + release gate) |
| `data/cves/accepted.yaml` | Risk accepted until `expires_at` |
| `data/cves/discarded.yaml` | False positive / N/A |
| `data/cves/fixed.yaml` | Remediated |
| `data/cves/manual.yaml` | Manually sourced entries |
| `data/cves/audit.yaml` | Who/when/what for every action |

Critical CVEs should block release (`release_gate.py`).

## Commands

```bash
python automation/scripts/cve_manage.py list
python automation/scripts/cve_triage.py
python automation/scripts/cve_remediate.py CVE-XXXX
python automation/scripts/cve_manage.py accept CVE-XXXX --reason "..." --expires-days 30 --approver you@example.com
python automation/scripts/cve_manage.py fix CVE-XXXX --pr URL
python automation/scripts/cve_manage.py expire
python automation/scripts/cve_manage.py audit --cve-id CVE-XXXX
python automation/scripts/release_gate.py
python automation/scripts/cve_metrics.py --write
```

## SLA (default)

| Severity | Hours |
|----------|------:|
| CRITICAL | 48 |
| HIGH | 168 (7d) |
| MEDIUM | 720 (30d) |
| LOW | 2160 (90d) |

Configurable in `automation/config.yaml` → `cve.sla_hours`.
