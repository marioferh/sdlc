# Architecture

## Systems

| Layer | Role |
|-------|------|
| `trackers/` | Human-readable definitions (Jira, CVEs, libraries, connections) |
| `data/cves/` | pending / accepted / discarded / fixed + audit log |
| `data/libraries/` | dependency baselines |
| `reports/` | generated CVE dashboard / metrics |
| `automation/scripts/` | clients + CVE ops CLIs |
| `.github/workflows/` | digest, library watch, weekly metrics |

## CVE data flow

```
Dependabot / manual add ──► pending.yaml
                              │
                              ├── triage (fix|mitigate|accept|discard)
                              ├── digest email (+ SLA breaches)
                              ├── remediate → Jira Task + checklist
                              ├── accept → accepted.yaml (expires)
                              ├── discard → discarded.yaml
                              └── fix → fixed.yaml
                                        │
release_gate ◄── blocks CRITICAL/HIGH still pending
metrics/dashboard ◄── aging, MTTR, audit trail
```
