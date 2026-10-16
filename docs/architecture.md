# Architecture

## Systems

| Layer | Role |
|-------|------|
| `trackers/` | Human-readable definitions (Jira, CVEs, libraries, connections) |
| `data/` | Machine state (`cves/*.yaml`, `libraries/baseline.yaml`) |
| `automation/scripts/` | Clients (Jira, GitHub, SMTP) + CLIs |
| `.github/workflows/` | Scheduled morning digest and library watch |

## Data flow

```
GitHub Dependabot ──► cve_digest / cve_store ──► pending.yaml
                              │
                              ├──► morning email (MAIL_TO)
                              └──► Jira Task (CRITICAL)

GitHub SBOM/deps  ──► library_watch ──► baseline.yaml
                              └──► email on version/new/removed deps

Operator CLI      ──► cve_manage (add / discard / undiscard)
```

## Repositories

List watched repos in `automation/config.yaml` → `github.repositories`.
