# Integrations

## Connected accounts

| System | Auth | Status check |
|--------|------|--------------|
| Jira | `JIRA_BASE_URL` + `JIRA_EMAIL` + `JIRA_API_TOKEN` | `python automation/scripts/check_connections.py` |
| GitHub | `GITHUB_TOKEN` (+ `GITHUB_USER` / `GITHUB_ORG`) | same |
| Email | SMTP (`SMTP_*`, `MAIL_FROM`, `MAIL_TO`) | same |

See `trackers/connections.md` and `.env.example`.

## Security / scanners

- GitHub Dependabot alerts (synced into CVE pending store)
- Trivy / Grype / osv.dev (optional; feed via `cve_manage.py add`)

## Optional

- Slack or Teams (not wired yet)
