# Connections

Link this SDLC to your accounts. Secrets go in `.env` (local) or GitHub Actions secrets (CI).

## Setup

1. Copy `.env.example` → `.env`
2. Copy `automation/config.example.yaml` → `automation/config.yaml`
3. Fill Jira, GitHub and SMTP values
4. Verify:

```bash
pip install -r automation/requirements.txt
python automation/scripts/check_connections.py
```

## Jira

| Variable | Purpose |
|----------|---------|
| `JIRA_BASE_URL` | e.g. `https://your-org.atlassian.net` |
| `JIRA_EMAIL` | Your Atlassian account email |
| `JIRA_API_TOKEN` | [API token](https://id.atlassian.com/manage-profile/security/api-tokens) |

Used for: epic/status sync, opening tasks for critical CVEs from the morning digest.

## GitHub

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | PAT with `repo` + `security_events` (Dependabot alerts) |
| `GITHUB_USER` | Your GitHub username |
| `GITHUB_ORG` | Optional org |

Configure watched repos under `github.repositories` in `automation/config.yaml`.

## Email

| Variable | Purpose |
|----------|---------|
| `SMTP_*` | SMTP host/port/user/password |
| `MAIL_FROM` / `MAIL_TO` | Sender and your inbox |

Used for: morning CVE digest and library-change alerts.
