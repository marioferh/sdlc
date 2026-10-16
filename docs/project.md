# Project

## Purpose

Lightweight SDLC for project orchestration: Jira epics, GitHub repos, CVEs and dependency changes in one place.

## Stack

- Markdown trackers + YAML data stores
- Python automation (`automation/scripts`)
- GitHub Actions for scheduled digests and library watch

## Teams

## Environments

## Integrations

- **Jira** — epics/stories; critical CVE tickets (`JIRA_*`)
- **GitHub** — repos, Dependabot alerts, dependency graph (`GITHUB_*`)
- **Email** — morning CVE digest + library alerts (`SMTP_*`, `MAIL_*`)
- Security scanners (optional feed into CVE store)

Setup: `trackers/connections.md`
