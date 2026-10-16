# Jira Tracker

Connect with `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` (see `trackers/connections.md`).

Collect:
- Epics
- Stories
- Tasks
- Bugs
- Blockers

Output:
- Daily summary
- Sprint summary
- Epic health

Automation:
- Morning CVE digest can open Tasks for CRITICAL items (`cve_digest.py`)
- Verify: `python automation/scripts/check_connections.py`
