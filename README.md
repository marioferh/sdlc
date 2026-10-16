# SDLC

A lightweight SDLC focused on project orchestration instead of documentation.

## Goals

- Track Jira epics and stories
- Track repositories involved in each epic
- Track CVEs affecting delivery (digest, discard, manual add)
- Alert on library / dependency changes
- Produce AI summaries
- Keep project context in one place

## Quick start

```bash
cp .env.example .env
cp automation/config.example.yaml automation/config.yaml
# fill Jira, GitHub and SMTP credentials
pip install -r automation/requirements.txt
python automation/scripts/check_connections.py
```

### Morning CVE email

```bash
python automation/scripts/cve_digest.py --dry-run
python automation/scripts/cve_digest.py
```

### Discard / add CVEs

```bash
python automation/scripts/cve_manage.py discard CVE-2024-1234 --reason "not applicable"
python automation/scripts/cve_manage.py add CVE-2024-9999 --manual --severity HIGH --package foo
```

### Library change alerts

```bash
python automation/scripts/library_watch.py --init
python automation/scripts/library_watch.py
```

## Structure

- `docs/` — project documentation
- `trackers/` — integration definitions (incl. connections, libraries)
- `data/` — CVE store + library baselines
- `epics/` — one folder per epic
- `ai/` — prompts and context
- `automation/` — workflows, config example, Python scripts
- `templates/` — reusable templates
- `.github/workflows/` — scheduled digests and library watch
