# Library Tracker

Watch dependency changes across repositories configured in `automation/config.yaml`.

## What is tracked

- New dependencies
- Version bumps
- Removed dependencies

Baseline: `data/libraries/baseline.yaml`

## Commands

```bash
# First run: capture baseline (no alert)
python automation/scripts/library_watch.py --init

# Detect changes and email you
python automation/scripts/library_watch.py

# Print only
python automation/scripts/library_watch.py --dry-run
```

CI: `.github/workflows/library-watch.yml` (twice daily).
