"""Append-only audit log for CVE and security actions."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import DATA_DIR

AUDIT_PATH = DATA_DIR / "cves" / "audit.yaml"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_actor() -> str:
    return os.getenv("SDLC_ACTOR") or os.getenv("JIRA_EMAIL") or os.getenv("USER") or "unknown"


def log(action: str, cve_id: str = "", *, actor: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
    entry = {
        "at": _now(),
        "actor": actor or default_actor(),
        "action": action,
        "cve_id": (cve_id or "").upper(),
        "details": details or {},
    }
    data: dict[str, Any] = {"entries": []}
    if AUDIT_PATH.exists():
        with AUDIT_PATH.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {"entries": []}
    data.setdefault("entries", [])
    data["entries"].append(entry)
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)
    return entry


def list_entries(cve_id: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    if not AUDIT_PATH.exists():
        return []
    with AUDIT_PATH.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    entries = list(data.get("entries") or [])
    if cve_id:
        cid = cve_id.upper()
        entries = [e for e in entries if str(e.get("cve_id", "")).upper() == cid]
    if limit is not None:
        entries = entries[-limit:]
    return entries
