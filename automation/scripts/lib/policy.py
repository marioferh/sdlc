"""Permissions, SLA and release-gate policy helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .config import load_config


DEFAULT_SLA_HOURS = {
    "CRITICAL": 48,
    "HIGH": 168,  # 7 days
    "MEDIUM": 720,  # 30 days
    "LOW": 2160,  # 90 days
}


def policy_cfg() -> dict[str, Any]:
    return (load_config().get("cve") or {}).get("policy") or {}


def sla_hours_for(severity: str) -> int | None:
    cfg = (load_config().get("cve") or {}).get("sla_hours") or {}
    merged = {**DEFAULT_SLA_HOURS, **{k.upper(): int(v) for k, v in cfg.items()}}
    return merged.get(severity.upper())


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(value[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def age_hours(item: dict[str, Any]) -> float | None:
    added = parse_ts(item.get("added_at"))
    if not added:
        return None
    return (datetime.now(timezone.utc) - added).total_seconds() / 3600.0


def sla_breached(item: dict[str, Any]) -> bool:
    sev = str(item.get("severity", "UNKNOWN")).upper()
    limit = sla_hours_for(sev)
    age = age_hours(item)
    if limit is None or age is None:
        return False
    return age > limit


def require_approver_for_accept(severity: str) -> bool:
    """CRITICAL accept-risk requires an approver distinct from actor when enabled."""
    sev = severity.upper()
    cfg = policy_cfg()
    need = {s.upper() for s in (cfg.get("four_eyes_severities") or ["CRITICAL"])}
    return sev in need and bool(cfg.get("require_four_eyes", True))


def can_discard(severity: str, actor: str, approver: str | None = None) -> tuple[bool, str]:
    cfg = policy_cfg()
    restricted = {s.upper() for s in (cfg.get("restricted_discard_severities") or ["CRITICAL"])}
    allowed = set(cfg.get("approvers") or [])
    sev = severity.upper()
    if sev not in restricted:
        return True, "ok"
    if not allowed:
        # No approvers configured → allow but warn via message
        return True, "no approvers configured; allowing"
    if actor in allowed or (approver and approver in allowed):
        return True, "ok"
    return False, f"{sev} discard/accept requires an approver from policy.approvers"


def release_blocking_severities() -> list[str]:
    gate = (load_config().get("cve") or {}).get("release_gate") or {}
    return [s.upper() for s in (gate.get("block_severities") or ["CRITICAL", "HIGH"])]


def release_gate_enabled() -> bool:
    gate = (load_config().get("cve") or {}).get("release_gate") or {}
    return bool(gate.get("enabled", True))
