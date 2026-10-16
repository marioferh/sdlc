"""YAML-backed CVE store: pending, discarded, accepted, fixed, manual."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from . import audit
from .config import DATA_DIR
from .policy import can_discard, parse_ts, require_approver_for_accept

CVE_DIR = DATA_DIR / "cves"
FILES = {
    "pending": CVE_DIR / "pending.yaml",
    "discarded": CVE_DIR / "discarded.yaml",
    "accepted": CVE_DIR / "accepted.yaml",
    "fixed": CVE_DIR / "fixed.yaml",
    "manual": CVE_DIR / "manual.yaml",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"items": []}
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    data.setdefault("items", [])
    return data


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)


def list_items(bucket: str) -> list[dict[str, Any]]:
    return list(_read(FILES[bucket])["items"])


def find_cve(cve_id: str) -> tuple[str, dict[str, Any]] | None:
    cid = cve_id.upper()
    for bucket, path in FILES.items():
        for item in _read(path)["items"]:
            if str(item.get("id", "")).upper() == cid:
                return bucket, item
    return None


def _remove_from(buckets: tuple[str, ...], cve_id: str) -> None:
    cid = cve_id.upper()
    for b in buckets:
        data = _read(FILES[b])
        data["items"] = [i for i in data["items"] if str(i.get("id", "")).upper() != cid]
        _write(FILES[b], data)


def _update_fields(bucket: str, cve_id: str, **fields: Any) -> dict[str, Any]:
    cid = cve_id.upper()
    data = _read(FILES[bucket])
    for i, item in enumerate(data["items"]):
        if str(item.get("id", "")).upper() == cid:
            item = {**item, **fields, "updated_at": _now()}
            data["items"][i] = item
            _write(FILES[bucket], data)
            return item
    raise ValueError(f"{cid} not found in {bucket}")


def add_cve(
    cve_id: str,
    *,
    severity: str = "UNKNOWN",
    package: str = "",
    repository: str = "",
    epic: str = "",
    notes: str = "",
    manual: bool = False,
    source: str = "manual",
    actor: str | None = None,
) -> dict[str, Any]:
    cid = cve_id.upper()
    existing = find_cve(cid)
    if existing:
        bucket, _item = existing
        if bucket in ("discarded", "accepted", "fixed"):
            raise ValueError(f"{cid} is in {bucket}. Reopen/undiscard before adding.")
        raise ValueError(f"{cid} already exists in {bucket}.")

    item = {
        "id": cid,
        "severity": severity.upper(),
        "package": package,
        "repository": repository,
        "epic": epic,
        "status": "pending",
        "source": source if not manual else "manual",
        "notes": notes,
        "added_at": _now(),
        "updated_at": _now(),
        "jira_key": "",
        "triage": {},
    }
    bucket = "manual" if manual else "pending"
    data = _read(FILES[bucket])
    data["items"].append(item)
    _write(FILES[bucket], data)

    if manual:
        pending = _read(FILES["pending"])
        if not any(str(i.get("id", "")).upper() == cid for i in pending["items"]):
            pending["items"].append({**item, "status": "pending"})
            _write(FILES["pending"], pending)

    audit.log("add", cid, actor=actor, details={"severity": item["severity"], "manual": manual, "source": item["source"]})
    return item


def discard_cve(
    cve_id: str,
    reason: str = "",
    *,
    actor: str | None = None,
    approver: str | None = None,
    expires: str | None = None,
) -> dict[str, Any]:
    cid = cve_id.upper()
    found = find_cve(cid)
    if not found:
        raise ValueError(f"{cid} not found.")
    bucket, item = found
    if bucket == "discarded":
        raise ValueError(f"{cid} already discarded.")

    who = actor or audit.default_actor()
    ok, msg = can_discard(str(item.get("severity", "")), who, approver)
    if not ok:
        raise ValueError(msg)

    _remove_from(("pending", "manual", "accepted"), cid)
    discarded = {
        **item,
        "status": "discarded",
        "discard_reason": reason,
        "discarded_at": _now(),
        "updated_at": _now(),
        "discarded_by": who,
        "approver": approver or "",
        "expires_at": expires or "",
    }
    data = _read(FILES["discarded"])
    data["items"].append(discarded)
    _write(FILES["discarded"], data)
    audit.log(
        "discard",
        cid,
        actor=who,
        details={"reason": reason, "approver": approver or "", "expires_at": expires or ""},
    )
    return discarded


def undiscard_cve(cve_id: str, *, actor: str | None = None) -> dict[str, Any]:
    cid = cve_id.upper()
    data = _read(FILES["discarded"])
    match = next((i for i in data["items"] if str(i.get("id", "")).upper() == cid), None)
    if not match:
        raise ValueError(f"{cid} is not in discarded.")
    data["items"] = [i for i in data["items"] if str(i.get("id", "")).upper() != cid]
    _write(FILES["discarded"], data)

    restored = {**match, "status": "pending", "updated_at": _now()}
    for key in ("discard_reason", "discarded_at", "discarded_by", "approver", "expires_at"):
        restored.pop(key, None)
    pending = _read(FILES["pending"])
    pending["items"].append(restored)
    _write(FILES["pending"], pending)
    audit.log("undiscard", cid, actor=actor)
    return restored


def accept_cve(
    cve_id: str,
    reason: str,
    expires_days: int,
    *,
    actor: str | None = None,
    approver: str | None = None,
) -> dict[str, Any]:
    """Accept risk for a limited time; excluded from release gate until expiry."""
    cid = cve_id.upper()
    found = find_cve(cid)
    if not found:
        raise ValueError(f"{cid} not found.")
    bucket, item = found
    if bucket == "accepted":
        raise ValueError(f"{cid} already accepted.")
    if bucket == "fixed":
        raise ValueError(f"{cid} is fixed; reopen before accepting risk.")

    who = actor or audit.default_actor()
    sev = str(item.get("severity", "")).upper()
    ok, msg = can_discard(sev, who, approver)
    if not ok:
        raise ValueError(msg)
    if require_approver_for_accept(sev) and not approver:
        raise ValueError(f"{sev} accept-risk requires --approver (four-eyes).")

    expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _remove_from(("pending", "manual", "discarded"), cid)
    accepted = {
        **item,
        "status": "accepted",
        "accept_reason": reason,
        "accepted_at": _now(),
        "expires_at": expires_at,
        "accepted_by": who,
        "approver": approver or "",
        "updated_at": _now(),
    }
    data = _read(FILES["accepted"])
    data["items"].append(accepted)
    _write(FILES["accepted"], data)
    audit.log(
        "accept",
        cid,
        actor=who,
        details={"reason": reason, "expires_at": expires_at, "approver": approver or "", "days": expires_days},
    )
    return accepted


def fix_cve(
    cve_id: str,
    *,
    notes: str = "",
    pr_url: str = "",
    actor: str | None = None,
) -> dict[str, Any]:
    cid = cve_id.upper()
    found = find_cve(cid)
    if not found:
        raise ValueError(f"{cid} not found.")
    _bucket, item = found
    _remove_from(("pending", "manual", "discarded", "accepted"), cid)
    fixed = {
        **item,
        "status": "fixed",
        "fix_notes": notes,
        "pr_url": pr_url,
        "fixed_at": _now(),
        "fixed_by": actor or audit.default_actor(),
        "updated_at": _now(),
    }
    data = _read(FILES["fixed"])
    data["items"].append(fixed)
    _write(FILES["fixed"], data)
    audit.log("fix", cid, actor=actor, details={"notes": notes, "pr_url": pr_url})
    return fixed


def set_jira_key(cve_id: str, jira_key: str, *, actor: str | None = None) -> dict[str, Any]:
    found = find_cve(cve_id)
    if not found:
        raise ValueError(f"{cve_id} not found.")
    bucket, _item = found
    item = _update_fields(bucket, cve_id, jira_key=jira_key)
    # Keep pending mirror in sync if dual-homed
    if bucket == "manual":
        try:
            _update_fields("pending", cve_id, jira_key=jira_key)
        except ValueError:
            pass
    audit.log("link_jira", cve_id.upper(), actor=actor, details={"jira_key": jira_key})
    return item


def set_triage(cve_id: str, triage: dict[str, Any], *, actor: str | None = None) -> dict[str, Any]:
    found = find_cve(cve_id)
    if not found:
        raise ValueError(f"{cve_id} not found.")
    bucket, _item = found
    item = _update_fields(bucket, cve_id, triage=triage)
    if bucket == "manual":
        try:
            _update_fields("pending", cve_id, triage=triage)
        except ValueError:
            pass
    audit.log("triage", cve_id.upper(), actor=actor, details=triage)
    return item


def expire_exceptions(*, actor: str | None = None) -> list[dict[str, Any]]:
    """Move expired accepted/discarded-with-expiry back to pending."""
    now = datetime.now(timezone.utc)
    reinstated: list[dict[str, Any]] = []

    for bucket in ("accepted", "discarded"):
        data = _read(FILES[bucket])
        keep: list[dict[str, Any]] = []
        for item in data["items"]:
            expires = parse_ts(item.get("expires_at"))
            if expires and expires <= now:
                restored = {
                    **item,
                    "status": "pending",
                    "updated_at": _now(),
                    "reopened_reason": f"exception expired ({item.get('expires_at')})",
                }
                for key in (
                    "accept_reason",
                    "accepted_at",
                    "accepted_by",
                    "discard_reason",
                    "discarded_at",
                    "discarded_by",
                    "approver",
                    "expires_at",
                ):
                    restored.pop(key, None)
                pending = _read(FILES["pending"])
                pending["items"].append(restored)
                _write(FILES["pending"], pending)
                audit.log(
                    "expire_exception",
                    str(item.get("id", "")),
                    actor=actor or "system",
                    details={"from": bucket},
                )
                reinstated.append(restored)
            else:
                keep.append(item)
        data["items"] = keep
        _write(FILES[bucket], data)
    return reinstated


def pending_for_digest(severities: list[str] | None = None) -> list[dict[str, Any]]:
    items = list_items("pending")
    excluded = set()
    for b in ("discarded", "accepted", "fixed"):
        excluded |= {str(i.get("id", "")).upper() for i in list_items(b)}
    items = [i for i in items if str(i.get("id", "")).upper() not in excluded]
    if severities:
        allowed = {s.upper() for s in severities}
        items = [i for i in items if str(i.get("severity", "UNKNOWN")).upper() in allowed]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return sorted(items, key=lambda i: (order.get(str(i.get("severity", "UNKNOWN")).upper(), 9), i.get("id", "")))


def blocking_for_release(severities: list[str]) -> list[dict[str, Any]]:
    """Pending CVEs that block release (accepted exceptions do not block)."""
    allowed = {s.upper() for s in severities}
    pending = pending_for_digest(None)
    return [i for i in pending if str(i.get("severity", "UNKNOWN")).upper() in allowed]


def upsert_from_scanner(item: dict[str, Any]) -> None:
    cid = str(item.get("id", "")).upper()
    if not cid:
        return
    if find_cve(cid):
        return
    add_cve(
        cid,
        severity=str(item.get("severity", "UNKNOWN")),
        package=str(item.get("package", "")),
        repository=str(item.get("repository", "")),
        epic=str(item.get("epic", "")),
        notes=str(item.get("notes", "")),
        manual=False,
        source=str(item.get("source", "scanner")),
        actor="scanner",
    )
