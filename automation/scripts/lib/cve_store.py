"""YAML-backed CVE store: pending, discarded, manual."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import DATA_DIR

CVE_DIR = DATA_DIR / "cves"
FILES = {
    "pending": CVE_DIR / "pending.yaml",
    "discarded": CVE_DIR / "discarded.yaml",
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
) -> dict[str, Any]:
    cid = cve_id.upper()
    existing = find_cve(cid)
    if existing:
        bucket, item = existing
        if bucket == "discarded":
            raise ValueError(f"{cid} is discarded. Undiscard first or remove from discarded.yaml.")
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
    }
    bucket = "manual" if manual else "pending"
    data = _read(FILES[bucket])
    data["items"].append(item)
    _write(FILES[bucket], data)

    # Keep a mirror in pending when added as manual so digests include it
    if manual:
        pending = _read(FILES["pending"])
        if not any(str(i.get("id", "")).upper() == cid for i in pending["items"]):
            pending["items"].append({**item, "status": "pending"})
            _write(FILES["pending"], pending)
    return item


def discard_cve(cve_id: str, reason: str = "") -> dict[str, Any]:
    cid = cve_id.upper()
    found = find_cve(cid)
    if not found:
        raise ValueError(f"{cid} not found.")
    bucket, item = found
    if bucket == "discarded":
        raise ValueError(f"{cid} already discarded.")

    # Remove from source bucket(s)
    for b in ("pending", "manual"):
        data = _read(FILES[b])
        data["items"] = [i for i in data["items"] if str(i.get("id", "")).upper() != cid]
        _write(FILES[b], data)

    discarded = {**item, "status": "discarded", "discard_reason": reason, "discarded_at": _now(), "updated_at": _now()}
    data = _read(FILES["discarded"])
    data["items"].append(discarded)
    _write(FILES["discarded"], data)
    return discarded


def undiscard_cve(cve_id: str) -> dict[str, Any]:
    cid = cve_id.upper()
    data = _read(FILES["discarded"])
    match = next((i for i in data["items"] if str(i.get("id", "")).upper() == cid), None)
    if not match:
        raise ValueError(f"{cid} is not in discarded.")
    data["items"] = [i for i in data["items"] if str(i.get("id", "")).upper() != cid]
    _write(FILES["discarded"], data)

    restored = {**match, "status": "pending", "updated_at": _now()}
    restored.pop("discard_reason", None)
    restored.pop("discarded_at", None)
    pending = _read(FILES["pending"])
    pending["items"].append(restored)
    _write(FILES["pending"], pending)
    return restored


def pending_for_digest(severities: list[str] | None = None) -> list[dict[str, Any]]:
    items = list_items("pending")
    discarded_ids = {str(i.get("id", "")).upper() for i in list_items("discarded")}
    items = [i for i in items if str(i.get("id", "")).upper() not in discarded_ids]
    if severities:
        allowed = {s.upper() for s in severities}
        items = [i for i in items if str(i.get("severity", "UNKNOWN")).upper() in allowed]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return sorted(items, key=lambda i: (order.get(str(i.get("severity", "UNKNOWN")).upper(), 9), i.get("id", "")))


def upsert_from_scanner(item: dict[str, Any]) -> None:
    """Add scanner findings into pending unless discarded or already present."""
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
    )
