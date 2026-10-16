#!/usr/bin/env python3
"""Detect library/dependency changes across watched GitHub repositories and alert by email."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib.config import DATA_DIR, load_config  # noqa: E402
from scripts.lib import email_client, github_client  # noqa: E402

BASELINE_PATH = DATA_DIR / "libraries" / "baseline.yaml"


def _pkg_key(pkg: dict) -> str:
    name = pkg.get("name") or pkg.get("SPDXID") or "unknown"
    version = ""
    for ref in pkg.get("externalRefs") or []:
        if ref.get("referenceType") == "purl":
            purl = ref.get("referenceLocator") or ""
            if "@" in purl:
                version = purl.rsplit("@", 1)[-1]
            break
    if not version:
        version = str(pkg.get("versionInfo") or "")
    return f"{name}@{version}" if version else name


def snapshot_repo(gh: github_client.GitHubClient, owner: str, name: str) -> dict[str, str]:
    packages = gh.dependency_manifest(owner, name)
    snap: dict[str, str] = {}
    for pkg in packages:
        # Skip the root document package
        if pkg.get("SPDXID") == "SPDXRef-Document":
            continue
        key = pkg.get("name") or pkg.get("SPDXID")
        if not key:
            continue
        snap[str(key)] = _pkg_key(pkg)
    return snap


def diff_snapshots(old: dict[str, str], new: dict[str, str]) -> list[str]:
    changes: list[str] = []
    for name, ver in new.items():
        if name not in old:
            changes.append(f"+ new dependency: {ver}")
        elif old[name] != ver:
            changes.append(f"~ version bump: {old[name]} -> {ver}")
    for name, ver in old.items():
        if name not in new:
            changes.append(f"- removed dependency: {ver}")
    return changes


def load_baseline() -> dict:
    if not BASELINE_PATH.exists():
        return {"repositories": {}}
    with BASELINE_PATH.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    data.setdefault("repositories", {})
    return data


def save_baseline(data: dict) -> None:
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with BASELINE_PATH.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch library/dependency changes")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--init", action="store_true", help="Write baseline without alerting")
    parser.add_argument("--no-email", action="store_true")
    args = parser.parse_args()

    cfg = load_config()
    repos = (cfg.get("github") or {}).get("repositories") or []
    if not repos:
        print("No repositories configured in automation/config.yaml (github.repositories).", file=sys.stderr)
        return 1

    gh = github_client.GitHubClient()
    baseline = load_baseline()
    all_changes: list[str] = []

    for repo in repos:
        owner, name = repo["owner"], repo["name"]
        key = f"{owner}/{name}"
        print(f"scanning {key}...")
        try:
            snap = snapshot_repo(gh, owner, name)
        except Exception as exc:  # noqa: BLE001
            print(f"  skip: {exc}", file=sys.stderr)
            continue

        if not snap:
            print(f"  no SBOM/dependency graph available for {key}")
            continue

        previous = (baseline["repositories"].get(key) or {}).get("packages") or {}
        if args.init or not previous:
            baseline["repositories"][key] = {"packages": snap}
            print(f"  baseline set ({len(snap)} packages)")
            continue

        changes = diff_snapshots(previous, snap)
        baseline["repositories"][key] = {"packages": snap}
        if changes:
            all_changes.append(f"## {key}")
            all_changes.extend(f"  {c}" for c in changes)
            all_changes.append("")
            print(f"  {len(changes)} change(s)")
        else:
            print("  no changes")

    save_baseline(baseline)

    if args.init:
        print("baseline initialized")
        return 0

    if not all_changes:
        print("no library changes detected")
        return 0

    prefix = (cfg.get("email") or {}).get("subject_prefix") or "[SDLC]"
    subject = f"{prefix} Library changes detected"
    body = "SDLC library watch\n\n" + "\n".join(all_changes)
    body += "\nRepos baseline: data/libraries/baseline.yaml\n"

    if args.dry_run or args.no_email:
        print(subject)
        print(body)
    else:
        email_client.send_mail(subject, body)
        print("library change alert emailed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
