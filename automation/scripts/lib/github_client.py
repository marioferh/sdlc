"""Minimal GitHub REST client (personal account / org)."""

from __future__ import annotations

import os
from typing import Any

import requests

from .config import require_env


class GitHubClient:
    def __init__(self) -> None:
        env = require_env("GITHUB_TOKEN")
        self.token = env["GITHUB_TOKEN"]
        self.user = os.getenv("GITHUB_USER", "")
        self.org = os.getenv("GITHUB_ORG", "")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def myself(self) -> dict[str, Any]:
        r = self.session.get("https://api.github.com/user", timeout=30)
        r.raise_for_status()
        return r.json()

    def dependabot_alerts(self, owner: str, repo: str, state: str = "open") -> list[dict]:
        url = f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts"
        r = self.session.get(url, params={"state": state, "per_page": 100}, timeout=60)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json()

    def dependency_manifest(self, owner: str, repo: str) -> list[dict]:
        """Best-effort: list dependency graph snapshots via SBOM if available."""
        url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
        r = self.session.get(url, timeout=60)
        if r.status_code in (404, 403):
            return []
        r.raise_for_status()
        sbom = r.json().get("sbom", {})
        return sbom.get("packages", [])

    def compare_commits(self, owner: str, repo: str, base: str, head: str) -> dict[str, Any]:
        url = f"https://api.github.com/repos/{owner}/{repo}/compare/{base}...{head}"
        r = self.session.get(url, timeout=60)
        r.raise_for_status()
        return r.json()


def connection_status() -> str:
    try:
        me = GitHubClient().myself()
        login = me.get("login") or os.getenv("GITHUB_USER")
        return f"ok (@{login})"
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"
