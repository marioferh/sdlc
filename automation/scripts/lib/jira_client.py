"""Minimal Jira Cloud REST client."""

from __future__ import annotations

import os
from typing import Any

import requests

from .config import require_env


class JiraClient:
    def __init__(self) -> None:
        env = require_env("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN")
        self.base = env["JIRA_BASE_URL"].rstrip("/")
        self.auth = (env["JIRA_EMAIL"], env["JIRA_API_TOKEN"])
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({"Accept": "application/json"})

    def myself(self) -> dict[str, Any]:
        r = self.session.get(f"{self.base}/rest/api/3/myself", timeout=30)
        r.raise_for_status()
        return r.json()

    def search(self, jql: str, fields: list[str] | None = None, max_results: int = 50) -> list[dict]:
        payload = {
            "jql": jql,
            "maxResults": max_results,
            "fields": fields or ["summary", "status", "assignee", "priority", "issuetype"],
        }
        r = self.session.post(f"{self.base}/rest/api/3/search", json=payload, timeout=60)
        r.raise_for_status()
        return r.json().get("issues", [])

    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]:
        r = self.session.post(
            f"{self.base}/rest/api/3/issue",
            json={"fields": fields},
            timeout=60,
        )
        r.raise_for_status()
        return r.json()

    def open_epics(self, project_key: str) -> list[dict]:
        jql = f'project = "{project_key}" AND issuetype = Epic AND statusCategory != Done ORDER BY updated DESC'
        return self.search(jql)


def connection_status() -> str:
    try:
        me = JiraClient().myself()
        return f"ok ({me.get('displayName') or me.get('emailAddress') or os.getenv('JIRA_EMAIL')})"
    except Exception as exc:  # noqa: BLE001 — status helper
        return f"error: {exc}"
