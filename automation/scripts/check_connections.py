#!/usr/bin/env python3
"""Verify Jira, GitHub and email connections for this SDLC."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib import email_client, github_client, jira_client  # noqa: E402


def main() -> int:
    print("SDLC connection status")
    print(f"  Jira:   {jira_client.connection_status()}")
    print(f"  GitHub: {github_client.connection_status()}")
    print(f"  Email:  {email_client.connection_status()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
