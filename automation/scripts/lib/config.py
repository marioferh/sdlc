"""Load SDLC automation config and secrets."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[3]
CONFIG_PATH = ROOT / "automation" / "config.yaml"
EXAMPLE_CONFIG_PATH = ROOT / "automation" / "config.example.yaml"
ENV_PATH = ROOT / ".env"
DATA_DIR = ROOT / "data"


def load_env() -> None:
    load_dotenv(ENV_PATH)


def load_config() -> dict[str, Any]:
    load_env()
    path = CONFIG_PATH if CONFIG_PATH.exists() else EXAMPLE_CONFIG_PATH
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def require_env(*keys: str) -> dict[str, str]:
    load_env()
    missing = [k for k in keys if not os.getenv(k)]
    if missing:
        raise SystemExit(
            f"Missing required environment variables: {', '.join(missing)}. "
            f"Copy .env.example to .env and fill them in."
        )
    return {k: os.environ[k] for k in keys}
