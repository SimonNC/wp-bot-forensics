"""Shared Kibana API session (basic auth as elastic, CSRF header)."""

import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from botforensics.config import load_settings  # noqa: E402


def session() -> tuple[requests.Session, str]:
    settings = load_settings(str(ROOT / ".env"))
    if not settings.elastic_password:
        raise SystemExit("ELASTIC_PASSWORD is empty: set it in .env")
    s = requests.Session()
    s.auth = ("elastic", settings.elastic_password)
    s.headers["kbn-xsrf"] = "true"
    return s, settings.kibana_url.rstrip("/")
