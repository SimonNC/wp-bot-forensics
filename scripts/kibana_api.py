"""Shared Kibana API session (basic auth as elastic, CSRF header)."""

import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from botforensics.config import load_settings  # noqa: E402


def session() -> tuple[requests.Session, str]:
    settings = load_settings()
    s = requests.Session()
    s.auth = ("elastic", settings.elastic_password)
    s.headers["kbn-xsrf"] = "true"
    return s, settings.kibana_url.rstrip("/")
