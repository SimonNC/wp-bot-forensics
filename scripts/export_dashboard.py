"""Export dashboards (with their visualisations and data views) to kibana/dashboard.ndjson."""

import json
from pathlib import Path

from kibana_api import session

OUT = Path(__file__).resolve().parents[1] / "kibana" / "dashboard.ndjson"
# Local user ids and timestamps: not portable, and noisy in diffs.
DROP_KEYS = ("created_by", "updated_by", "created_at", "updated_at")


def _normalise(value):
    """Replace CRLF by LF in every string, descending into embedded JSON strings."""
    if isinstance(value, str):
        if value[:1] in ("{", "["):
            try:
                inner = json.loads(value)
            except ValueError:
                inner = None
            if inner is not None:
                return json.dumps(_normalise(inner), separators=(",", ":"), ensure_ascii=False)
        return value.replace("\r\n", "\n")
    if isinstance(value, dict):
        return {k: _normalise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    return value


def sanitize(obj: dict) -> dict:
    """Drop user/timestamp metadata and normalise line endings of one exported object."""
    obj = {k: v for k, v in obj.items() if k not in DROP_KEYS}
    if "attributes" in obj:
        obj["attributes"] = _normalise(obj["attributes"])
    return obj


if __name__ == "__main__":
    s, kibana = session()
    resp = s.post(f"{kibana}/api/saved_objects/_export",
                  json={"type": ["dashboard"], "includeReferencesDeep": True}, timeout=60)
    resp.raise_for_status()
    objs = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
    if not any(o.get("type") == "dashboard" for o in objs):
        raise SystemExit("no dashboard found in Kibana: build and save one first")
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w", encoding="utf-8", newline="\n") as fh:
        for o in objs:
            fh.write(json.dumps(sanitize(o), ensure_ascii=False) + "\n")
    print(f"{len(objs)} objects -> {OUT}")
