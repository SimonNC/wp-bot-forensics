"""Export dashboards (with their visualisations and data views) to kibana/dashboard.ndjson."""

import json
from pathlib import Path

from kibana_api import session

OUT = Path(__file__).resolve().parents[1] / "kibana" / "dashboard.ndjson"

if __name__ == "__main__":
    s, kibana = session()
    resp = s.post(f"{kibana}/api/saved_objects/_export",
                  json={"type": ["dashboard"], "includeReferencesDeep": True}, timeout=60)
    resp.raise_for_status()
    lines = [ln for ln in resp.text.splitlines() if ln.strip()]
    if not any(json.loads(ln).get("type") == "dashboard" for ln in lines):
        raise SystemExit("no dashboard found in Kibana: build and save one first")
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_bytes(resp.content)
    print(f"{len(lines)} objects -> {OUT}")
