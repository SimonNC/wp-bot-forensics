"""Export dashboards (with their visualisations and data views) to kibana/dashboard.ndjson."""

from pathlib import Path

from kibana_api import session

OUT = Path(__file__).resolve().parents[1] / "kibana" / "dashboard.ndjson"

if __name__ == "__main__":
    s, kibana = session()
    resp = s.post(f"{kibana}/api/saved_objects/_export",
                  json={"type": ["dashboard"], "includeReferencesDeep": True}, timeout=60)
    resp.raise_for_status()
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(resp.text, encoding="utf-8")
    print(f"{len(resp.text.splitlines())} objects -> {OUT}")
