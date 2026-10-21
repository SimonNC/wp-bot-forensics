"""Import kibana/dashboard.ndjson into Kibana (overwrites objects with the same ids)."""

from pathlib import Path

from kibana_api import session

NDJSON = Path(__file__).resolve().parents[1] / "kibana" / "dashboard.ndjson"

if __name__ == "__main__":
    if not NDJSON.exists():
        raise SystemExit(f"{NDJSON} not found: run scripts/export_dashboard.py first")
    s, kibana = session()
    with NDJSON.open("rb") as fh:
        resp = s.post(f"{kibana}/api/saved_objects/_import?overwrite=true",
                      files={"file": ("dashboard.ndjson", fh, "application/ndjson")}, timeout=60)
    resp.raise_for_status()
    body = resp.json()
    print(f"success={body['success']} imported={body.get('successCount')}")
    if not body["success"]:
        raise SystemExit(body.get("errors"))
    # Logs are UTC: make Kibana display (and resolve the stored time range) in UTC.
    tz = s.post(f"{kibana}/api/kibana/settings",
                json={"changes": {"dateFormat:tz": "UTC"}}, timeout=30)
    tz.raise_for_status()
    print("dateFormat:tz=UTC")
