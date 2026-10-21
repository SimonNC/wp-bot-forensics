"""Create the Kibana data views (what Kibana calls the 'tables' it can chart)."""

from kibana_api import session

DATA_VIEWS = [
    ("weblogs-requests", "Web requests", "@timestamp"),
    ("weblogs-actors", "Actors (one per IP)", "last_seen"),
    ("cerber-events", "WP Cerber events", "@timestamp"),
]

if __name__ == "__main__":
    s, kibana = session()
    for view_id, name, time_field in DATA_VIEWS:
        resp = s.post(f"{kibana}/api/data_views/data_view", json={
            "data_view": {"id": view_id, "title": view_id, "name": name,
                          "timeFieldName": time_field},
            "override": True,
        }, timeout=30)
        resp.raise_for_status()
        print(f"data view {view_id}: ok")
