from datetime import UTC, datetime, timedelta

import pandas as pd

from botforensics.enrich import REQUEST_COLUMNS
from botforensics.features import FEATURE_COLUMNS, actor_features, campaign_members

T0 = datetime(2026, 10, 14, 3, 0, tzinfo=UTC)


def make(rows: list[dict]) -> pd.DataFrame:
    base = {"timestamp": T0, "ip_hash": "ip-a", "asn": None, "as_org": None, "country": None,
            "is_datacenter": False, "method": "GET", "path": "/", "path_category": "html",
            "has_query": False, "status": 200, "size": 1, "referer": "https://x/",
            "user_agent": "Mozilla/5.0", "ua_kind": "browser", "bot_name": None,
            "chrome_major": None, "is_internal_ua": False}
    df = pd.DataFrame([{**base, **r} for r in rows], columns=REQUEST_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def one(df):
    return actor_features(df).set_index("ip_hash").loc["ip-a"]


def test_columns():
    assert list(actor_features(make([{}])).columns) == FEATURE_COLUMNS


def test_peak_rpm_and_regular_rhythm():
    df = make([{"timestamp": T0 + timedelta(seconds=2 * i)} for i in range(40)])
    a = one(df)
    assert a["n_requests"] == 40
    assert a["peak_rpm"] == 30
    assert a["cv_interarrival"] == 0.0


def test_cv_nan_when_too_few_requests():
    assert pd.isna(one(make([{}, {"timestamp": T0 + timedelta(seconds=5)}]))["cv_interarrival"])


def test_login_burst_and_probes_and_rates():
    rows = [{"method": "POST", "path": "/xmlrpc.php", "path_category": "xmlrpc", "status": 403,
             "timestamp": T0 + timedelta(seconds=10 * i)} for i in range(12)]
    rows.append({"path": "/.env", "path_category": "sensitive_probe", "status": 404})
    a = one(make(rows))
    assert a["login_posts"] == 12
    assert a["login_posts_10min_max"] == 12
    assert a["sensitive_probes"] == 1
    assert round(a["rate_4xx"], 2) == 1.0
    assert round(a["rate_403"], 2) == round(12 / 13, 2)


def test_referer_static_and_night():
    rows = [
        {"referer": None},
        {"referer": "https://x/"},
        {"path": "/s.css", "path_category": "static"},
        # 14:00 UTC = 01:00 in local → night
        {"timestamp": T0.replace(hour=14)},
    ]
    a = one(make(rows))
    assert a["html_requests"] == 3
    assert round(a["html_no_referer_ratio"], 2) == round(1 / 3, 2)
    assert a["static_ratio"] == 0.25
    assert a["night_ratio"] == 0.25


def test_campaign_members():
    rows = [{"ip_hash": f"ip-{i}", "method": "POST", "path_category": "xmlrpc",
             "user_agent": "KitUA/1.0", "timestamp": T0 + timedelta(minutes=i)} for i in range(3)]
    rows.append({"ip_hash": "ip-solo", "method": "POST", "path_category": "xmlrpc",
                 "user_agent": "Other/1.0"})
    assert campaign_members(make(rows)) == {"ip-0", "ip-1", "ip-2"}
