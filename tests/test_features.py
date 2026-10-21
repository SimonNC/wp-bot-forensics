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
            "chrome_major": None, "is_internal_ua": False,
            "is_allowlisted": False}
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


def _post(ip, category="xmlrpc", minutes=0, **extra):
    return {"ip_hash": ip, "method": "POST", "path_category": category,
            "timestamp": T0 + timedelta(minutes=minutes), **extra}


def test_campaign_members():
    rows = [_post(f"ip-{i}", user_agent="KitUA/1.0", minutes=i) for i in range(3)]
    rows.append(_post("ip-solo", user_agent="Other/1.0", minutes=90))  # next hour
    rows.append(_post("ip-login", category="login", minutes=5))  # other target
    assert campaign_members(make(rows)) == {"ip-0", "ip-1", "ip-2"}


def test_campaign_survives_rotating_user_agents():
    uas = ["KitUA/1.0", "Mozilla/5.0 Chrome/120.0.0.0", "KitUA/1.0"]
    rows = [_post(f"ip-{i}", user_agent=ua, minutes=10 * i) for i, ua in enumerate(uas)]
    assert campaign_members(make(rows)) == {"ip-0", "ip-1", "ip-2"}


def test_campaign_ignores_verified_crawlers():
    rows = [_post(f"ip-{i}", minutes=i) for i in range(2)]
    rows.append(_post("ip-jetpack", minutes=3, user_agent="Jetpack by WordPress.com",
                      ua_kind="declared_bot", bot_name="Jetpack", as_org="Automattic, Inc"))
    assert campaign_members(make(rows)) == set()
    # A spoofed Jetpack still counts.
    rows.append(_post("ip-fake", minutes=4, ua_kind="declared_bot", bot_name="Jetpack",
                      as_org="Hetzner Online GmbH"))
    assert campaign_members(make(rows)) == {"ip-0", "ip-1", "ip-fake"}


def test_allowlisted_ip_is_true_if_any_request_is_allowlisted():
    assert bool(one(make([{}, {"is_allowlisted": True}]))["allowlisted_ip"])
    assert not one(make([{}, {}]))["allowlisted_ip"]
