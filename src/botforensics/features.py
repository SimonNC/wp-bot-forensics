"""Per-IP behavioural indicators (one row per actor)."""

import pandas as pd

LOCAL_OFFSET = pd.Timedelta(hours=11)  # local time, no daylight saving time
LOGIN_CATEGORIES = ["login", "xmlrpc"]

FEATURE_COLUMNS = ["ip_hash", "n_requests", "first_seen", "last_seen", "peak_rpm",
                   "cv_interarrival", "rate_4xx", "rate_403", "sensitive_probes", "login_posts",
                   "login_posts_10min_max", "in_campaign", "robots_reads", "sitemap_reads",
                   "html_requests", "html_no_referer_ratio", "static_ratio", "night_ratio",
                   "form_posts", "distinct_paths", "distinct_uas", "internal_ua_ratio",
                   "ua_kind", "bot_name", "chrome_major_min", "top_user_agent", "asn", "as_org",
                   "country", "is_datacenter"]


def _login_posts(req: pd.DataFrame) -> pd.DataFrame:
    return req[(req["method"] == "POST") & req["path_category"].isin(LOGIN_CATEGORIES)]


def _peak(ts: pd.Series, window: str) -> int:
    # Fixed windows (floor), simpler to explain than sliding ones.
    return int(ts.dt.floor(window).value_counts().max()) if len(ts) else 0


def _first(series: pd.Series):
    values = series.dropna()
    return values.iat[0] if len(values) else None


def campaign_members(req: pd.DataFrame, min_ips: int = 3, window: str = "1h") -> set[str]:
    """IPs sharing a user-agent on login endpoints with others in the same window."""
    login = _login_posts(req)
    if login.empty:
        return set()
    key = login["user_agent"].fillna("-") + "|" + login["timestamp"].dt.floor(window).astype(str)
    ips_per_key = login.groupby(key)["ip_hash"].nunique()
    hot = ips_per_key[ips_per_key >= min_ips].index
    return set(login.loc[key.isin(hot), "ip_hash"])


def _cv(ts: pd.Series) -> float:
    diffs = ts.diff().dt.total_seconds().dropna()
    if len(diffs) < 3:
        return float("nan")
    if diffs.mean() == 0:
        return 0.0
    return float(diffs.std(ddof=0) / diffs.mean())


def _features_for(ip: str, g: pd.DataFrame, in_campaign: bool) -> dict:
    ts = g["timestamp"]
    status = g["status"]
    cat = g["path_category"]
    login = _login_posts(g)
    html = g[(cat == "html") & (g["method"] == "GET")]
    chrome = g["chrome_major"].dropna()
    uas = g["user_agent"].dropna()
    asn = _first(g["asn"])
    return {
        "ip_hash": ip,
        "n_requests": len(g),
        "first_seen": ts.min(),
        "last_seen": ts.max(),
        "peak_rpm": _peak(ts, "1min"),
        "cv_interarrival": _cv(ts),
        "rate_4xx": float(status.between(400, 499).mean()),
        "rate_403": float((status == 403).mean()),
        "sensitive_probes": int((cat == "sensitive_probe").sum()),
        "login_posts": len(login),
        "login_posts_10min_max": _peak(login["timestamp"], "10min"),
        "in_campaign": in_campaign,
        "robots_reads": int((cat == "robots").sum()),
        "sitemap_reads": int((cat == "sitemap").sum()),
        "html_requests": len(html),
        "html_no_referer_ratio": (
            float(html["referer"].isna().mean()) if len(html) else float("nan")
        ),
        "static_ratio": float((cat == "static").mean()),
        "night_ratio": float(((ts + LOCAL_OFFSET).dt.hour < 6).mean()),
        "form_posts": int(((g["method"] == "POST") & (cat == "form")).sum()),
        "distinct_paths": int(g["path"].nunique()),
        "distinct_uas": int(uas.nunique()),
        "internal_ua_ratio": float(g["is_internal_ua"].mean()),
        "ua_kind": g["ua_kind"].mode().iat[0],
        "bot_name": _first(g["bot_name"]),
        "chrome_major_min": int(chrome.min()) if len(chrome) else None,
        "top_user_agent": uas.mode().iat[0] if len(uas) else None,
        "asn": None if asn is None else int(asn),
        "as_org": _first(g["as_org"]),
        "country": _first(g["country"]),
        "is_datacenter": bool(g["is_datacenter"].iat[0]),
    }


def actor_features(req: pd.DataFrame) -> pd.DataFrame:
    campaign = campaign_members(req)
    rows = [
        _features_for(ip, g.sort_values("timestamp"), ip in campaign)
        for ip, g in req.groupby("ip_hash", sort=False)
    ]
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df["asn"] = df["asn"].astype("Float64")
    df["chrome_major_min"] = df["chrome_major_min"].astype("Float64")
    for col in ("ip_hash", "ua_kind", "bot_name", "top_user_agent", "as_org", "country"):
        df[col] = df[col].astype("string")
    return df
