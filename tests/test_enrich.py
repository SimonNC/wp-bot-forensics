from datetime import UTC, datetime

import pytest

from botforensics.enrich import (
    REQUEST_COLUMNS,
    bot_asn_consistent,
    chrome_major,
    classify_path,
    classify_ua,
    enrich_requests,
    is_datacenter,
    is_internal_ua,
)
from botforensics.geo import GeoLookup, IpInfo
from botforensics.parse import Request
from botforensics.privacy import Redactor, pseudonymise


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/xmlrpc.php", "xmlrpc"),
        ("/wp-login.php", "login"),
        ("/<custom-login>/", "login"),
        ("/wp-cron.php", "cron"),
        ("/wp-admin/admin-post.php", "form"),
        ("/.env", "sensitive_probe"),
        ("/.git/config", "sensitive_probe"),
        ("/wp-config.php.bak", "sensitive_probe"),
        ("/1.php", "sensitive_probe"),
        ("/adminfuns.php", "sensitive_probe"),
        ("/wp-content/uploads/2026/x.php", "sensitive_probe"),
        ("/index.php", "html"),
        ("/wp-admin/admin-ajax.php", "admin"),
        ("/wp-json/wp/v2/users", "rest_api"),
        ("/robots.txt", "robots"),
        ("/wp-sitemap-posts-page-1.xml", "sitemap"),
        ("/feed/", "feed"),
        ("/wp-content/themes/t/style.css", "static"),
        ("/contact/", "html"),
        ("/", "html"),
    ],
)
def test_classify_path(path, expected):
    assert classify_path(path) == expected


@pytest.mark.parametrize(
    ("ua", "expected"),
    [
        (None, ("missing", None)),
        ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
         ("declared_bot", "Googlebot")),
        ("Jetpack by WordPress.com", ("declared_bot", "Jetpack")),
        ("Mozilla/5.0 (compatible; SomeNewBot/1.0)", ("declared_bot", "SomeNewBot")),
        ("curl/8.18.0", ("tool", None)),
        ("python-requests/2.32", ("tool", None)),
        ("Mozilla/5.0 (Windows NT 10.0) Chrome/155.0.0.0 Safari/537.36", ("browser", None)),
        ("WordPress/7.1.3; https://site.example", ("other", None)),
    ],
)
def test_classify_ua(ua, expected):
    assert classify_ua(ua) == expected


def test_chrome_major():
    assert chrome_major("Mozilla/5.0 Chrome/120.0.0.0 Safari") == 120
    assert chrome_major("curl/8") is None
    assert chrome_major(None) is None


def test_is_datacenter():
    assert is_datacenter("Microsoft Corporation")
    assert is_datacenter("OVH SAS")
    assert not is_datacenter("Orange")
    assert not is_datacenter(None)


def test_bot_asn_consistent():
    assert bot_asn_consistent("Googlebot", "Google LLC") is True
    assert bot_asn_consistent("Googlebot", "Hetzner Online GmbH") is False
    assert bot_asn_consistent("SomeNewBot", "Hetzner Online GmbH") is None
    assert bot_asn_consistent("Jetpack", None) is None


def test_is_internal_ua():
    assert is_internal_ua("Uptime-Kuma/2.5.5", "site.example")
    assert is_internal_ua("Mozilla/5.0+(compatible; UptimeRobot/2.0)", "site.example")
    assert is_internal_ua("WordPress/7.1.3; https://site.example", "site.example")
    # Pingback floods come from other WordPress sites: not internal.
    assert not is_internal_ua("WordPress/6.0; https://other.example", "site.example")
    assert not is_internal_ua(None, "site.example")
    assert not is_internal_ua("WordPress/7.1.3; https://site.example.evil.example", "site.example")
    assert is_internal_ua("WordPress/7.1.3; https://site.example/", "site.example")


def test_enrich_requests_pseudonymises_and_redacts():
    req = Request(
        host="203.0.113.7",
        timestamp=datetime(2026, 10, 14, 3, 0, tzinfo=UTC),
        method="POST", path="/secretadm/", has_query=False, protocol="HTTP/1.1",
        status=302, size=10, referer="https://site.example/secretadm/?a=1",
        user_agent="Mozilla/5.0 Chrome/129.0.0.0",
    )
    host_hash = pseudonymise("203.0.113.7", "k")
    geo = GeoLookup(None, None, {host_hash: IpInfo(1, "x", "NC")})
    df = enrich_requests([req], geo, "k", Redactor("site.example", "site.example", "secretadm"),
                         "site.example")
    assert list(df.columns) == REQUEST_COLUMNS
    row = df.iloc[0]
    assert row["ip_hash"] == host_hash
    assert row["path"] == "/<custom-login>/"
    assert row["path_category"] == "login"
    assert row["referer"] == "https://site.example/<custom-login>/"
    assert row["chrome_major"] == 129
    assert row["ua_kind"] == "browser"
    assert "203.0.113.7" not in df.to_csv()
