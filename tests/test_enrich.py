import ipaddress
from datetime import UTC, datetime

import pandas as pd
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
        # Encoded or doubled characters must not dodge the categories.
        ("/%2eenv", "sensitive_probe"),
        ("/%2Egit/config", "sensitive_probe"),
        ("//xmlrpc.php", "xmlrpc"),
        ("///wp-login.php", "login"),
        ("/wp-admin//admin-post.php", "form"),
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
        ("WordPress/7.1.3; https://example.com", ("other", None)),
        # A phone brand, not a bot.
        ("Mozilla/5.0 (Linux; Android 10; CUBOT X30) AppleWebKit/537.36 Chrome/150.0.0.0",
         ("browser", None)),
        ("Mozilla/5.0 (Linux; Android 13; CUBOT) AppleWebKit/537.36", ("browser", None)),
        ("Mozilla/5.0 (compatible; EvilBot/1.0)", ("declared_bot", "EvilBot")),
        ("Mozilla/5.0 (compatible; Foo Spider)", ("declared_bot", "Spider")),
        # A bot word inside a URL is not a product token.
        ("Mozilla/5.0 (compatible; AhrefsSiteAudit/6.1; +http://ahrefs.com/robot/)",
         ("browser", None)),
        ("Mozilla/5.0 (compatible; Foo/1.0; https://foo.example/crawler)", ("browser", None)),
        ("Mozilla/5.0 (X11; Linux) Chrome/150.0 Safari/537.36 abbotsford.example",
         ("browser", None)),
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
    assert is_datacenter("Google LLC")
    # Generic words matched ISPs and CDNs, not hosting providers.
    for org in ("Cloud Fiber Ltd", "Server Telecom", "Akamai Technologies", "Web Hosting NC",
                "Google Fiber Inc."):
        assert not is_datacenter(org), org


def test_bot_asn_consistent():
    assert bot_asn_consistent("Googlebot", "Google LLC") is True
    assert bot_asn_consistent("Googlebot", "Hetzner Online GmbH") is False
    assert bot_asn_consistent("Amazonbot", "Amazon.com, Inc.") is True
    assert bot_asn_consistent("PetalBot", "Huawei Cloud Service data center") is True
    assert bot_asn_consistent("PetalBot", "Hetzner Online GmbH") is False
    assert bot_asn_consistent("SomeNewBot", "Hetzner Online GmbH") is None
    assert bot_asn_consistent("Jetpack", None) is None
    assert bot_asn_consistent("Jetpack", pd.NA) is None  # string columns hold pd.NA


def test_is_internal_ua():
    assert is_internal_ua("Uptime-Kuma/2.5.5", "example.com")
    assert is_internal_ua("Mozilla/5.0+(compatible; UptimeRobot/2.0)", "example.com")
    assert is_internal_ua("WordPress/7.1.3; https://example.com", "example.com")
    # Pingback floods come from other WordPress sites: not internal.
    assert not is_internal_ua("WordPress/6.0; https://other.example", "example.com")
    assert not is_internal_ua(None, "example.com")
    assert not is_internal_ua("WordPress/7.1.3; https://example.com.evil.example", "example.com")
    assert is_internal_ua("WordPress/7.1.3; https://example.com/", "example.com")


def test_enrich_requests_pseudonymises_and_redacts():
    req = Request(
        host="203.0.113.7",
        timestamp=datetime(2026, 10, 14, 3, 0, tzinfo=UTC),
        method="POST", path="/secretadm/", has_query=False, protocol="HTTP/1.1",
        status=302, size=10, referer="https://example.com/secretadm/?a=1",
        user_agent="Mozilla/5.0 Chrome/129.0.0.0",
    )
    host_hash = pseudonymise("203.0.113.7", "k")
    geo = GeoLookup(None, None, {host_hash: IpInfo(1, "x", "NC")})
    df = enrich_requests([req], geo, "k", Redactor("example.com", "example.com", "secretadm"),
                         "example.com")
    assert list(df.columns) == REQUEST_COLUMNS
    row = df.iloc[0]
    assert row["ip_hash"] == host_hash
    assert row["path"] == "/<custom-login>/"
    assert row["path_category"] == "login"
    assert row["referer"] == "https://example.com/<custom-login>/"
    assert row["chrome_major"] == 129
    assert row["ua_kind"] == "browser"
    assert "203.0.113.7" not in df.to_csv()


def _req(host):
    return Request(
        host=host, timestamp=datetime(2026, 10, 14, 3, 0, tzinfo=UTC),
        method="GET", path="/", has_query=False, protocol="HTTP/1.1",
        status=200, size=1, referer=None, user_agent="Mozilla/5.0",
    )


def test_enrich_flags_allowlisted_hosts():
    nets = (ipaddress.ip_network("203.0.113.7/32"), ipaddress.ip_network("2001:db8:1:2::/64"))
    hosts = ["203.0.113.7", "2001:db8:1:2:aaaa::1", "203.0.113.8", "2001:db8:9::1"]
    df = enrich_requests([_req(h) for h in hosts], GeoLookup(None, None), "k",
                         Redactor("example.com", "example.com", ""), "example.com", nets)
    assert list(df["is_allowlisted"]) == [True, True, False, False]
    assert list(df.columns).index("is_allowlisted") == REQUEST_COLUMNS.index("is_internal_ua") + 1
    assert "203.0.113" not in df.to_csv()


def test_enrich_reads_allowlisted_from_sidecar_for_pseudonyms():
    geo = GeoLookup(None, None, {"ip-0123456789abcdef": IpInfo(1, "x", "NC", True),
                                 "ip-fedcba9876543210": IpInfo(1, "x", "NC")})
    df = enrich_requests([_req("ip-0123456789abcdef"), _req("ip-fedcba9876543210")], geo, "k",
                         Redactor("example.com", "example.com", ""), "example.com")
    assert list(df["is_allowlisted"]) == [True, False]
