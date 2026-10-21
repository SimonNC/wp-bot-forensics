import pandas as pd
import pytest

from botforensics.rules import CATEGORIES, classify, classify_actors

BENIGN = {
    "ip_hash": "ip-a", "n_requests": 5, "peak_rpm": 2, "cv_interarrival": 1.2,
    "rate_4xx": 0.0, "rate_403": 0.0, "sensitive_probes": 0, "login_posts": 0,
    "login_posts_10min_max": 0, "in_campaign": False, "robots_reads": 0, "sitemap_reads": 0,
    "html_requests": 3, "html_no_referer_ratio": 0.3, "static_ratio": 0.4, "night_ratio": 0.0,
    "form_posts": 0, "distinct_paths": 4, "distinct_uas": 1, "internal_ua_ratio": 0.0,
    "ua_kind": "browser", "bot_name": None, "chrome_major_min": 154.0,
    "top_user_agent": "Mozilla/5.0", "asn": 1, "as_org": "Orange", "country": "NC",
    "is_datacenter": False, "cerber_verdict": None, "allowlisted_ip": False,
}


def cat(**overrides):
    return classify({**BENIGN, **overrides})


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, "unknown"),
        ({"internal_ua_ratio": 0.9}, "internal"),
        ({"allowlisted_ip": True}, "internal"),
        ({"allowlisted_ip": True, "sensitive_probes": 3, "peak_rpm": 45, "ua_kind": "tool"},
         "internal"),
        ({"allowlisted_ip": True, "login_posts_10min_max": 15, "login_posts": 15}, "internal"),
        ({"cerber_verdict": "logged_in"}, "internal"),
        # Friendly names are spoofable: attack behaviour wins.
        ({"internal_ua_ratio": 0.9, "sensitive_probes": 3}, "vuln_scanner"),
        ({"internal_ua_ratio": 0.9, "login_posts_10min_max": 15, "login_posts": 15},
         "credential_attack"),
        ({"ua_kind": "declared_bot", "bot_name": "Googlebot", "as_org": "Google LLC"},
         "verified_crawler"),
        # Unverifiable declared bots (unknown operator or no network info) are generic bots.
        ({"ua_kind": "declared_bot", "bot_name": "SomeNewBot"}, "generic_bot"),
        ({"ua_kind": "declared_bot", "bot_name": "Googlebot", "as_org": None}, "generic_bot"),
        # Form spam beats a verified identity.
        ({"ua_kind": "declared_bot", "bot_name": "Jetpack", "as_org": "Automattic, Inc",
          "form_posts": 3}, "form_spam"),
        ({"ua_kind": "declared_bot", "bot_name": "Googlebot", "as_org": "Hetzner Online GmbH"},
         "spoofed_crawler"),
        ({"login_posts_10min_max": 15, "login_posts": 15}, "credential_attack"),
        ({"ua_kind": "declared_bot", "bot_name": "Googlebot", "as_org": "Hetzner Online GmbH",
          "login_posts_10min_max": 15, "login_posts": 15}, "credential_attack"),
        ({"in_campaign": True, "login_posts": 2}, "credential_attack"),
        # Genuine Jetpack network, but attack behaviour: the declared name is no excuse.
        ({"ua_kind": "declared_bot", "bot_name": "Jetpack", "as_org": "Automattic, Inc",
          "login_posts": 40, "login_posts_10min_max": 12}, "credential_attack"),
        ({"sensitive_probes": 1}, "vuln_scanner"),
        ({"rate_4xx": 0.8, "n_requests": 20}, "vuln_scanner"),
        ({"cerber_verdict": "form_refused"}, "form_spam"),
        ({"form_posts": 3}, "form_spam"),
        ({"ua_kind": "tool"}, "generic_bot"),
        ({"ua_kind": "missing"}, "generic_bot"),
        ({"chrome_major_min": 120.0}, "generic_bot"),
        ({"peak_rpm": 45}, "generic_bot"),
        ({"cv_interarrival": 0.02, "n_requests": 30}, "generic_bot"),
        # A datacenter network alone is not enough to call an actor a bot.
        ({"is_datacenter": True, "as_org": "Microsoft Corporation"}, "unknown"),
        ({"is_datacenter": True, "as_org": "OVH SAS", "ua_kind": "tool"}, "generic_bot"),
        # A logged-in session does not excuse sensitive probes.
        ({"cerber_verdict": "logged_in", "sensitive_probes": 2}, "vuln_scanner"),
    ],
)
def test_classify(overrides, expected):
    assert cat(**overrides)[0] == expected


def test_reasons_are_explicit():
    category, reasons = cat(login_posts_10min_max=48, login_posts=60, is_datacenter=True,
                            as_org="Microsoft Corporation")
    assert category == "credential_attack"
    assert "login_posts_10min=48" in reasons
    assert "datacenter=Microsoft Corporation" in reasons


def test_spoofed_attacker_keeps_spoofing_in_reasons():
    category, reasons = cat(ua_kind="declared_bot", bot_name="Googlebot",
                            as_org="Hetzner Online GmbH", login_posts_10min_max=15,
                            login_posts=15)
    assert category == "credential_attack"
    assert any(r.startswith("Googlebot_from=") for r in reasons)


def test_unverified_declared_bot_reason():
    category, reasons = cat(ua_kind="declared_bot", bot_name="EvilBot", as_org="OVH SAS")
    assert category == "generic_bot"
    assert reasons == ["declared=EvilBot(unverified)"]


def test_verified_crawler_reason():
    category, reasons = cat(ua_kind="declared_bot", bot_name="Googlebot", as_org="Google LLC")
    assert category == "verified_crawler"
    assert "declared=Googlebot" in reasons


def test_datacenter_only_actor_keeps_reason():
    category, reasons = cat(is_datacenter=True, as_org="Microsoft Corporation")
    assert category == "unknown"
    assert reasons == ["datacenter=Microsoft Corporation"]


def test_categories_in_precedence_order():
    assert CATEGORIES == ["internal", "credential_attack", "vuln_scanner", "spoofed_crawler",
                          "form_spam", "verified_crawler", "generic_bot", "unknown"]


def test_nan_values_do_not_trigger():
    assert cat(cv_interarrival=float("nan"), chrome_major_min=float("nan"),
               cerber_verdict=float("nan"))[0] == "unknown"


def test_classify_actors_adds_columns():
    out = classify_actors(pd.DataFrame([BENIGN, {**BENIGN, "ip_hash": "ip-b", "ua_kind": "tool"}]))
    assert list(out["category"]) == ["unknown", "generic_bot"]
    assert out["reasons"].iloc[1] == ["ua=tool"]
    assert set(out["category"]) <= set(CATEGORIES)


def test_allowlisted_reason_and_no_effect_otherwise():
    category, reasons = classify({**BENIGN, "allowlisted_ip": True, "sensitive_probes": 2})
    assert category == "internal"
    assert "allowlisted_operator_ip" in reasons
    category, reasons = classify({**BENIGN, "sensitive_probes": 2})
    assert category == "vuln_scanner"
    assert "allowlisted_operator_ip" not in reasons
