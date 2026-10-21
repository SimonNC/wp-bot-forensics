"""Explainable classification of actors: every verdict carries its evidence."""

from collections.abc import Mapping

import pandas as pd

from botforensics.enrich import bot_asn_consistent

CATEGORIES = ["internal", "verified_crawler", "spoofed_crawler", "credential_attack",
              "vuln_scanner", "form_spam", "generic_bot", "unknown"]

CURRENT_CHROME_MAJOR = 155  # Chrome stable in October 2026
OUTDATED_CHROME_GAP = 12    # about a year of 4-week releases
LOGIN_BURST = 10            # login POSTs in one 10-minute window
LOGIN_VOLUME = 20           # login POSTs over the whole period
HIGH_RATE = 30              # requests in one minute
METRONOMIC_CV = 0.1         # coefficient of variation of inter-arrival times

CREDENTIAL = {"login_burst", "login_volume", "campaign"}
SCANNER = {"sensitive_probe", "high_4xx"}
FORM = {"form_refused", "form_repeat"}
GENERIC = {"ua_missing", "ua_tool", "outdated_chrome", "high_rate", "metronomic", "datacenter",
           "declared_bot"}


def _present(value) -> bool:
    return value is not None and not pd.isna(value)


def signals(a: Mapping) -> dict[str, str]:
    """Name → human-readable evidence, for every indicator that fires."""
    s: dict[str, str] = {}
    verdict = a.get("cerber_verdict")
    verdict = verdict if _present(verdict) else None
    if a["allowlisted_ip"]:
        s["allowlisted_ip"] = "allowlisted_operator_ip"
    if a["internal_ua_ratio"] >= 0.5:
        s["internal_ua"] = f"internal_ua_ratio={a['internal_ua_ratio']:.2f}"
    if verdict == "logged_in":
        s["cerber_logged_in"] = "cerber=logged_in"
    if a["ua_kind"] == "declared_bot":
        s["declared_bot"] = f"declared={a['bot_name']}"
        if bot_asn_consistent(a["bot_name"], a["as_org"]) is False:
            s["bot_asn_mismatch"] = f"{a['bot_name']}_from={a['as_org']}"
    if a["login_posts_10min_max"] >= LOGIN_BURST:
        s["login_burst"] = f"login_posts_10min={a['login_posts_10min_max']}"
    if a["login_posts"] >= LOGIN_VOLUME:
        s["login_volume"] = f"login_posts={a['login_posts']}"
    if a["in_campaign"]:
        s["campaign"] = "distributed_campaign"
    if a["sensitive_probes"] >= 1:
        s["sensitive_probe"] = f"sensitive_probes={a['sensitive_probes']}"
    if a["rate_4xx"] >= 0.5 and a["n_requests"] >= 10:
        s["high_4xx"] = f"rate_4xx={a['rate_4xx']:.2f}"
    if verdict == "form_refused":
        s["form_refused"] = "cerber=form_refused"
    if a["form_posts"] >= 3:
        s["form_repeat"] = f"form_posts={a['form_posts']}"
    if a["ua_kind"] == "missing":
        s["ua_missing"] = "ua=missing"
    if a["ua_kind"] == "tool":
        s["ua_tool"] = "ua=tool"
    chrome = a.get("chrome_major_min")
    if _present(chrome) and chrome < CURRENT_CHROME_MAJOR - OUTDATED_CHROME_GAP:
        s["outdated_chrome"] = f"chrome={int(chrome)}"
    if a["peak_rpm"] >= HIGH_RATE:
        s["high_rate"] = f"peak_rpm={a['peak_rpm']}"
    cv = a["cv_interarrival"]
    if _present(cv) and cv < METRONOMIC_CV and a["n_requests"] >= 10:
        s["metronomic"] = f"cv_interarrival={cv:.2f}"
    if a["is_datacenter"]:
        s["datacenter"] = f"datacenter={a['as_org']}"
    return s


def classify(a: Mapping) -> tuple[str, list[str]]:
    s = signals(a)
    fired = s.keys()
    # Owned IPs cannot be spoofed like a user-agent: allowlist wins.
    if "allowlisted_ip" in fired:
        return "internal", list(s.values())
    # Attack behaviour wins over identity claims; spoofing stays visible in reasons.
    attack = fired & (CREDENTIAL | SCANNER)
    if fired & {"internal_ua", "cerber_logged_in"} and not attack:
        category = "internal"
    elif fired & CREDENTIAL:
        category = "credential_attack"
    elif fired & SCANNER:
        category = "vuln_scanner"
    elif "bot_asn_mismatch" in fired:
        category = "spoofed_crawler"
    elif "declared_bot" in fired:
        category = "verified_crawler"
    elif fired & FORM:
        category = "form_spam"
    elif fired & GENERIC:
        category = "generic_bot"
    else:
        category = "unknown"
    return category, list(s.values())


def classify_actors(actors: pd.DataFrame) -> pd.DataFrame:
    out = actors.copy()
    # pd.NA is not usable in boolean tests: hand plain None to the rules.
    records = out.astype(object).where(out.notna(), None).to_dict("records")
    results = [classify(row) for row in records]
    out["category"] = [c for c, _ in results]
    out["reasons"] = [r for _, r in results]
    return out
