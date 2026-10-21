"""Per-request enrichment: path and user-agent families, network origin, pseudonymised IP."""

import re
from collections.abc import Iterable
from pathlib import PurePosixPath

import pandas as pd

from botforensics.geo import GeoLookup
from botforensics.parse import Request
from botforensics.privacy import CUSTOM_LOGIN, Redactor, is_pseudonym, pseudonymise, strip_query

STATIC_EXT = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif",
              ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}
# Legitimate PHP entry points at the WordPress root; any other root .php is a webshell hunt.
WP_ROOT_PHP = {"/index.php", "/wp-login.php", "/xmlrpc.php", "/wp-cron.php",
               "/wp-comments-post.php", "/wp-signup.php", "/wp-activate.php",
               "/wp-trackback.php", "/wp-links-opml.php", "/wp-mail.php"}
SENSITIVE_RE = re.compile(
    r"(?:^|/)\.(?:env|git|svn|hg|aws|ssh|htaccess|htpasswd|ds_store|vscode)"
    r"|wp-config|phpinfo|/(?:vendor|cgi-bin|phpmyadmin|pma|adminer)(?:/|$)"
    r"|\.(?:sql|bak|old|orig|swp|zip|tar|gz|7z|rar)$",
    re.I,
)

TOOL_RE = re.compile(
    r"curl|wget|python|aiohttp|httpx|go-http-client|java/|okhttp|libwww|lwp::|httpclient"
    r"|axios|node-fetch|undici|scrapy|php/|guzzle|masscan|zgrab|nuclei|nikto|sqlmap|wpscan"
    r"|headless",
    re.I,
)
KNOWN_BOTS = ["Googlebot", "bingbot", "Applebot", "YandexBot", "DuckDuckBot", "Baiduspider",
              "GPTBot", "OAI-SearchBot", "ChatGPT-User", "ClaudeBot", "PerplexityBot",
              "Amazonbot", "AhrefsBot", "SemrushBot", "MJ12bot", "DotBot", "PetalBot",
              "Bytespider", "facebookexternalhit", "Jetpack", "UptimeRobot", "Uptime-Kuma"]
GENERIC_BOT_RE = re.compile(r"([\w.-]*(?:bot|crawler|spider|scanner)[\w.-]*)", re.I)
CHROME_RE = re.compile(r"Chrome/(\d+)\.")
MONITOR_RE = re.compile(r"Uptime-Kuma|UptimeRobot", re.I)

DATACENTER_KEYWORDS = ("amazon", "aws", "microsoft", "azure", "google", "digitalocean", "ovh",
                       "hetzner", "linode", "akamai", "contabo", "alibaba", "tencent", "oracle",
                       "scaleway", "vultr", "choopa", "leaseweb", "m247", "hostinger", "ionos",
                       "datacamp", "cloud", "hosting", "server", "data center", "datacenter",
                       "colocation")
# A declared crawler must come from its operator's network.
BOT_ASN = {
    "Googlebot": ("google",),
    "bingbot": ("microsoft",),
    "Applebot": ("apple",),
    "YandexBot": ("yandex",),
    "DuckDuckBot": ("microsoft", "duckduckgo"),
    "Jetpack": ("automattic",),
    "facebookexternalhit": ("facebook", "meta"),
}

REQUEST_COLUMNS = ["timestamp", "ip_hash", "asn", "as_org", "country", "is_datacenter",
                   "method", "path", "path_category", "has_query", "status", "size",
                   "referer", "user_agent", "ua_kind", "bot_name", "chrome_major",
                   "is_internal_ua"]
TEXT_COLUMNS = ["ip_hash", "as_org", "country", "method", "path", "path_category", "referer",
                "user_agent", "ua_kind", "bot_name"]


def classify_path(path: str) -> str:
    p = path.lower()
    if p == "/xmlrpc.php":
        return "xmlrpc"
    if p == "/wp-login.php" or p.startswith(CUSTOM_LOGIN):
        return "login"
    if p == "/wp-cron.php":
        return "cron"
    if p == "/wp-admin/admin-post.php":
        return "form"
    if SENSITIVE_RE.search(p):
        return "sensitive_probe"
    if p.endswith(".php") and p.count("/") == 1 and p not in WP_ROOT_PHP:
        return "sensitive_probe"
    if "/wp-content/uploads/" in p and p.endswith(".php"):
        return "sensitive_probe"
    if p.startswith("/wp-admin"):
        return "admin"
    if p.startswith("/wp-json"):
        return "rest_api"
    if p == "/robots.txt":
        return "robots"
    if "sitemap" in p and p.endswith(".xml"):
        return "sitemap"
    if p.startswith("/feed") or p.endswith("/feed/"):
        return "feed"
    if PurePosixPath(p).suffix in STATIC_EXT:
        return "static"
    return "html"


def classify_ua(ua: str | None) -> tuple[str, str | None]:
    if not ua:
        return "missing", None
    lowered = ua.lower()
    for name in KNOWN_BOTS:
        if name.lower() in lowered:
            return "declared_bot", name
    if TOOL_RE.search(ua):
        return "tool", None
    m = GENERIC_BOT_RE.search(ua)
    if m:
        return "declared_bot", m.group(1)
    if ua.startswith("Mozilla/"):
        return "browser", None
    return "other", None


def chrome_major(ua: str | None) -> int | None:
    m = CHROME_RE.search(ua or "")
    return int(m.group(1)) if m else None


def is_datacenter(as_org: str | None) -> bool:
    lowered = (as_org or "").lower()
    return any(k in lowered for k in DATACENTER_KEYWORDS)


def bot_asn_consistent(bot_name: str | None, as_org: str | None) -> bool | None:
    if bot_name not in BOT_ASN or not as_org:
        return None
    lowered = as_org.lower()
    return any(k in lowered for k in BOT_ASN[bot_name])


def is_internal_ua(ua: str | None, site_label: str) -> bool:
    if not ua:
        return False
    if MONITOR_RE.search(ua):
        return True
    return ua.startswith("WordPress/") and bool(site_label) and site_label in ua


def enrich_requests(requests: Iterable[Request], geo: GeoLookup, key: str, redact: Redactor,
                    site_label: str) -> pd.DataFrame:
    rows = []
    for r in requests:
        info = geo.lookup(r.host)
        path = redact(r.path)
        ua = redact(r.user_agent)
        ua_kind, bot_name = classify_ua(ua)
        rows.append({
            "timestamp": r.timestamp,
            "ip_hash": r.host if is_pseudonym(r.host) else pseudonymise(r.host, key),
            "asn": info.asn,
            "as_org": info.as_org,
            "country": info.country,
            "is_datacenter": is_datacenter(info.as_org),
            "method": r.method,
            "path": path,
            "path_category": classify_path(path),
            "has_query": r.has_query,
            "status": r.status,
            "size": r.size,
            "referer": strip_query(redact(r.referer)),
            "user_agent": ua,
            "ua_kind": ua_kind,
            "bot_name": bot_name,
            "chrome_major": chrome_major(ua),
            "is_internal_ua": is_internal_ua(ua, site_label),
        })
    df = pd.DataFrame(rows, columns=REQUEST_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["asn"] = df["asn"].astype("Float64")
    df["chrome_major"] = df["chrome_major"].astype("Float64")
    # Explicit string dtype: an all-empty column must stay a string column in Parquet/DuckDB.
    for col in TEXT_COLUMNS:
        df[col] = df[col].astype("string")
    return df
