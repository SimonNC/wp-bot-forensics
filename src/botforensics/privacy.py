"""Pseudonymisation of personal data and redaction of site secrets."""

import hashlib
import hmac
import ipaddress
import re
from urllib.parse import unquote

PSEUDO_PREFIX = "ip-"
CUSTOM_LOGIN = "/<custom-login>"
AUTHOR = "<author>"
# WordPress author archives expose usernames: /author/<login>/.
AUTHOR_RE = re.compile(r"(/author/)[^/?#\s]+", re.I)


def pseudonymise(value: str, key: str, prefix: str = PSEUDO_PREFIX) -> str:
    # Keyed hash: without the key, the 2^32 IPv4 space cannot be brute-forced back.
    digest = hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{prefix}{digest}"


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_pseudonym(value: str, prefix: str = PSEUDO_PREFIX) -> bool:
    suffix = value[len(prefix):]
    return value.startswith(prefix) and re.fullmatch(r"[0-9a-f]{16}", suffix) is not None


def strip_query(url: str | None) -> str | None:
    return None if url is None else url.split("?", 1)[0]


class Redactor:
    """Hides the custom login URL (a security secret), author archive usernames and optionally
    the site domain."""

    def __init__(self, site_domain: str, site_label: str, custom_login_slug: str):
        self.site_label = site_label
        slug = custom_login_slug.strip("/")
        self.slug_re = (
            re.compile(rf"/{re.escape(slug)}(?=[/?#;\s]|$)", re.I) if slug else None
        )
        self.domain_re = (
            re.compile(re.escape(site_domain), re.I)
            if site_domain and site_label != site_domain
            else None
        )

    def __call__(self, text: str | None) -> str | None:
        if text is None:
            return None
        if self.slug_re:
            text = self.slug_re.sub(CUSTOM_LOGIN, text)
            # Percent-encoded slug (/%73ecretadm/): only then is the decoded form kept.
            decoded = unquote(text)
            if self.slug_re.search(decoded):
                text = self.slug_re.sub(CUSTOM_LOGIN, decoded)
        text = AUTHOR_RE.sub(rf"\g<1>{AUTHOR}", text)
        if self.domain_re:
            text = self.domain_re.sub(self.site_label, text)
        return text
