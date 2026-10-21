"""Pseudonymisation of personal data and redaction of site secrets."""

import hashlib
import hmac
import ipaddress
import re

PSEUDO_PREFIX = "ip-"
CUSTOM_LOGIN = "/<custom-login>"


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


def is_pseudonym(value: str) -> bool:
    return value.startswith(PSEUDO_PREFIX) and len(value) == len(PSEUDO_PREFIX) + 16


def strip_query(url: str | None) -> str | None:
    return None if url is None else url.split("?", 1)[0]


class Redactor:
    """Hides the custom login URL (a security secret) and optionally the site domain."""

    def __init__(self, site_domain: str, site_label: str, custom_login_slug: str):
        self.site_domain = site_domain
        self.site_label = site_label
        self.slug_re = (
            re.compile(rf"/{re.escape(custom_login_slug)}(?=/|\?|$)")
            if custom_login_slug
            else None
        )

    def __call__(self, text: str | None) -> str | None:
        if text is None:
            return None
        if self.slug_re:
            text = self.slug_re.sub(CUSTOM_LOGIN, text)
        if self.site_domain and self.site_label != self.site_domain:
            text = text.replace(self.site_domain, self.site_label)
        return text
