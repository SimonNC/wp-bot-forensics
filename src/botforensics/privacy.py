"""Pseudonymisation of personal data and redaction of site secrets."""

import hashlib
import hmac
import ipaddress
import re
from urllib.parse import unquote

PSEUDO_PREFIX = "ip-"
CUSTOM_LOGIN = "/<custom-login>"
AUTHOR = "<author>"
# WordPress author archives expose usernames: /author/<login>/. Matched on the raw text, each
# character possibly percent-encoded; everything after the marker up to ?, # or whitespace goes.
_SEP = r"(?:/|%2f)"
_WORD = "".join(f"(?:{c}|%{ord(c):02x}|%{ord(c.upper()):02x})" for c in "author")
AUTHOR_RE = re.compile(rf"{_SEP}{_WORD}{_SEP}+[^?#\s]+", re.I)
AUTHOR_PATH = f"/author/{AUTHOR}"
EMAIL_RE = re.compile(r"[\w.+-]+@[a-z][\w-]*(?:\.[\w-]+)*\.[a-z]{2,}\b", re.I)  # not x@2x.png
EMAIL = "<email>"
# Uploaded media names can carry people's names or social-network photo ids.
MEDIA_RE = re.compile(
    r"(/wp-content/uploads/(?:[^/?#\s]+/)*)[^/?#\s]+?"
    r"(\.(?:jpe?g|png|gif|webp|avif|svg|bmp|ico|pdf|mp4|webm|mov|mp3|heic))(?=[?#\s\"]|$)",
    re.I,
)


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
    """Hides the custom login URL (a security secret), author archive usernames, e-mail
    addresses and optionally the site domain."""

    def __init__(self, site_domain: str, site_label: str, custom_login_slug: str):
        self.site_label = site_label
        slug = custom_login_slug.strip("/")
        self.slug_re = (
            re.compile(rf"/{re.escape(slug)}(?=[/?#;\s]|$)", re.I) if slug else None
        )
        # The domain, and its first label anywhere (theme folder, file or e-mail names), in one
        # pass so the replacement is never rescanned.
        self.domain_re = (
            re.compile(rf"{re.escape(site_domain)}|{re.escape(site_domain.split('.')[0])}", re.I)
            if site_domain and site_label != site_domain
            else None
        )
        self.label_name = site_label.split(".")[0]

    def __call__(self, text: str | None) -> str | None:
        if text is None:
            return None
        if self.slug_re:
            text = self.slug_re.sub(CUSTOM_LOGIN, text)
            # Percent-encoded slug (/%73ecretadm/): only then is the decoded form kept.
            decoded = unquote(text)
            if self.slug_re.search(decoded):
                text = self.slug_re.sub(CUSTOM_LOGIN, decoded)
        text = AUTHOR_RE.sub(AUTHOR_PATH, text)
        text = EMAIL_RE.sub(EMAIL, text)
        text = MEDIA_RE.sub(r"\1<media>\2", text)
        if self.domain_re:
            text = self.domain_re.sub(
                lambda m: self.site_label if "." in m.group(0) else self.label_name, text)
        return text
