"""The versioned sample is public: check it carries no personal data or site secrets."""

import csv
import re
from pathlib import Path

import pytest

from botforensics.parse import parse_line
from botforensics.privacy import EMAIL_RE, MEDIA_RE, is_pseudonym

SAMPLE = Path(__file__).parents[1] / "data" / "sample"
IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
AUTHOR_RE = re.compile(r"/author/(?!<author>(?:[/?#]|$))", re.I)

pytestmark = pytest.mark.skipif(not (SAMPLE / "apache").is_dir(), reason="no versioned sample")


def _clean_url(value: str | None) -> bool:
    if not value:
        return True
    media = [m for m in MEDIA_RE.finditer(value) if not value[m.end(1):].startswith("<media>")]
    return (IPV4_RE.search(value) is None and AUTHOR_RE.search(value) is None
            and EMAIL_RE.search(value) is None and not media)


def test_apache_sample_has_no_ip_or_username():
    lines = [line for f in sorted((SAMPLE / "apache").glob("*.log")) for line in
             f.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    for line in lines:
        r = parse_line(line)
        assert r is not None
        assert is_pseudonym(r.host)
        assert _clean_url(r.path) and _clean_url(r.referer), r.path


def test_cerber_sample_has_no_ip_or_username():
    for f in sorted((SAMPLE / "cerber").glob("*.csv")):
        rows = list(csv.reader(f.read_text(encoding="utf-8").splitlines()))[3:]
        for ip, _event, _status, user, _ts, url in rows:
            assert is_pseudonym(ip)
            assert not user or is_pseudonym(user, "user-")
            assert _clean_url(url), url


def test_ip_info_sidecar_is_keyed_by_pseudonyms():
    with (SAMPLE / "ip_info.csv").open(encoding="utf-8", newline="") as fh:
        assert all(is_pseudonym(row["ip_hash"]) for row in csv.DictReader(fh))
