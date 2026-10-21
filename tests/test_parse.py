import gzip
from datetime import UTC, datetime

from botforensics.parse import ParseStats, format_time, parse_file, parse_line

XMLRPC = (
    '203.0.113.7 - - [14/Oct/2026:03:07:41 +0000] "POST /xmlrpc.php HTTP/1.1" 403 384 '
    '"-" "Mozilla/5.0 (X11; Ubuntu)"'
)


def test_parse_combined_line():
    r = parse_line(XMLRPC)
    assert r is not None
    assert r.host == "203.0.113.7"
    assert r.timestamp == datetime(2026, 10, 14, 3, 7, 41, tzinfo=UTC)
    assert (r.method, r.path, r.protocol) == ("POST", "/xmlrpc.php", "HTTP/1.1")
    assert (r.status, r.size) == (403, 384)
    assert r.referer is None
    assert r.user_agent == "Mozilla/5.0 (X11; Ubuntu)"
    assert r.has_query is False


def test_timezone_converted_to_utc():
    line = '198.51.100.1 - - [27/May/2020:02:08:42 -0700] "GET / HTTP/1.1" 200 12 "-" "x"'
    assert parse_line(line).timestamp == datetime(2020, 5, 27, 9, 8, 42, tzinfo=UTC)


def test_query_string_dropped():
    line = (
        '203.0.113.7 - - [14/Oct/2026:00:02:06 +0000] '
        '"POST /wp-cron.php?doing_wp_cron=179 HTTP/1.1" 200 224 "-" "WordPress/7.1.3"'
    )
    r = parse_line(line)
    assert r.path == "/wp-cron.php"
    assert r.has_query is True


def test_escaped_quote_in_user_agent():
    line = '203.0.113.7 - - [14/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "a \\"b\\" c"'
    assert parse_line(line).user_agent == 'a "b" c'


def test_ipv6_host_and_dash_size():
    line = '2001:db8::1 - - [14/Oct/2026:00:00:00 +0000] "HEAD / HTTP/1.1" 304 - "-" "-"'
    r = parse_line(line)
    assert r.host == "2001:db8::1"
    assert r.size == 0
    assert r.user_agent is None


def test_malformed_request_is_kept_without_method():
    line = '203.0.113.7 - - [14/Oct/2026:00:00:00 +0000] "\\x16\\x03\\x01" 400 226 "-" "-"'
    r = parse_line(line)
    assert r.method is None
    assert r.path == "\\x16\\x03\\x01"
    assert r.status == 400


def test_garbage_line_returns_none():
    assert parse_line("not a log line") is None


def test_non_numeric_size_is_malformed():
    line = '203.0.113.7 - - [14/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 abc "-" "x"'
    assert parse_line(line) is None


def test_parse_file_counts_malformed(tmp_path):
    path = tmp_path / "access.log.gz"
    with gzip.open(path, "wt") as fh:
        fh.write(XMLRPC + "\n" + XMLRPC + "\n" + "garbage\n\n")
    stats = ParseStats()
    assert len(list(parse_file(path, stats))) == 2
    assert (stats.lines, stats.parsed, stats.malformed) == (3, 2, 1)


def test_format_time_roundtrip():
    ts = datetime(2026, 10, 4, 3, 7, 41, tzinfo=UTC)
    assert format_time(ts) == "04/Oct/2026:03:07:41 +0000"


def test_backslash_escapes_are_decoded():
    line = ('203.0.113.7 - - [14/Oct/2026:03:07:41 +0000] "GET / HTTP/1.1" 200 1 "-" '
            r'"a \"b\" C:\\dir\\"')
    assert parse_line(line).user_agent == 'a "b" C:\\dir\\'


def test_bare_question_mark_keeps_has_query():
    line = '203.0.113.7 - - [14/Oct/2026:03:07:41 +0000] "GET /a/? HTTP/1.1" 200 1 "-" "x"'
    r = parse_line(line)
    assert (r.path, r.has_query) == ("/a/", True)
