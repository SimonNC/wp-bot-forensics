from dataclasses import replace

import pytest

from botforensics.config import DEV_KEY
from botforensics.pipeline import run, write_parquet

LINES = [
    '{ip} - - [14/Oct/2026:03:0{i}:00 +0000] "POST /xmlrpc.php HTTP/1.1" 403 384 "-" "Kit/1"'
    .format(ip="203.0.113.7", i=i) for i in range(10)
] + [
    '198.51.100.2 - - [14/Oct/2026:04:00:00 +0000] "GET /.env HTTP/1.1" 404 10 "-" "-"',
    '198.51.100.3 - - [14/Oct/2026:05:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" '
    '"Uptime-Kuma/2.5.5"',
    "garbage",
]


def _data(tmp_path):
    (tmp_path / "apache").mkdir()
    (tmp_path / "apache" / "access-2026-10-14.log").write_text("\n".join(LINES) + "\n")
    return tmp_path


def test_run_classifies_and_writes(tmp_path, settings):
    result = run(_data(tmp_path), settings)
    assert result.stats.parsed == 12 and result.stats.malformed == 1
    assert sorted(result.actors["category"]) == ["credential_attack", "internal", "vuln_scanner"]
    assert "actor_category" in result.requests.columns
    assert "203.0.113.7" not in result.requests.to_csv()
    out = tmp_path / "processed"
    write_parquet(result, out)
    assert {p.name for p in out.iterdir()} == {
        "requests.parquet", "actors.parquet", "cerber_events.parquet"}


def test_real_ips_with_dev_key_are_refused(tmp_path, settings):
    with pytest.raises(RuntimeError, match="PSEUDO_KEY"):
        run(_data(tmp_path), replace(settings, pseudo_key=DEV_KEY))
