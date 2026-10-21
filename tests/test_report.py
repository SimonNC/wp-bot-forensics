from pathlib import Path

import pandas as pd
import pytest

from botforensics.pipeline import run, write_parquet
from botforensics.report import (
    build_report,
    load_queries,
    md_table,
    review_agreement,
    write_review_sample,
)

QUERIES = Path(__file__).parents[1] / "analysis" / "queries.sql"
LINES = "\n".join(
    [f'203.0.113.{i} - - [14/Oct/2026:03:00:0{i % 10} +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"'
     for i in range(12)]
) + "\n"


def _processed(tmp_path, settings):
    (tmp_path / "raw" / "apache").mkdir(parents=True)
    (tmp_path / "raw" / "apache" / "a.log").write_text(LINES)
    out = tmp_path / "processed"
    write_parquet(run(tmp_path / "raw", settings), out)
    return out


def test_load_queries_parses_blocks():
    queries = load_queries(QUERIES)
    names = [name for name, _, _ in queries]
    assert names[0] == "overview"
    assert len(names) == len(set(names))
    assert all(sql.strip() for _, _, sql in queries)


def test_md_table():
    md = md_table(pd.DataFrame({"a": [1], "b": [["x", "y"]]}))
    assert md.splitlines() == ["| a | b |", "|---|---|", "| 1 | x, y |"]


def test_build_report_runs_every_query(tmp_path, settings):
    report = build_report(_processed(tmp_path, settings), QUERIES)
    assert report.startswith("# Findings")
    assert "vuln_scanner" in report
    assert "Error" not in report


def test_review_sample_and_agreement(tmp_path, settings):
    out = tmp_path / "review.csv"
    assert write_review_sample(_processed(tmp_path, settings), out, n=5) == 5
    assert review_agreement(out) is None  # nothing filled yet
    df = pd.read_csv(out)
    df["my_category"] = df["category"]
    df.loc[0, "my_category"] = "unknown"
    df.to_csv(out, index=False)
    assert "4/5" in review_agreement(out)


def test_review_agreement_normalises_and_reports_per_category(tmp_path):
    out = tmp_path / "review.csv"
    pd.DataFrame({
        "ip_hash": [f"ip-{i}" for i in range(6)],
        "category": ["vuln_scanner", "vuln_scanner", "generic_bot", "generic_bot", "unknown",
                     "unknown"],
        "my_category": [" Vuln_Scanner ", "vuln_scanner", "unknown", "GENERIC_BOT", "human", ""],
    }).to_csv(out, index=False)
    text = review_agreement(out)
    assert "3/4" in text  # the invalid label and the blank row are not counted
    assert "| vuln_scanner | 2 | 2 |" in text
    assert "| generic_bot | 1 | 2 |" in text
    assert "Invalid labels (not a category): 1 (human)" in text
    assert "stratified" in text


def test_review_sample_refuses_to_overwrite_labels(tmp_path, settings):
    processed = _processed(tmp_path, settings)
    out = tmp_path / "review.csv"
    write_review_sample(processed, out, n=5)
    df = pd.read_csv(out)
    df["my_category"] = df["category"]
    df.to_csv(out, index=False)
    before = out.read_text()
    with pytest.raises(FileExistsError, match="my_category"):
        write_review_sample(processed, out, n=5)
    assert out.read_text() == before
    write_review_sample(processed, out, n=5, force=True)
    assert out.read_text() != before


def test_review_sample_is_stratified(tmp_path):
    processed = tmp_path / "processed"
    processed.mkdir()
    cats = ["vuln_scanner"] * 40 + ["unknown"] * 3 + ["form_spam"] * 2
    pd.DataFrame({
        "ip_hash": [f"ip-{i}" for i in range(len(cats))], "category": cats,
        "n_requests": 1, "as_org": "x", "top_user_agent": "ua",
        "iforest_outlier": False, "reasons": [[] for _ in cats],
    }).to_parquet(processed / "actors.parquet")
    out = tmp_path / "review.csv"
    assert write_review_sample(processed, out, n=9) == 9
    got = pd.read_csv(out)
    assert set(got["category"]) == {"vuln_scanner", "unknown", "form_spam"}
    assert got["category"].is_monotonic_increasing


def test_load_queries_header_mention_and_missing_title(tmp_path):
    ok = tmp_path / "ok.sql"
    lines = ['-- Each block: "-- name:" then title.', "", "-- name: a", "-- title: A", "SELECT 1;"]
    ok.write_text("\n".join(lines))
    assert load_queries(ok) == [("a", "A", "SELECT 1;")]
    bad = tmp_path / "bad.sql"
    bad.write_text("\n".join(["-- name: broken", "SELECT 1;"]))
    with pytest.raises(ValueError, match="broken"):
        load_queries(bad)
