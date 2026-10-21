from pathlib import Path

import pandas as pd

from botforensics.pipeline import run, write_parquet
from botforensics.report import (
    build_report,
    load_queries,
    md_table,
    review_agreement,
    write_review_sample,
)

QUERIES = Path("analysis/queries.sql")
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
