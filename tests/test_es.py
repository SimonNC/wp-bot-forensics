from pathlib import Path

import pandas as pd

from botforensics.es import INDEXES, load_mapping, to_documents
from botforensics.pipeline import run

FIXTURE = (
    '203.0.113.7 - - [14/Oct/2026:03:00:00 +0000] "POST /xmlrpc.php HTTP/1.1" 403 1 "-" "Kit"\n'
)


def test_to_documents_renames_time_and_nulls():
    df = pd.DataFrame({"timestamp": pd.to_datetime(["2026-10-14T03:00:00Z"]),
                       "x": [float("nan")], "reasons": [["a", "b"]]})
    doc = to_documents(df, "timestamp")[0]
    assert doc["@timestamp"].startswith("2026-10-14T03:00:00")
    assert doc["x"] is None
    assert doc["reasons"] == ["a", "b"]


def test_mappings_match_dataframe_columns(tmp_path: Path, settings):
    (tmp_path / "apache").mkdir()
    (tmp_path / "apache" / "a.log").write_text(FIXTURE)
    result = run(tmp_path, settings)
    frames = {"weblogs-requests": (result.requests, "timestamp"),
              "weblogs-actors": (result.actors, None),
              "cerber-events": (result.events, "timestamp")}
    for index, (df, time_col) in frames.items():
        props = set(load_mapping(index)["mappings"]["properties"])
        cols = {("@timestamp" if c == time_col else c) for c in df.columns}
        assert props == cols, index
    assert set(INDEXES) == set(frames)
