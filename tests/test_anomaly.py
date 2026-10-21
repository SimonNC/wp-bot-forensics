import numpy as np
import pandas as pd

from botforensics.anomaly import MODEL_FEATURES, score_actors


def actors(n: int) -> pd.DataFrame:
    rng = np.random.default_rng(0)
    rows = []
    for i in range(n):
        row = {f: float(rng.uniform(0, 1)) for f in MODEL_FEATURES}
        row.update({"ip_hash": f"ip-{i}", "n_requests": float(rng.integers(3, 10)),
                    "is_datacenter": False})
        rows.append(row)
    return pd.DataFrame(rows)


def test_extreme_actor_is_top_outlier():
    df = actors(60)
    df.loc[59, ["n_requests", "peak_rpm", "login_posts", "login_posts_10min_max"]] = [
        5000, 300, 4000, 900]
    out = score_actors(df)
    assert out["iforest_score"].idxmax() == 59
    assert bool(out.loc[59, "iforest_outlier"])
    assert out["iforest_outlier"].sum() <= 6


def test_too_few_actors_are_not_scored():
    out = score_actors(actors(5))
    assert out["iforest_score"].isna().all()
    assert not out["iforest_outlier"].any()


def test_missing_values_are_tolerated():
    df = actors(30)
    df.loc[0, "cv_interarrival"] = np.nan
    df.loc[1, "html_no_referer_ratio"] = np.nan
    assert score_actors(df)["iforest_score"].notna().all()
