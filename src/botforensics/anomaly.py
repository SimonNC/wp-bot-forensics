"""Isolation Forest over actor features: surfaces automated actors the rules missed."""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

MODEL_FEATURES = ["n_requests", "peak_rpm", "cv_interarrival", "rate_4xx", "rate_403",
                  "sensitive_probes", "login_posts", "login_posts_10min_max", "robots_reads",
                  "sitemap_reads", "html_no_referer_ratio", "static_ratio", "night_ratio",
                  "form_posts", "distinct_paths", "distinct_uas", "is_datacenter"]
# Heavy-tailed counts: log scale so one huge attacker does not flatten everyone else.
LOG_FEATURES = ["n_requests", "peak_rpm", "sensitive_probes", "login_posts",
                "login_posts_10min_max", "robots_reads", "sitemap_reads", "form_posts",
                "distinct_paths", "distinct_uas"]
MIN_ACTORS = 10


def score_actors(actors: pd.DataFrame, contamination: float = 0.05,
                 seed: int = 42) -> pd.DataFrame:
    out = actors.copy()
    if len(out) < MIN_ACTORS:
        out["iforest_score"] = float("nan")
        out["iforest_outlier"] = False
        return out
    x = out[MODEL_FEATURES].astype(float)
    x["cv_interarrival"] = x["cv_interarrival"].fillna(1.0)  # too few requests: neutral
    x["html_no_referer_ratio"] = x["html_no_referer_ratio"].fillna(0.0)
    x[LOG_FEATURES] = np.log1p(x[LOG_FEATURES])
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(x)
    out["iforest_score"] = -model.score_samples(x)
    out["iforest_outlier"] = model.predict(x) == -1
    return out
