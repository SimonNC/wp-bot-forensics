"""End-to-end pipeline: raw files → enriched requests, actors and Cerber events."""

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from botforensics.anomaly import score_actors
from botforensics.cerber import cerber_verdicts, empty_events, prepare_events, read_activity
from botforensics.config import DEV_KEY, Settings
from botforensics.enrich import enrich_requests
from botforensics.features import actor_features
from botforensics.geo import GeoLookup, load_sidecar
from botforensics.parse import ParseStats, parse_file
from botforensics.privacy import Redactor, is_ip
from botforensics.rules import classify_actors


@dataclass
class Result:
    requests: pd.DataFrame
    actors: pd.DataFrame
    events: pd.DataFrame
    stats: ParseStats


def find_inputs(data_dir: Path) -> tuple[list[Path], list[Path], Path | None]:
    apache = sorted((data_dir / "apache").glob("*.log*"))
    cerber = sorted((data_dir / "cerber").glob("*activity*.csv"))
    sidecar = data_dir / "ip_info.csv"
    return apache, cerber, sidecar if sidecar.exists() else None


def _check_key(settings: Settings, hosts) -> None:
    if settings.pseudo_key == DEV_KEY and any(is_ip(h) for h in hosts):
        raise RuntimeError("Real IP addresses found: set a secret PSEUDO_KEY in .env first")


def run(data_dir: Path, settings: Settings) -> Result:
    apache, cerber_files, sidecar = find_inputs(data_dir)
    geo = GeoLookup(settings.asn_db, settings.country_db,
                    load_sidecar(sidecar) if sidecar else None)
    redact = Redactor(settings.site_domain, settings.site_label, settings.custom_login_slug)

    stats = ParseStats()
    parsed = [r for path in apache for r in parse_file(path, stats)]
    _check_key(settings, (r.host for r in parsed))
    requests = enrich_requests(parsed, geo, settings.pseudo_key, redact, settings.site_label)

    raw_events = [read_activity(path) for path in cerber_files]
    for raw in raw_events:
        _check_key(settings, raw["ip"])
    events = (pd.concat([prepare_events(raw, settings.pseudo_key, redact, geo)
                         for raw in raw_events], ignore_index=True)
              if raw_events else empty_events())

    actors = actor_features(requests).merge(cerber_verdicts(events), on="ip_hash", how="left")
    actors["cerber_events"] = actors["cerber_events"].fillna(0).astype(int)
    actors["cerber_verdict"] = actors["cerber_verdict"].astype("string")
    actors = score_actors(classify_actors(actors))
    requests["actor_category"] = requests["ip_hash"].map(
        actors.set_index("ip_hash")["category"])
    return Result(requests, actors, events, stats)


def write_parquet(result: Result, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    result.requests.to_parquet(out_dir / "requests.parquet", index=False)
    result.actors.to_parquet(out_dir / "actors.parquet", index=False)
    result.events.to_parquet(out_dir / "cerber_events.parquet", index=False)
