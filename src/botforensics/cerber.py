"""WP Cerber activity log export (CSV, French labels) → events and per-IP verdicts."""

import io
from pathlib import Path

import pandas as pd

from botforensics.geo import GeoLookup
from botforensics.privacy import Redactor, is_pseudonym, pseudonymise, strip_query

# Original column names, used when writing the pseudonymised sample.
CERBER_HEADER = ["Adresse IP", "Événement", "Statut", "Nom d’utilisateur",
                 "Unix Timestamp", "URL"]
COLUMN_MAP = {"adresse ip": "ip", "événement": "event", "statut": "status",
              "nom d'utilisateur": "username", "unix timestamp": "unix_ts", "url": "url"}
EVENT_GROUPS = {
    "sous-réseau ip verrouillé": "locked",
    "adresse ip verrouillée": "locked",
    "compte temporairement verrouillé": "locked",
    "analyse du code vulnérable": "malicious_request",
    "requête malveillante refusée": "malicious_request",
    "tentative d'accès à une url interdite": "malicious_request",
    "requête vers l'api rest refusée": "api_refused",
    "requête vers l'api xml-rpc refusée": "api_refused",
    "envoi du formulaire refusé": "form_refused",
    "tentative de connexion avec un nom d'utilisateur inexistant": "login_failed",
    "échec de la connexion": "login_failed",
    "tentative de connexion refusée": "login_failed",
    "connecté": "logged_in",
}
VERDICT_PRIORITY = ["locked", "malicious_request", "login_failed", "form_refused",
                    "api_refused", "logged_in"]
EVENT_DTYPES = {"timestamp": "datetime64[ns, UTC]", "ip_hash": "string", "asn": "Float64",
                "as_org": "string", "country": "string", "event": "string",
                "event_group": "string", "status": "string", "username_hash": "string",
                "url": "string"}
EVENT_COLUMNS = list(EVENT_DTYPES)


def empty_events() -> pd.DataFrame:
    # Typed even when empty, so Parquet/DuckDB see real column types, not NULL.
    return pd.DataFrame({col: pd.Series(dtype=dtype) for col, dtype in EVENT_DTYPES.items()})


def _norm(text: str) -> str:
    return text.replace("’", "'").strip().lower()


def read_activity(path: Path) -> pd.DataFrame:
    lines = path.read_text(encoding="utf-8-sig").splitlines(keepends=True)
    header = next(i for i, line in enumerate(lines) if _norm(line).startswith('"adresse ip"'))
    df = pd.read_csv(io.StringIO("".join(lines[header:])), dtype=str, keep_default_na=False)
    df = df.rename(columns={c: COLUMN_MAP[_norm(c)] for c in df.columns if _norm(c) in COLUMN_MAP})
    df = df[["ip", "event", "status", "username", "url", "unix_ts"]].copy()
    df["timestamp"] = pd.to_datetime(df.pop("unix_ts").astype(float), unit="s", utc=True)
    return df


def prepare_events(raw: pd.DataFrame, key: str, redact: Redactor,
                   geo: GeoLookup) -> pd.DataFrame:
    if raw.empty:
        return empty_events()
    infos = raw["ip"].map(geo.lookup)
    ev = pd.DataFrame({
        "timestamp": raw["timestamp"],
        "ip_hash": raw["ip"].map(lambda v: v if is_pseudonym(v) else pseudonymise(v, key)),
        "asn": infos.map(lambda i: i.asn).astype("Float64"),
        "as_org": infos.map(lambda i: i.as_org),
        "country": infos.map(lambda i: i.country),
        "event": raw["event"],
        "event_group": raw["event"].map(lambda e: EVENT_GROUPS.get(_norm(e), "other")),
        "status": raw["status"].replace("", None),
        "username_hash": raw["username"].map(
            lambda u: None if not u else (u if is_pseudonym(u, "user-")
                                          else pseudonymise(u, key, prefix="user-"))),
        "url": raw["url"].map(lambda u: strip_query(redact(u)) if u else None),
    })
    return ev.astype(EVENT_DTYPES).reset_index(drop=True)


def cerber_verdicts(events: pd.DataFrame) -> pd.DataFrame:
    if events.empty:
        return pd.DataFrame({"ip_hash": pd.Series(dtype="string"),
                             "cerber_verdict": pd.Series(dtype="string"),
                             "cerber_events": pd.Series(dtype="int64")})
    rank = {group: i for i, group in enumerate(VERDICT_PRIORITY)}
    ranked = events[events["event_group"].isin(rank)].assign(
        rank=lambda d: d["event_group"].map(rank))
    best = ranked.sort_values("rank").groupby("ip_hash")["event_group"].first()
    counts = events.groupby("ip_hash").size()
    out = pd.DataFrame({"cerber_verdict": best, "cerber_events": counts})
    out["cerber_verdict"] = out["cerber_verdict"].astype("string")
    return out.rename_axis("ip_hash").reset_index()
