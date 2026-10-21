"""Elasticsearch: explicit mappings and bulk indexing."""

import json
from importlib import resources

import pandas as pd
from elasticsearch import Elasticsearch, helpers

from botforensics.config import Settings

INDEXES = {
    "weblogs-requests": "requests.json",
    "weblogs-actors": "actors.json",
    "cerber-events": "cerber_events.json",
}


def load_mapping(index: str) -> dict:
    text = resources.files("botforensics").joinpath("mappings", INDEXES[index]).read_text()
    return json.loads(text)


def connect(settings: Settings) -> Elasticsearch:
    es = Elasticsearch(settings.es_url, basic_auth=("elastic", settings.elastic_password),
                       request_timeout=120)
    es.info()  # fail fast on wrong password or stopped cluster
    return es


def to_documents(df: pd.DataFrame, time_col: str | None) -> list[dict]:
    # to_json handles NaN/NA → null, numpy scalars and ISO-8601 dates in one pass.
    docs = json.loads(df.to_json(orient="records", date_format="iso", date_unit="s"))
    if time_col:
        for doc in docs:
            doc["@timestamp"] = doc.pop(time_col)
    return docs


def index_dataframe(es: Elasticsearch, index: str, df: pd.DataFrame,
                    time_col: str | None) -> int:
    body = load_mapping(index)
    es.indices.delete(index=index, ignore_unavailable=True)
    es.indices.create(index=index, settings=body["settings"], mappings=body["mappings"])
    actions = ({"_index": index, "_source": doc} for doc in to_documents(df, time_col))
    ok, errors = helpers.bulk(es, actions, chunk_size=2000, raise_on_error=False)
    if errors:
        raise RuntimeError(f"{len(errors)} bulk errors, first: {errors[0]}")
    es.indices.refresh(index=index)
    return ok
