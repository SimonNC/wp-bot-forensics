"""Download DB-IP Lite ASN and country databases (CC BY 4.0) into data/geo/."""

import gzip
import shutil
import sys
from datetime import date
from pathlib import Path

import requests

DEST = Path("data/geo")
URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"


def months() -> list[str]:
    today = date.today().replace(day=1)
    previous = (today.replace(year=today.year - 1, month=12) if today.month == 1
                else today.replace(month=today.month - 1))
    return [today.strftime("%Y-%m"), previous.strftime("%Y-%m")]


def download(kind: str) -> Path:
    target = DEST / f"dbip-{kind}-lite.mmdb"
    for month in months():
        resp = requests.get(URL.format(kind=kind, month=month), stream=True, timeout=120)
        if resp.status_code == 200:
            gz = target.with_suffix(".mmdb.gz")
            with gz.open("wb") as fh:
                shutil.copyfileobj(resp.raw, fh)
            with gzip.open(gz, "rb") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            gz.unlink()
            print(f"{kind}: {month} -> {target}")
            return target
    sys.exit(f"no DB-IP {kind} database found for {months()}")


if __name__ == "__main__":
    DEST.mkdir(parents=True, exist_ok=True)
    download("asn")
    download("country")
