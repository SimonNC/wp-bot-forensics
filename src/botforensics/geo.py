"""IP → ASN / country lookups (DB-IP Lite mmdb) with a sidecar for pseudonymised samples."""

import csv
import logging
from dataclasses import dataclass
from pathlib import Path

import maxminddb

from botforensics.privacy import is_pseudonym


@dataclass(frozen=True)
class IpInfo:
    asn: int | None
    as_org: str | None
    country: str | None


EMPTY_INFO = IpInfo(None, None, None)


logger = logging.getLogger(__name__)


def _open(path: Path | None):
    if not path:
        return None
    if not Path(path).exists():
        logger.warning("GeoIP database not found: %s", path)
        return None
    return maxminddb.open_database(str(path))


class GeoLookup:
    def __init__(self, asn_db: Path | None, country_db: Path | None,
                 sidecar: dict[str, IpInfo] | None = None):
        self.asn_reader = _open(asn_db)
        self.country_reader = _open(country_db)
        self.sidecar = sidecar or {}
        self._cache: dict[str, IpInfo] = {}

    def lookup(self, host: str) -> IpInfo:
        if is_pseudonym(host):
            return self.sidecar.get(host, EMPTY_INFO)
        if host not in self._cache:
            self._cache[host] = self._lookup_ip(host)
        return self._cache[host]

    def _lookup_ip(self, ip: str) -> IpInfo:
        try:
            asn = self.asn_reader.get(ip) if self.asn_reader else None
            country = self.country_reader.get(ip) if self.country_reader else None
        except ValueError:  # not an IP address
            return EMPTY_INFO
        asn = asn or {}
        country = (country or {}).get("country") or {}
        return IpInfo(
            asn.get("autonomous_system_number"),
            asn.get("autonomous_system_organization"),
            country.get("iso_code"),
        )


def load_sidecar(path: Path) -> dict[str, IpInfo]:
    with path.open(encoding="utf-8", newline="") as fh:
        return {
            row["ip_hash"]: IpInfo(
                int(row["asn"]) if row["asn"] else None,
                row["as_org"] or None,
                row["country"] or None,
            )
            for row in csv.DictReader(fh)
        }


def write_sidecar(path: Path, infos: dict[str, IpInfo]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip_hash", "asn", "as_org", "country"])
        for ip_hash, info in sorted(infos.items()):
            writer.writerow([ip_hash, info.asn or "", info.as_org or "", info.country or ""])
