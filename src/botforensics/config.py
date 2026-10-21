"""Runtime settings, read from environment variables and an optional .env file."""

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

DEV_KEY = "dev-only-key"


@dataclass(frozen=True)
class Settings:
    es_url: str
    elastic_password: str
    kibana_url: str
    pseudo_key: str
    site_domain: str
    site_label: str
    custom_login_slug: str
    asn_db: Path
    country_db: Path
    internal_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


def parse_networks(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid INTERNAL_IPS item: {item!r}") from exc
    return tuple(networks)


def load_settings(env_file: str | None = ".env") -> Settings:
    if env_file and Path(env_file).exists():
        load_dotenv(env_file, override=False)
    domain = os.getenv("SITE_DOMAIN", "")
    return Settings(
        es_url=os.getenv("ES_URL", "http://localhost:9200"),
        elastic_password=os.getenv("ELASTIC_PASSWORD", ""),
        kibana_url=os.getenv("KIBANA_URL", "http://localhost:5601"),
        pseudo_key=os.getenv("PSEUDO_KEY", DEV_KEY),
        site_domain=domain,
        site_label=os.getenv("SITE_LABEL", domain),
        custom_login_slug=os.getenv("CUSTOM_LOGIN_SLUG", ""),
        asn_db=Path(os.getenv("ASN_DB", "data/geo/dbip-asn-lite.mmdb")),
        country_db=Path(os.getenv("COUNTRY_DB", "data/geo/dbip-country-lite.mmdb")),
        internal_networks=parse_networks(os.getenv("INTERNAL_IPS", "")),
    )
