import pytest

from botforensics.config import Settings


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        es_url="http://localhost:9200",
        elastic_password="",
        kibana_url="http://localhost:5601",
        pseudo_key="test-key",
        site_domain="site.example",
        site_label="site.example",
        custom_login_slug="secretadm",
        asn_db=tmp_path / "missing-asn.mmdb",
        country_db=tmp_path / "missing-country.mmdb",
        internal_networks=(),
    )

