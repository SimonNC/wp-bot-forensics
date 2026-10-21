from pathlib import Path

from botforensics.config import DEV_KEY, load_settings


def test_defaults_without_env_file(monkeypatch):
    for var in ("PSEUDO_KEY", "SITE_DOMAIN", "SITE_LABEL", "CUSTOM_LOGIN_SLUG", "ASN_DB"):
        monkeypatch.delenv(var, raising=False)
    s = load_settings(env_file=None)
    assert s.pseudo_key == DEV_KEY
    assert s.site_domain == ""
    assert s.site_label == ""
    assert s.asn_db == Path("data/geo/dbip-asn-lite.mmdb")


def test_site_label_defaults_to_domain(monkeypatch):
    monkeypatch.setenv("SITE_DOMAIN", "example.org")
    monkeypatch.delenv("SITE_LABEL", raising=False)
    assert load_settings(env_file=None).site_label == "example.org"


def test_env_file_is_read(tmp_path, monkeypatch):
    # setenv then delenv: monkeypatch restores the original state, so load_dotenv cannot leak.
    monkeypatch.setenv("CUSTOM_LOGIN_SLUG", "placeholder")
    monkeypatch.delenv("CUSTOM_LOGIN_SLUG")
    env = tmp_path / ".env"
    env.write_text("CUSTOM_LOGIN_SLUG=secretadm\n")
    assert load_settings(env_file=str(env)).custom_login_slug == "secretadm"
