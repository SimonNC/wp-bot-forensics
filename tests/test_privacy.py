from botforensics.privacy import (
    Redactor,
    is_ip,
    is_pseudonym,
    pseudonymise,
    strip_query,
)


def test_pseudonymise_is_deterministic_and_keyed():
    a = pseudonymise("203.0.113.7", "k1")
    assert a == pseudonymise("203.0.113.7", "k1")
    assert a != pseudonymise("203.0.113.7", "k2")
    assert a.startswith("ip-") and len(a) == 3 + 16
    int(a[3:], 16)  # pure hex digest, nothing of the IP left


def test_username_prefix():
    assert pseudonymise("admin", "k", prefix="user-").startswith("user-")


def test_is_ip_and_is_pseudonym():
    assert is_ip("203.0.113.7") and is_ip("2001:db8::1")
    assert not is_ip("ip-0123456789abcdef")
    assert is_pseudonym(pseudonymise("203.0.113.7", "k"))
    assert not is_pseudonym("203.0.113.7")
    assert not is_pseudonym("ip-zzzzzzzzzzzzzzzz")
    assert is_pseudonym(pseudonymise("bob", "k", prefix="user-"), "user-")


def test_redactor_replaces_login_slug_as_path_segment_only():
    r = Redactor("site.example", "site.example", "secretadm")
    assert r("/secretadm/") == "/<custom-login>/"
    assert r("site.example/secretadm") == "site.example/<custom-login>"
    assert r("https://site.example/secretadm/?x=1") == "https://site.example/<custom-login>/?x=1"
    assert r("/secretadmin") == "/secretadmin"


def test_redactor_slug_is_case_insensitive_and_bounded():
    r = Redactor("site.example", "site.example", "secretadm")
    assert r("/SecretAdm/") == "/<custom-login>/"
    assert r("/secretadm#x") == "/<custom-login>#x"
    assert r("/secretadm;a") == "/<custom-login>;a"
    assert r("/secretadm") == "/<custom-login>"
    assert r("GET /secretadm HTTP/1.1") == "GET /<custom-login> HTTP/1.1"
    assert r("/secretadmin/") == "/secretadmin/"


def test_redactor_slug_configured_with_slashes():
    r = Redactor("site.example", "site.example", "/secretadm/")
    assert r("/secretadm/") == "/<custom-login>/"
    assert r("https://site.example/secretadm?x") == "https://site.example/<custom-login>?x"


def test_redactor_slug_percent_encoded():
    r = Redactor("site.example", "site.example", "secretadm")
    assert r("/%73ecretadm/") == "/<custom-login>/"
    assert r("/%53ECRETADM/x") == "/<custom-login>/x"
    # Other percent-encoded text is left as is.
    assert r("/caf%C3%A9/") == "/caf%C3%A9/"


def test_redactor_author_archive_usernames():
    r = Redactor("site.example", "site.example", "")
    assert r("/author/jdoe/") == "/author/<author>/"
    assert r("/author/jdoe") == "/author/<author>"
    assert r("https://site.example/author/j.doe?x=1") == "https://site.example/author/<author>?x=1"
    assert r("/author/jdoe#top") == "/author/<author>#top"
    assert r("/Author/JDoe/page/2/") == "/Author/<author>/page/2/"
    assert r("/coauthor/x") == "/coauthor/x"


def test_redactor_author_encoded_and_odd_forms():
    r = Redactor("", "", "")
    for path in ("/%61uthor/jdoe", "/author%2Fjdoe", "/author//jdoe", "/AUTHOR/jdoe/"):
        assert "jdoe" not in r(path)
    assert r("/author//jdoe") == "/author/<author>"
    assert r("/coauthor/x") == "/coauthor/x"


def test_redactor_domain_case_insensitive():
    r = Redactor("site.example", "site.example", "")
    assert r("https://site.example/") == "https://site.example/"


def test_redactor_replaces_domain_when_label_differs():
    r = Redactor("site.example", "site.example", "")
    assert r("WordPress/7.1.3; https://site.example") == "WordPress/7.1.3; https://site.example"


def test_redactor_noop_and_none():
    r = Redactor("", "", "")
    assert r("/a/b") == "/a/b"
    assert r(None) is None


def test_strip_query():
    assert strip_query("https://x.org/a?page=1") == "https://x.org/a"
    assert strip_query(None) is None
