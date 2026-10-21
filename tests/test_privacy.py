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
    r = Redactor("example.com", "example.com", "secretadm")
    assert r("/secretadm/") == "/<custom-login>/"
    assert r("example.com/secretadm") == "example.com/<custom-login>"
    assert r("https://example.com/secretadm/?x=1") == "https://example.com/<custom-login>/?x=1"
    assert r("/secretadmin") == "/secretadmin"


def test_redactor_slug_is_case_insensitive_and_bounded():
    r = Redactor("example.com", "example.com", "secretadm")
    assert r("/SecretAdm/") == "/<custom-login>/"
    assert r("/secretadm#x") == "/<custom-login>#x"
    assert r("/secretadm;a") == "/<custom-login>;a"
    assert r("/secretadm") == "/<custom-login>"
    assert r("GET /secretadm HTTP/1.1") == "GET /<custom-login> HTTP/1.1"
    assert r("/secretadmin/") == "/secretadmin/"


def test_redactor_slug_configured_with_slashes():
    r = Redactor("example.com", "example.com", "/secretadm/")
    assert r("/secretadm/") == "/<custom-login>/"
    assert r("https://example.com/secretadm?x") == "https://example.com/<custom-login>?x"


def test_redactor_slug_percent_encoded():
    r = Redactor("example.com", "example.com", "secretadm")
    assert r("/%73ecretadm/") == "/<custom-login>/"
    assert r("/%53ECRETADM/x") == "/<custom-login>/x"
    # Other percent-encoded text is left as is.
    assert r("/caf%C3%A9/") == "/caf%C3%A9/"


def test_redactor_author_archive_usernames():
    r = Redactor("example.com", "example.com", "")
    assert r("/author/jdoe/") == "/author/<author>"
    assert r("/author/jdoe") == "/author/<author>"
    assert r("https://example.com/author/j.doe?x=1") == "https://example.com/author/<author>?x=1"
    assert r("/author/jdoe#top") == "/author/<author>#top"
    assert r("/Author/JDoe/page/2/") == "/author/<author>"
    assert r("/coauthor/x") == "/coauthor/x"


def test_redactor_author_encoded_and_odd_forms():
    r = Redactor("", "", "")
    for path in ("/%61uthor/jdoe", "/author%2Fjdoe", "/author//jdoe", "/AUTHOR/jdoe/"):
        assert "jdoe" not in r(path)
    assert r("/author//jdoe") == "/author/<author>"
    assert r("/coauthor/x") == "/coauthor/x"
    for raw, want in {
        "/author/jdoe%20smith": "/author/<author>",
        "/author/j%2Fdoe": "/author/<author>",
        "/author/a%3Fb": "/author/<author>",
        "/foo%20bar/author/x": "/foo%20bar/author/<author>",
        "/author/jdoe?q=a%26b": "/author/<author>?q=a%26b",
        "/AUTHOR/jdoe/": "/author/<author>",
    }.items():
        assert r(raw) == want


def test_redactor_domain_case_insensitive():
    r = Redactor("example.com", "site.example", "")
    assert r("https://EXAMPLE.COM/") == "https://site.example/"


def test_redactor_replaces_domain_when_label_differs():
    r = Redactor("example.com", "site.example", "")
    assert r("WordPress/7.1.3; https://example.com") == "WordPress/7.1.3; https://site.example"


def test_redactor_replaces_site_name_in_paths():
    r = Redactor("acme-vet.example", "site.example", "")
    assert r("/wp-content/themes/acme-vet/logo.png") == "/wp-content/themes/site/logo.png"
    assert r("/wp-content/themes/ACME-VET/") == "/wp-content/themes/site/"
    assert r("https://acme-vet.example/x") == "https://site.example/x"
    assert r("/uploads/cat-acme-vet.webp") == "/uploads/cat-site.webp"


def test_redactor_hides_uploaded_media_names():
    r = Redactor("", "", "")
    assert r("/wp-content/uploads/2026/09/Jane-300x300-1.webp") == \
        "/wp-content/uploads/2026/09/<media>.webp"
    assert r("/wp-content/uploads/2021/04/1189_2722_n.JPG?x=1") == \
        "/wp-content/uploads/2021/04/<media>.JPG?x=1"
    assert r("https://a.example/wp-content/uploads/logo.png.webp") == \
        "https://a.example/wp-content/uploads/<media>.webp"
    # Attack probes stay visible.
    assert r("/wp-content/uploads/2025/11/amp.php") == "/wp-content/uploads/2025/11/amp.php"
    assert r("/wp-content/uploads/") == "/wp-content/uploads/"


def test_redactor_hides_email_addresses():
    r = Redactor("", "", "")
    assert r("/mailto:jane.doe+web@mail.example") == "/mailto:<email>"
    assert r("/contact/?to=a_b@c-d.co.uk") == "/contact/?to=<email>"
    assert r("/wp-content/x@2x.png") == "/wp-content/x@2x.png"


def test_redactor_noop_and_none():
    r = Redactor("", "", "")
    assert r("/a/b") == "/a/b"
    assert r(None) is None


def test_strip_query():
    assert strip_query("https://x.org/a?page=1") == "https://x.org/a"
    assert strip_query(None) is None
