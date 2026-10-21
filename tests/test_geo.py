from botforensics.geo import EMPTY_INFO, GeoLookup, IpInfo, load_sidecar, write_sidecar


def test_sidecar_roundtrip_and_lookup(tmp_path):
    path = tmp_path / "ip_info.csv"
    infos = {"ip-0123456789abcdef": IpInfo(8075, "Microsoft Corporation", "IN")}
    write_sidecar(path, infos)
    loaded = load_sidecar(path)
    assert loaded == infos
    geo = GeoLookup(None, None, loaded)
    assert geo.lookup("ip-0123456789abcdef").as_org == "Microsoft Corporation"
    assert geo.lookup("ip-ffffffffffffffff") == EMPTY_INFO


def test_sidecar_roundtrip_with_allowlisted(tmp_path):
    path = tmp_path / "ip_info.csv"
    infos = {"ip-0123456789abcdef": IpInfo(1, "Orange", "NC", True),
             "ip-fedcba9876543210": IpInfo(2, "X", "FR")}
    write_sidecar(path, infos)
    header = path.read_text(encoding="utf-8").splitlines()[0]
    assert header == "ip_hash,asn,as_org,country,allowlisted"
    assert load_sidecar(path) == infos


def test_sidecar_without_allowlisted_column(tmp_path):
    path = tmp_path / "ip_info.csv"
    path.write_text("ip_hash,asn,as_org,country\nip-0123456789abcdef,1,Orange,NC\n",
                    encoding="utf-8")
    assert load_sidecar(path) == {"ip-0123456789abcdef": IpInfo(1, "Orange", "NC", False)}


def test_missing_databases_return_empty(tmp_path, caplog):
    with caplog.at_level("WARNING", logger="botforensics.geo"):
        geo = GeoLookup(tmp_path / "nope.mmdb", tmp_path / "nope2.mmdb")
    assert "nope.mmdb" in caplog.text
    assert "nope2.mmdb" in caplog.text
    assert geo.lookup("203.0.113.7") == EMPTY_INFO
