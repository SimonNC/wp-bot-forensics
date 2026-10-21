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


def test_missing_databases_return_empty(tmp_path):
    geo = GeoLookup(tmp_path / "nope.mmdb", tmp_path / "nope2.mmdb")
    assert geo.lookup("203.0.113.7") == EMPTY_INFO
