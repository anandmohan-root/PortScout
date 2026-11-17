import gzip
import time

from portscout import monitor


def conn(dest_ip="93.184.216.34", host="example.com", program="app.exe", port=50000):
    return monitor.Conn(program, 1, port, dest_ip, 443, "ESTABLISHED", host, "US")


def test_baseline_then_new_destination_alert(tmp_path):
    store = monitor.Store(tmp_path / "h.db")
    assert store.baseline
    store.record([conn(), conn("8.8.8.8", "", port=49999)])
    store.end_baseline()
    assert store.unseen() == set()                    # learned silently on first run
    store.record([conn(), conn("1.2.3.4", "new.example", port=50001)])
    assert store.unseen() == {("app.exe", "new.example")}
    store.mark_seen([("app.exe", "new.example")])
    assert store.unseen() == set()
    store.record([conn("1.2.3.5", "cdn2.new.example", port=50003),     # same site, new address
                  conn("8.8.8.9", "", port=50004)])                     # no name, same /24
    assert store.unseen() == set()
    store.record([conn(host=None, dest_ip="5.6.7.8", port=50002)])   # name still looking up
    assert store.unseen() == set()
    assert not monitor.Store(tmp_path / "h.db").baseline              # later runs alert


def test_timeline_keeps_one_row_per_connection_and_prunes(tmp_path):
    store = monitor.Store(tmp_path / "h.db")
    now = time.time()
    store.record([conn()], now - 10)
    store.record([conn()], now)
    rows = store.timeline(now - 60)
    assert len(rows) == 1 and rows[0][4] == "example.com" and rows[0][1] == now
    assert store.timeline(now - 60, "other.exe") == []
    assert store.programs() == ["app.exe"]
    assert store.countries(now - 60) == {"US": 1}
    store.record([conn(port=1)], now - monitor.KEEP_SECONDS - 100)
    assert len(store.timeline(0)) == 2
    store.record([])
    assert len(store.timeline(0)) == 1                                 # pruned while running


def test_geo_lookup(tmp_path):
    f = tmp_path / "geo.csv.gz"
    with gzip.open(f, "wt") as g:
        g.write("1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\n2001:4860::,2001:4860:ffff::,US\n")
    geo = monitor.Geo(f)
    for _ in range(100):
        if geo.ready:
            break
        time.sleep(0.05)
    assert geo.country("8.8.8.8") == "US" and geo.country("1.0.0.7") == "AU"
    assert geo.country("2001:4860::8888") == "US"
    assert geo.country("9.9.9.9") == ""
    assert geo.country("192.168.1.5") == monitor.LOCAL


def test_site_groups_rotating_addresses():
    assert monitor.site("a23-208-178-10.deploy.static.akamaitechnologies.com", "23.208.178.10")         == "akamaitechnologies.com"
    assert monitor.site("www.bbc.co.uk", "1.1.1.1") == "bbc.co.uk"
    assert monitor.site("News.Example.com.", "1.1.1.1") == "example.com"
    assert monitor.site("MyPC", "::1") == "mypc"
    assert monitor.site("", "160.79.104.10") == "160.79.104.0/24"
    assert monitor.site(None, "2001:db8:1:2::5") == "2001:db8:1::/48"


def test_vendor_list_parse_save_and_lookup(monkeypatch):
    import pytest
    rows = [f"MA-L,{i:06X},Maker {i},Somewhere" for i in range(12000)]
    csv_text = "Registry,Assignment,Organization Name,Organization Address\n" + "\n".join(
        rows + ['MA-L,98:9D:B2,Bad,x', 'MA-L,989DB2,"Example  Router, Inc.",Addr'])
    vendors = monitor.parse_vendors(csv_text)
    assert vendors["989DB2"] == "Example Router, Inc." and "98:9D:B2" not in vendors
    with pytest.raises(ValueError):
        monitor.parse_vendors("<html>Access denied</html>")      # error page, not the list

    class Response:
        def __init__(self, *_a, **_k): pass
        def read(self): return csv_text.encode()
        def __enter__(self): return self
        def __exit__(self, *_): pass
    monkeypatch.setattr(monitor.urllib.request, "urlopen", Response)
    assert monitor.download_vendors() == len(vendors)
    loaded = monitor.load_vendors()
    assert monitor.vendor(loaded, "98:9d:b2:ef:ab:0f") == "Example Router, Inc."
    assert monitor.vendor(loaded, "1a:22:bb:b5:ec:bb") == "private MAC"
    assert monitor.vendor(loaded, "fc:ff:ff:00:00:01") == ""                   # unknown maker
