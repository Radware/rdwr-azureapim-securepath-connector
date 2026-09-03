import importlib.util
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("sync", os.path.join(HERE, "..", "securepath-apim-sync.py"))
sync = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync)

APPS = [
    {"id": "11111111-1111-1111-1111-111111111111", "oopApiKey": "key-1", "applicationAssetType": "OUT_OF_PATH",
     "deploymentStatus": "PROTECTING",
     "featuresData": {"wafFeatureData": {"mainDomain": {"mainDomain": "shop.example.test"},
                                         "oopDns": {"dnsRecords": [{"type": "CNAME", "value": "aaaa.oop.radwarecloud.net"}]}}}},
    {"id": "22222222-2222-2222-2222-222222222222", "oopApiKey": "key-2", "applicationAssetType": "OUT_OF_PATH",
     "deploymentStatus": "PROTECTING",
     "featuresData": {"wafFeatureData": {"mainDomain": {"mainDomain": "api.example.test"},
                                         "oopDns": {"dnsRecords": [{"type": "CNAME", "value": "aaaa.oop.radwarecloud.net"}]}}}},
]


class FakeAz:
    """Records az rest calls; serves a subscription id, sku and backends."""

    def __init__(self, sku="StandardV2", backends=None):
        self.sku_name = sku
        self.backends = backends or []
        self.puts = []

    def __call__(self, args):
        if args[:2] == ["account", "show"]:
            return "sub-1\n"
        if args[2] == "GET" and args[4].endswith("/backends?api-version=2024-05-01"):
            return json.dumps({"value": [{"name": n, "properties": {"url": u}} for n, u in self.backends]})
        if args[2] == "GET":
            return json.dumps({"sku": {"name": self.sku_name}})
        if args[2] == "PUT":
            self.puts.append((args[4], json.loads(args[8])))
            return ""
        raise AssertionError(args)


def test_render_map_is_single_quoted_and_rejects_unsafe_chars():
    m = sync.project_cloud_apps(APPS)
    r = sync.render_map(m)
    assert '"' not in r and r.startswith("{'api.example.test': {'api_key': 'key-2'")
    assert json.loads(r.replace("'", '"')) == m
    try:
        sync.render_map({"x": {"app_id": "a&b"}})
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_sync_writes_map_and_one_backend_per_distinct_endpoint():
    az = FakeAz()
    w = sync.AzWriter("rg", "apim", run=az)
    rc, m = sync.sync(w, APPS, log=lambda *_: None)
    assert rc == 0 and set(m) == {"shop.example.test", "api.example.test"}
    paths = [p for p, _ in az.puts]
    assert paths[0].endswith("/namedValues/rdwr-app-map?api-version=2024-05-01")
    assert az.puts[0][1]["properties"]["secret"] is True and '"' not in az.puts[0][1]["properties"]["value"]
    assert len(paths) == 2 and "/backends/securepath-sideband-1?" in paths[1]
    assert az.puts[1][1]["properties"]["url"] == "https://aaaa.oop.radwarecloud.net"


def test_sync_is_idempotent_and_skips_backends_on_v1_tiers():
    az = FakeAz(backends=[("securepath-sideband", "https://aaaa.oop.radwarecloud.net")])
    sync.sync(sync.AzWriter("rg", "apim", run=az), APPS, log=lambda *_: None)
    assert len(az.puts) == 1  # map only, backend already there
    az2 = FakeAz(sku="Developer")
    sync.sync(sync.AzWriter("rg", "apim", run=az2), APPS, log=lambda *_: None)
    assert len(az2.puts) == 1


def test_dry_run_writes_nothing_and_no_apps_returns_1():
    az = FakeAz()
    rc, _ = sync.sync(sync.AzWriter("rg", "apim", run=az), APPS, dry_run=True, log=lambda *_: None)
    assert rc == 0 and az.puts == []
    rc, _ = sync.sync(sync.AzWriter("rg", "apim", run=az), [], log=lambda *_: None)
    assert rc == 1 and az.puts == []
