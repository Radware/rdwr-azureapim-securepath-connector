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
     "featuresData": {"wafFeatureData": {"mainDomain": {"mainDomain": "Shop.Example.Test"},
                                         "oopDns": {"dnsRecords": [{"type": "A", "value": "1.2.3.4"},
                                                                   {"type": "CNAME", "value": "aaaa.oop.radwarecloud.net"}]}}},
     "apiProtection": {"hostname": {"useDefault": False, "hostname": "api.example.test"}}},
    {"id": "22222222-2222-2222-2222-222222222222", "oopApiKey": "key-2", "applicationAssetType": "OUT_OF_PATH",
     "deploymentStatus": "PROTECTING",
     "featuresData": {"wafFeatureData": {"mainDomain": {"mainDomain": "www.example.test"},
                                         "oopDns": {"dnsRecords": [{"type": "CNAME", "value": "bbbb.oop.radwarecloud.net"}]}}}},
    {"id": "3", "oopApiKey": "key-3", "applicationAssetType": "OUT_OF_PATH", "deploymentStatus": "PROVISIONING",
     "featuresData": {"wafFeatureData": {"mainDomain": {"mainDomain": "new.example.test"}}}},
    {"id": "4", "oopApiKey": "key-4", "applicationAssetType": "CDN", "deploymentStatus": "PROTECTING"},
]


class FakeAz:
    """Serves a subscription id, sku, the current map and backends; records PUTs."""

    def __init__(self, sku="StandardV2", backends=None, current_map=None, secret=True):
        self.sku_name = sku
        self.backends = backends or []
        self.current_map = current_map
        self.secret = secret
        self.puts = []

    def __call__(self, args):
        if args[:2] == ["account", "show"]:
            return "sub-1\n"
        method, uri = args[2], args[4]
        if method == "GET" and uri.endswith("/backends?api-version=2024-05-01"):
            return json.dumps({"value": [{"name": n, "properties": {"url": u}} for n, u in self.backends]})
        if method == "GET" and "/namedValues/rdwr-app-map?" in uri:
            if self.current_map is None:
                return ""
            return json.dumps({"properties": {"secret": self.secret, "value": None if self.secret else self.current_map}})
        if method == "POST" and uri.endswith("/namedValues/rdwr-app-map/listValue?api-version=2024-05-01"):
            return json.dumps({"value": self.current_map})
        if method == "GET":
            return json.dumps({"sku": {"name": self.sku_name}})
        if method == "PUT":
            self.puts.append((uri, json.loads(args[8])))
            return ""
        raise AssertionError(args)


def test_projection_rules():
    m = sync.project_cloud_apps(APPS)
    assert set(m) == {"shop.example.test", "api.example.test", "www.example.test"}
    assert m["shop.example.test"]["endpoint"] == "aaaa.oop.radwarecloud.net"
    assert m["api.example.test"]["app_id"] == m["shop.example.test"]["app_id"]
    assert m["shop.example.test"]["port"] == 443 and m["shop.example.test"]["ssl"] is True
    assert sync.project_cloud_apps({"content": APPS}) == m


def test_render_map_is_single_quoted_and_rejects_unsafe_chars():
    r = sync.render_map(sync.project_cloud_apps(APPS))
    assert '"' not in r and r.startswith("{'api.example.test':")
    assert json.loads(r.replace("'", '"')) == sync.project_cloud_apps(APPS)
    try:
        sync.render_map({"x": {"app_id": "a&b"}})
        assert False
    except ValueError:
        pass


def test_diff_and_merge_keep_hand_written_entries():
    desired = sync.project_cloud_apps(APPS)
    current = {"orders-api": {"app_id": "manual", "api_key": "k", "endpoint": "cccc.oop.radwarecloud.net", "base_path": "/orders"},
               "old.example.test": {"app_id": "gone", "api_key": "k", "endpoint": "dddd.oop.radwarecloud.net"},
               "shop.example.test": {"app_id": "stale", "api_key": "key-old", "endpoint": "aaaa.oop.radwarecloud.net", "base_path": "/shop"}}
    added, changed, removed, unchanged = sync.diff_maps(current, desired)
    assert set(added) == {"api.example.test", "www.example.test"}
    assert set(changed) == {"shop.example.test"} and set(removed) == {"old.example.test"} and unchanged == {}
    merged = sync.merge(current, desired, prune=False)
    assert merged["orders-api"]["base_path"] == "/orders"
    assert merged["shop.example.test"]["app_id"] == "11111111-1111-1111-1111-111111111111"
    assert merged["shop.example.test"]["base_path"] == "/shop"
    assert "old.example.test" in merged
    assert "old.example.test" not in sync.merge(current, desired, prune=True)


def test_apply_writes_only_when_something_changes_and_creates_backends_once():
    desired = sync.project_cloud_apps(APPS)
    az = FakeAz()
    assert sync.apply(sync.AzWriter("rg", "apim", run=az), desired, log=lambda *_: None) == 0
    uris = [u for u, _ in az.puts]
    assert sum("/namedValues/rdwr-app-map?" in u for u in uris) == 1
    assert sum("/backends/securepath-sideband-" in u for u in uris) == 2
    assert '"' not in az.puts[0][1]["properties"]["value"] and az.puts[0][1]["properties"]["secret"] is True
    az2 = FakeAz(current_map=sync.render_map(desired),
                 backends=[("securepath-sideband-1", "https://aaaa.oop.radwarecloud.net"), ("securepath-sideband-2", "https://bbbb.oop.radwarecloud.net")])
    assert sync.apply(sync.AzWriter("rg", "apim", run=az2), desired, log=lambda *_: None) == 0
    assert az2.puts == []


def test_check_reports_drift_and_v1_tiers_need_no_backends():
    desired = sync.project_cloud_apps(APPS)
    az = FakeAz(sku="Developer", current_map=sync.render_map(desired), backends=[])
    assert sync.check(sync.AzWriter("rg", "apim", run=az), desired, log=lambda *_: None) == 0
    az_drift = FakeAz(sku="Developer", current_map="##DISABLED##")
    assert sync.check(sync.AzWriter("rg", "apim", run=az_drift), desired, log=lambda *_: None) == 1


def test_export_writes_a_bicep_parameter_file(tmp_path):
    out = tmp_path / "p.json"
    assert sync.export_parameters(sync.project_cloud_apps(APPS), str(out), log=lambda *_: None) == 0
    assert json.loads(out.read_text())["parameters"]["appMap"]["value"]["www.example.test"]["endpoint"] == "bbbb.oop.radwarecloud.net"
