import importlib.util
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("sync", os.path.join(HERE, "..", "securepath-apim-sync.py"))
sync = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync)

APPS = [
    {"id": "11111111-1111-1111-1111-111111111111", "oopApiKey": "SECRET-ONE", "applicationAssetType": "OUT_OF_PATH",
     "deploymentStatus": "PROTECTING",
     "featuresData": {"wafFeatureData": {"mainDomain": {"mainDomain": "Shop.Example.Test"},
                                         "oopDns": {"dnsRecords": [{"type": "A", "value": "1.2.3.4"},
                                                                   {"type": "CNAME", "value": "aaaa.oop.radwarecloud.net"}]}}},
     "apiProtection": {"hostname": {"useDefault": False, "hostname": "api.example.test"}}},
    {"id": "22222222-2222-2222-2222-222222222222", "oopApiKey": "SECRET-TWO", "applicationAssetType": "OUT_OF_PATH",
     "deploymentStatus": "PROTECTING",
     "featuresData": {"wafFeatureData": {"mainDomain": {"mainDomain": "www.example.test"},
                                         "oopDns": {"dnsRecords": [{"type": "CNAME", "value": "bbbb.oop.radwarecloud.net"}]}}}},
    {"id": "3", "oopApiKey": "key-3", "applicationAssetType": "OUT_OF_PATH", "deploymentStatus": "PROVISIONING",
     "featuresData": {"wafFeatureData": {"mainDomain": {"mainDomain": "new.example.test"}}}},
    {"id": "4", "oopApiKey": "key-4", "applicationAssetType": "CDN", "deploymentStatus": "PROTECTING"},
]
K1 = sync.key_nv_name("11111111-1111-1111-1111-111111111111")
K2 = sync.key_nv_name("22222222-2222-2222-2222-222222222222")


class FakeAz:
    """Serves a subscription id, sku, the generated fragment, key Named Values and backends;
    records PUTs and DELETEs."""

    def __init__(self, sku="StandardV2", backends=None, fragment=None, keys=None):
        self.sku_name = sku
        self.backends = backends or []
        self.fragment = fragment  # None = not registered, else fragment text
        self.keys = dict(keys or {})  # nv name -> secret value
        self.puts, self.deletes = [], []

    def __call__(self, args):
        if args[:2] == ["account", "show"]:
            return "sub-1\n"
        method, uri = args[2], args[4]
        if method == "GET" and "/policyFragments/securepath-app-map?" in uri:
            return self.fragment or ""
        if method == "GET" and uri.endswith("/backends?api-version=2024-05-01"):
            return json.dumps({"value": [{"name": n, "properties": {"url": u}} for n, u in self.backends]})
        if method == "GET" and uri.endswith("/namedValues?api-version=2024-05-01"):
            return json.dumps({"value": [{"name": n, "properties": {"secret": True}} for n in self.keys]})
        if method == "POST" and "/listValue?" in uri:
            name = uri.split("/namedValues/")[1].split("/")[0]
            return json.dumps({"value": self.keys.get(name)})
        if method == "GET":
            return json.dumps({"sku": {"name": self.sku_name}})
        if method == "PUT":
            body = json.loads(args[8])
            self.puts.append((uri, body))
            if "/namedValues/" in uri:
                self.keys[uri.split("/namedValues/")[1].split("?")[0]] = body["properties"]["value"]
            if "/policyFragments/" in uri:
                self.fragment = body["properties"]["value"]
            return ""
        if method == "DELETE":
            self.deletes.append(uri)
            self.keys.pop(uri.split("/namedValues/")[1].split("?")[0], None)
            return ""
        raise AssertionError(args)


def test_projection_rules():
    m = sync.project_cloud_apps(APPS)
    assert set(m) == {"shop.example.test", "api.example.test", "www.example.test"}
    assert m["shop.example.test"]["endpoint"] == "aaaa.oop.radwarecloud.net"
    assert m["api.example.test"]["app_id"] == m["shop.example.test"]["app_id"]
    assert m["shop.example.test"]["port"] == 443 and m["shop.example.test"]["ssl"] is True
    assert sync.project_cloud_apps({"content": APPS}) == m


def test_fragment_carries_key_references_not_keys_and_round_trips():
    desired = sync.project_cloud_apps(APPS)
    text = sync.render_fragment(desired)
    assert "SECRET-ONE" not in text and "SECRET-TWO" not in text
    assert "{{" + K1 + "}}" in text and "{{" + K2 + "}}" in text
    assert '"' not in text.split('value="', 1)[1].split('" />')[0]
    back = sync.parse_fragment(text)
    assert set(back) == set(desired)
    assert back["www.example.test"]["api_key"] == "{{" + K2 + "}}"
    assert sync.parse_fragment(open(os.path.join(HERE, "..", "..", "fragments", "securepath-app-map.fragment.xml")).read()) == {}


def test_key_nv_name_is_stable_and_safe():
    assert K1 == "rdwr-app-key-11111111111111111111111111111111"
    assert sync.key_nv_name("Abc-DEF") == "rdwr-app-key-abcdef"


def test_diff_detects_changed_key_through_the_named_value():
    desired = sync.project_cloud_apps(APPS)
    current = sync.parse_fragment(sync.render_fragment(desired))
    keys = {K1: "SECRET-ONE", K2: "SECRET-OLD"}
    added, changed, removed, unchanged = sync.diff_maps(current, desired, keys)
    assert not added and not removed
    assert set(changed) == {"www.example.test"} and set(unchanged) == {"shop.example.test", "api.example.test"}


def test_apply_writes_keys_fragment_and_backends_then_is_idempotent():
    desired = sync.project_cloud_apps(APPS)
    az = FakeAz()
    assert sync.apply(sync.AzWriter("rg", "apim", run=az), desired, log=lambda *_: None) == 0
    uris = [u for u, _ in az.puts]
    assert sum("/namedValues/rdwr-app-key-" in u for u in uris) == 2
    assert sum("/policyFragments/securepath-app-map?" in u for u in uris) == 1
    assert sum("/backends/securepath-sideband-" in u for u in uris) == 2
    assert az.keys == {K1: "SECRET-ONE", K2: "SECRET-TWO"}
    # keys must be written before the fragment that references them
    assert uris.index([u for u in uris if "/policyFragments/" in u][0]) > max(i for i, u in enumerate(uris) if "/namedValues/" in u)
    az.puts.clear()
    az.backends = [("securepath-sideband-1", "https://aaaa.oop.radwarecloud.net"), ("securepath-sideband-2", "https://bbbb.oop.radwarecloud.net")]
    assert sync.apply(sync.AzWriter("rg", "apim", run=az), desired, log=lambda *_: None) == 0
    assert az.puts == []


def test_prune_removes_gone_entries_and_their_key_named_values():
    desired = sync.project_cloud_apps(APPS)
    az = FakeAz(fragment=sync.render_fragment({**desired, "old.example.test": {"app_id": "99999999-0000-0000-0000-000000000000", "api_key": "k9", "endpoint": "cccc.oop.radwarecloud.net"}}),
                keys={K1: "SECRET-ONE", K2: "SECRET-TWO", sync.key_nv_name("99999999-0000-0000-0000-000000000000"): "k9"},
                backends=[("b1", "https://aaaa.oop.radwarecloud.net"), ("b2", "https://bbbb.oop.radwarecloud.net")])
    w = sync.AzWriter("rg", "apim", run=az)
    assert sync.check(w, desired, log=lambda *_: None) == 1  # 'gone' counts as drift
    assert sync.apply(w, desired, log=lambda *_: None) == 0  # without --prune: kept, nothing written
    assert az.puts == [] and az.deletes == []
    assert sync.apply(w, desired, prune=True, log=lambda *_: None) == 0
    assert any("/policyFragments/" in u for u, _ in az.puts)
    assert len(az.deletes) == 1 and "rdwr-app-key-99999999" in az.deletes[0]
    assert "old.example.test" not in sync.parse_fragment(az.fragment)


def test_check_and_v1_tiers():
    desired = sync.project_cloud_apps(APPS)
    az = FakeAz(sku="Developer", fragment=sync.render_fragment(desired), keys={K1: "SECRET-ONE", K2: "SECRET-TWO"})
    assert sync.check(sync.AzWriter("rg", "apim", run=az), desired, log=lambda *_: None) == 0
    assert sync.check(sync.AzWriter("rg", "apim", run=FakeAz(sku="Developer")), desired, log=lambda *_: None) == 1


def test_export_writes_a_bicep_parameter_file(tmp_path):
    out = tmp_path / "p.json"
    assert sync.export_parameters(sync.project_cloud_apps(APPS), str(out), log=lambda *_: None) == 0
    assert json.loads(out.read_text())["parameters"]["appMap"]["value"]["www.example.test"]["endpoint"] == "bbbb.oop.radwarecloud.net"
