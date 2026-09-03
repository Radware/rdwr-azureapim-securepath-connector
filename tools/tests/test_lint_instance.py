import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("lint", os.path.join(HERE, "..", "securepath-apim-lint.py"))
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)


def fx(name):
    with open(os.path.join(HERE, "fixtures", name), encoding="utf-8") as f:
        return f.read()


NV_OK = {n: "x" for n in lint.REQUIRED_NAMED_VALUES}
NV_OK.update({"rdwr-app-id": "afa37f7d53ce4e76a4988c4955c2d7e5",
              "rdwr-app-ep-addr": "afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net",
              "rdwr-app-ep-ssl": "true",
              "rdwr-app-map": "##DISABLED##", "rdwr-true-host-header": "##DISABLED##"})


class FakeReader(lint.Reader):
    def __init__(self, sku="StandardV2", glob=None, apis=None, products=None, nvs=None, backends=None):
        self._sku, self._glob = sku, glob
        self._apis, self._products = apis or {}, products or {}
        self._nvs = NV_OK if nvs is None else nvs
        self._backends = backends if backends is not None else [
            "https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net"]

    def sku(self): return self._sku
    def global_policy(self): return self._glob
    def apis(self): return list(self._apis)
    def api_policy(self, i): return self._apis[i]
    def products(self): return list(self._products)
    def product_policy(self, i): return self._products[i]
    def named_values(self): return dict(self._nvs)
    def backends(self): return list(self._backends)


def codes(f):
    return sorted(x.code for x in f)


def test_global_install_with_based_apis_is_clean():
    r = FakeReader(glob=fx("clean_global.xml"), apis={"orders": fx("no_connector_api.xml"), "bare": None})
    assert lint.lint_instance(r) == []


def test_l01_no_connector_anywhere():
    r = FakeReader(glob=None, apis={"orders": fx("no_connector_api.xml")})
    assert codes(lint.lint_instance(r)) == ["L01"]


def test_l02_connector_at_two_scopes():
    r = FakeReader(glob=fx("clean_global.xml"), apis={"orders": fx("clean_api.xml")})
    f = lint.lint_instance(r)
    assert "L02" in codes(f)
    assert any("orders" in x.scope for x in f if x.code == "L02")


def test_l03_reported_only_when_connector_is_global():
    api_no_conn_no_base = fx("no_base_inbound.xml").replace(
        '        <include-fragment fragment-id="securepath-inbound" />\n', '').replace(
        '        <include-fragment fragment-id="securepath-outbound" />\n', '').replace(
        '        <include-fragment fragment-id="securepath-onerror" />\n', '')
    r = FakeReader(glob=fx("clean_global.xml"), apis={"orders": api_no_conn_no_base})
    assert "L03" in codes(lint.lint_instance(r))
    r2 = FakeReader(glob=None, apis={"orders": fx("no_base_inbound.xml")})
    assert "L03" not in codes(lint.lint_instance(r2))


def test_l07_missing_named_value():
    nvs = dict(NV_OK)
    del nvs["rdwr-bot-manager-enabled"]
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs)
    f = lint.lint_instance(r)
    assert codes(f) == ["L07"] and "rdwr-bot-manager-enabled" in f[0].message


def test_l08_app_id_with_dot_and_wrong_endpoint():
    nvs = dict(NV_OK)
    nvs["rdwr-app-id"] = "x.v1.radwarecloud.net"
    nvs["rdwr-app-ep-addr"] = "x.v1.radwarecloud.net"
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs, backends=["https://x.v1.radwarecloud.net"])
    assert codes(lint.lint_instance(r)) == ["L08", "L08"]


def test_l09_v2_tier_without_backend_for_endpoint():
    r = FakeReader(sku="StandardV2", glob=fx("clean_global.xml"), backends=["https://other.oop.radwarecloud.net"])
    assert codes(lint.lint_instance(r)) == ["L09"]
    r2 = FakeReader(sku="Developer", glob=fx("clean_global.xml"), backends=[])
    assert codes(lint.lint_instance(r2)) == []


def test_l09_skipped_for_plain_http_endpoint():
    nvs = dict(NV_OK)
    nvs["rdwr-app-ep-ssl"] = "false"
    r = FakeReader(sku="StandardV2", glob=fx("clean_global.xml"), nvs=nvs, backends=[])
    assert codes(lint.lint_instance(r)) == []


def test_l10_app_map_validation_when_present():
    nvs = dict(NV_OK)
    nvs["rdwr-app-map"] = '{"orders": {"app_id": "a", "api_key": "k"}}'
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs)
    f = lint.lint_instance(r)
    assert codes(f) == ["L10"] and "endpoint" in f[0].message
    nvs["rdwr-app-map"] = "##DISABLED##"
    assert lint.lint_instance(FakeReader(glob=fx("clean_global.xml"), nvs=nvs)) == []


def test_az_reader_strips_byte_order_mark_and_reports_garbage():
    import pytest
    r = lint.AzReader.__new__(lint.AzReader)
    r.base = "https://example.invalid"
    r._az = lambda args: '﻿{"properties": {"value": "﻿<policies />"}}'
    assert r._policy("") == "<policies />"
    r._az = lambda args: "﻿<policies>\n\t<inbound />\n</policies>\n"
    assert r._policy("") == "<policies>\n\t<inbound />\n</policies>"
    r._az = lambda args: ""
    assert r._policy("") is None
    r._az = lambda args: "not json"
    with pytest.raises(RuntimeError):
        r._get("/apis")


def test_l04_flows_through_from_api_documents():
    r = FakeReader(glob=None, apis={"orders": fx("jwt_before_fragment.xml")})
    assert "L04" in codes(lint.lint_instance(r))


def test_single_quoted_map_is_accepted_and_base_path_checked():
    nvs = dict(NV_OK)
    nvs["rdwr-app-map"] = "{'orders': {'app_id': 'a', 'api_key': 'k', 'endpoint': 'x.oop.radwarecloud.net', 'base_path': 'orders'}}"
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs, backends=["https://x.oop.radwarecloud.net", "https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net"])
    f = lint.lint_instance(r)
    assert codes(f) == ["L10"] and "base_path" in f[0].message
    nvs["rdwr-app-map"] = "{'orders': {'app_id': 'a', 'api_key': 'k', 'endpoint': 'x.oop.radwarecloud.net', 'base_path': '/orders'}}"
    assert lint.lint_instance(FakeReader(glob=fx("clean_global.xml"), nvs=nvs, backends=["https://x.oop.radwarecloud.net", "https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net"])) == []


def test_map_endpoint_without_backend_is_l09():
    nvs = dict(NV_OK)
    nvs["rdwr-app-map"] = "{'orders': {'app_id': 'a', 'api_key': 'k', 'endpoint': 'y.oop.radwarecloud.net'}}"
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs)
    f = lint.lint_instance(r)
    assert codes(f) == ["L09"] and "y.oop.radwarecloud.net" in f[0].message
