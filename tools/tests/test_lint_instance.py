import importlib.util
import json
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
              "rdwr-app-map": "##DISABLED##", "rdwr-true-host-header": "##DISABLED##",
              "rdwr-custom-bot-block-statuses": "##DISABLED##"})


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

    frags = None  # per-test overrides: fragment id -> text (None = not registered)

    def fragment(self, fragment_id):
        # a healthy instance carries the shipped fragments, registered as-is
        if self.frags is not None and fragment_id in self.frags:
            return self.frags[fragment_id]
        path = os.path.join(HERE, "..", "..", "fragments", f"{fragment_id}.fragment.xml")
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as f:
            return f.read()


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


def test_l08_endpoint_with_scheme_port_or_path():
    """A scheme, port or path in rdwr-app-ep-addr ends in .oop.radwarecloud.net just the same, so the
    old check passed it; the connector serves every request uninspected with it (config_incomplete)."""
    for bad in ("https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net",
                "afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net:443",
                "afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net/"):
        nvs = dict(NV_OK)
        nvs["rdwr-app-ep-addr"] = bad
        f = lint.lint_instance(FakeReader(glob=fx("clean_global.xml"), nvs=nvs))
        assert "L08" in codes(f) and any("not a bare host name" in x.message for x in f), (bad, codes(f))


def test_l10_map_entry_port_out_of_range_and_endpoint_with_scheme():
    nvs = dict(NV_OK)
    nvs["rdwr-app-map"] = ("{'orders': {'app_id': 'a', 'api_key': 'k', 'endpoint': 'afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net', 'port': 70000},"
                           " 'shop': {'app_id': 'a', 'api_key': 'k', 'endpoint': 'https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net'}}")
    f = lint.lint_instance(FakeReader(glob=fx("clean_global.xml"), nvs=nvs))
    msgs = [x.message for x in f if x.code == "L10"]
    assert any("'orders' port is 70000" in m for m in msgs), msgs
    assert any("'shop' endpoint" in m and "not a bare host name" in m for m in msgs), msgs


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


class FakeReaderWithFragment(FakeReader):
    def __init__(self, *a, fragment=None, **kw):
        super().__init__(*a, **kw)
        self._fragment = fragment

    def fragment(self, fragment_id):
        if fragment_id == "securepath-app-map":
            return self._fragment
        return super().fragment(fragment_id)


GEN = ('<fragment>\n    <set-variable name="rdwrAppMapGenerated" value="{\'shop.example.test\': {\'app_id\': \'a1\', '
       '\'api_key\': \'{{rdwr-app-key-a1}}\', \'endpoint\': \'gen1.oop.radwarecloud.net\', \'port\': 443, \'ssl\': true}}" />\n</fragment>\n')


def test_generated_map_endpoints_and_key_named_values_are_checked():
    nvs = dict(NV_OK)
    r = FakeReaderWithFragment(glob=fx("clean_global.xml"), nvs=nvs, fragment=GEN,
                               backends=["https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net"])
    assert codes(lint.lint_instance(r)) == ["L09", "L12"]
    nvs["rdwr-app-key-a1"] = "k"
    r = FakeReaderWithFragment(glob=fx("clean_global.xml"), nvs=nvs, fragment=GEN,
                               backends=["https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net", "https://gen1.oop.radwarecloud.net"])
    assert lint.lint_instance(r) == []


def test_missing_app_map_fragment_is_l11_when_fragments_are_used():
    r = FakeReaderWithFragment(glob=fx("clean_global.xml"), fragment=None)
    assert codes(lint.lint_instance(r)) == ["L11"]
    r2 = FakeReaderWithFragment(glob=fx("clean_global.xml"), fragment=open(os.path.join(HERE, "..", "..", "fragments", "securepath-app-map.fragment.xml")).read())
    assert lint.lint_instance(r2) == []


def test_l11_when_inbound_is_referenced_without_the_app_map_before_it():
    glob = fx("clean_global.xml").replace('        <include-fragment fragment-id="securepath-app-map" />\n', '')
    assert codes(lint.lint_instance(FakeReader(glob=glob))) == ["L11"]
    swapped = fx("clean_global.xml").replace(
        '        <include-fragment fragment-id="securepath-app-map" />\n        <include-fragment fragment-id="securepath-inbound" />',
        '        <include-fragment fragment-id="securepath-inbound" />\n        <include-fragment fragment-id="securepath-app-map" />')
    assert codes(lint.lint_instance(FakeReader(glob=swapped))) == ["L11"]


# ---------------------------------------------------------------- L14 custom Bot Manager block statuses

def _nv(**over):
    d = dict(NV_OK); d.update(over); return d


def _codes(nvs):
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs, backends=["https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net"])
    return [f for f in lint.lint_instance(r) if f.code == "L13"]


def test_L13_disabled_and_valid_list_with_bot_manager_are_clean():
    assert _codes(_nv()) == []
    assert _codes(_nv(**{"rdwr-custom-bot-block-statuses": "429, 418", "rdwr-bot-manager-enabled": "true"})) == []
    assert _codes(_nv(**{"rdwr-custom-bot-block-statuses": "*", "rdwr-bot-manager-enabled": "true"})) == []


def test_L13_invalid_list():
    f = _codes(_nv(**{"rdwr-custom-bot-block-statuses": "429,abc", "rdwr-bot-manager-enabled": "true"}))
    assert len(f) == 1 and "not a status-code list" in f[0].message


def test_L13_standard_and_5xx_statuses_flagged():
    f = _codes(_nv(**{"rdwr-custom-bot-block-statuses": "403,429,503", "rdwr-bot-manager-enabled": "true"}))
    msgs = " | ".join(x.message for x in f)
    assert "403" in msgs and "standard verdicts" in msgs and "503" in msgs and "never relayed" in msgs and len(f) == 2


def test_L13_ignored_without_bot_manager():
    f = _codes(_nv(**{"rdwr-custom-bot-block-statuses": "429", "rdwr-bot-manager-enabled": "false"}))
    assert len(f) == 1 and "rdwr-bot-manager-enabled is not true" in f[0].message


def test_L13_map_entry_override_checked():
    m = "{'orders-api': {'app_id': 'a1', 'api_key': 'k', 'endpoint': 'a1.oop.radwarecloud.net', 'bot_manager': true, 'bot_block_statuses': '429,abc'}}"
    f = _codes(_nv(**{"rdwr-app-map": m}))
    assert len(f) == 1 and "entry 'orders-api'" in f[0].message


# ---------------------------------------------------------------- L15 live fragments vs the shipped files

def _l15(frags):
    r = FakeReader(glob=fx("clean_global.xml"), nvs=NV_OK, backends=["https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net"])
    r.frags = frags
    return [f for f in lint.lint_instance(r) if f.code == "L14"]


def test_L14_clean_when_live_fragments_match_shipped_files_modulo_whitespace():
    shipped = lint.shipped_fragment("securepath-inbound")
    assert shipped and _l15({}) == []
    import re
    reindented = re.sub(r"(?m)^( {4})+", lambda m: "\t" * (len(m.group(0)) // 4), shipped)  # what the instance stores
    assert _l15({"securepath-inbound": reindented.replace("\n", "\r\n") + "\n\n"}) == []


def test_L14_when_live_fragment_is_stale_or_missing():
    stale = lint.shipped_fragment("securepath-inbound").replace("rdwrCustomBotBlockMatch", "rdwrOld")
    f = _l15({"securepath-inbound": stale})
    assert len(f) == 1 and "differs from fragments/securepath-inbound.fragment.xml" in f[0].message and "asynchronous" in f[0].fix
    f = _l15({"securepath-onerror": None})
    assert len(f) == 1 and "not registered" in f[0].message


def test_L14_not_reported_for_document_installs():
    doc = '<policies><inbound><base /><set-variable name="rdwrAppEpAddr" value="x" /></inbound><backend><base /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>'
    r = FakeReader(glob=None, apis={"orders": doc}, nvs=NV_OK)
    r.frags = {"securepath-inbound": "<fragment>old</fragment>"}
    assert [f for f in lint.lint_instance(r) if f.code == "L14"] == []


# ---------------------------------------------------------------- L10 entry types, one-line documents, paging, secret reads

def test_L10_flags_mistyped_map_entries():
    nvs = dict(NV_OK)
    nvs["rdwr-app-map"] = "{'orders': {'app_id': 'a', 'api_key': 'k', 'endpoint': 'y.oop.radwarecloud.net', 'port': 'https', 'ssl': 'yes'}, 'shop': 'not-an-object'}"
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs, backends=["https://y.oop.radwarecloud.net"])
    msgs = [f.message for f in lint.lint_instance(r) if f.code == "L10"]
    assert any("port is \"https\"" in m for m in msgs) and any("ssl is \"yes\"" in m for m in msgs) and any("'shop' is not an object" in m for m in msgs)


class PagedAz:
    """az stub: /apis comes in two pages via nextLink; secret Named Values include a foreign one."""
    def __init__(self):
        self.listed = []

    def __call__(self, args):
        if args[:2] == ["account", "show"]:
            return "sub-1\n"
        uri = args[4]
        if "/apis?" in uri:
            return json.dumps({"value": [{"name": "a1"}], "nextLink": "https://management.azure.com/next-page"})
        if uri == "https://management.azure.com/next-page":
            return json.dumps({"value": [{"name": "a2"}]})
        if "/namedValues?" in uri:
            return json.dumps({"value": [{"name": "rdwr-api-key", "properties": {"secret": True}},
                                         {"name": "someone-elses-secret", "properties": {"secret": True}},
                                         {"name": "rdwr-app-id", "properties": {"value": "x"}}]})
        if "/listValue" in uri:
            self.listed.append(uri.split("/namedValues/")[1].split("/")[0])
            return json.dumps({"value": "k"})
        return json.dumps({"value": [], "sku": {"name": "StandardV2"}})


def test_reader_follows_next_link_and_reads_only_connector_secrets(monkeypatch):
    az = PagedAz()
    monkeypatch.setattr(lint.AzReader, "_az", staticmethod(az))
    r = lint.AzReader("rg", "apim")
    assert r.apis() == ["a1", "a2"]
    nvs = r.named_values()
    assert nvs["rdwr-api-key"] == "k" and nvs["someone-elses-secret"] is None and nvs["rdwr-app-id"] == "x"
    assert az.listed == ["rdwr-api-key"]


# ---------------------------------------------------------------- L03 at operation scope

class OpReader(FakeReader):
    """An instance whose APIs carry operation-level policies."""
    ops = {}
    op_policies = {}

    def operations(self, api_id):
        return list(self.ops.get(api_id, []))

    def operation_policy(self, api_id, operation_id):
        return self.op_policies.get((api_id, operation_id))


def _op_reader(op_policy):
    r = OpReader(glob=fx("clean_global.xml"), apis={"orders": None}, nvs=NV_OK)
    r.ops = {"orders": ["get-item"]}
    r.op_policies = {("orders", "get-item"): op_policy}
    return r


OP_NO_BASE = ('<policies><inbound><set-header name="X-Op" exists-action="override"><value>1</value></set-header></inbound>'
              "<backend><base /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>")
OP_WITH_BASE = ('<policies><inbound><base /><set-header name="X-Op" exists-action="override"><value>1</value></set-header></inbound>'
                "<backend><base /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>")


def test_operation_without_base_is_reported_only_when_asked():
    r = _op_reader(OP_NO_BASE)
    assert [f for f in lint.lint_instance(r) if f.code == "L03"] == []      # default: not checked
    found = [f for f in lint.lint_instance(r, check_operations=True) if f.code == "L03"]
    assert len(found) == 1
    assert "operation get-item" in found[0].scope and "skips the connector entirely" in found[0].message


def test_operation_with_base_is_clean():
    r = _op_reader(OP_WITH_BASE)
    assert [f for f in lint.lint_instance(r, check_operations=True) if f.code == "L03"] == []


def test_operations_are_not_read_when_no_wider_scope_carries_the_connector():
    """A connector installed only at API scope cannot be skipped by an operation policy."""
    r = _op_reader(OP_NO_BASE)
    r._glob = None
    r._apis = {"orders": fx("clean_api.xml")}
    assert [f for f in lint.lint_instance(r, check_operations=True) if f.code == "L03"] == []
