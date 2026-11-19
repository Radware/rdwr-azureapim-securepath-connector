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
NV_OK.update({"rdwr-app-id": "0123456789abcdef0123456789abcdef",
              "rdwr-app-ep-addr": "0123456789abcdef0123456789abcdef.oop.radwarecloud.net",
              "rdwr-app-ep-ssl": "true",
              "rdwr-app-map": "##DISABLED##", "rdwr-true-host-header": "##DISABLED##",
              "rdwr-custom-bot-block-statuses": "##DISABLED##",
              "rdwr-inline-mode": "##DISABLED##", "rdwr-inline-proof-header": "##DISABLED##",
              "rdwr-inline-proof-addresses": "##DISABLED##"})


class FakeReader(lint.Reader):
    def __init__(self, sku="StandardV2", glob=None, apis=None, products=None, nvs=None, backends=None):
        self._sku, self._glob = sku, glob
        self._apis, self._products = apis or {}, products or {}
        self._nvs = NV_OK if nvs is None else nvs
        self._backends = backends if backends is not None else [
            "https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net"]

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
    for bad in ("https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net",
                "0123456789abcdef0123456789abcdef.oop.radwarecloud.net:443",
                "0123456789abcdef0123456789abcdef.oop.radwarecloud.net/"):
        nvs = dict(NV_OK)
        nvs["rdwr-app-ep-addr"] = bad
        f = lint.lint_instance(FakeReader(glob=fx("clean_global.xml"), nvs=nvs))
        assert "L08" in codes(f) and any("not a bare host name" in x.message for x in f), (bad, codes(f))


def test_l10_map_entry_port_out_of_range_and_endpoint_with_scheme():
    nvs = dict(NV_OK)
    nvs["rdwr-app-map"] = ("{'orders': {'app_id': 'a', 'api_key': 'k', 'endpoint': '0123456789abcdef0123456789abcdef.oop.radwarecloud.net', 'port': 70000},"
                           " 'shop': {'app_id': 'a', 'api_key': 'k', 'endpoint': 'https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net'}}")
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
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs, backends=["https://x.oop.radwarecloud.net", "https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net"])
    f = lint.lint_instance(r)
    assert codes(f) == ["L10"] and "base_path" in f[0].message
    nvs["rdwr-app-map"] = "{'orders': {'app_id': 'a', 'api_key': 'k', 'endpoint': 'x.oop.radwarecloud.net', 'base_path': '/orders'}}"
    assert lint.lint_instance(FakeReader(glob=fx("clean_global.xml"), nvs=nvs, backends=["https://x.oop.radwarecloud.net", "https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net"])) == []


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
                               backends=["https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net"])
    assert codes(lint.lint_instance(r)) == ["L09", "L12"]
    nvs["rdwr-app-key-a1"] = "k"
    r = FakeReaderWithFragment(glob=fx("clean_global.xml"), nvs=nvs, fragment=GEN,
                               backends=["https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net", "https://gen1.oop.radwarecloud.net"])
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
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs, backends=["https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net"])
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
    r = FakeReader(glob=fx("clean_global.xml"), nvs=NV_OK, backends=["https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net"])
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


class FakeReaderWithApis(FakeReader):
    def __init__(self, *a, info=None, **kw):
        super().__init__(*a, **kw)
        self._info = info

    def api_info(self):
        return self._info


NV_BM = dict(NV_OK, **{"rdwr-bot-manager-enabled": "true"})
CAPTCHA_INFO = {"orders": {"path": "orders", "subscription_required": True},
                "securepath-captcha": {"path": "7f7c01e221604f25", "subscription_required": False}}


def test_l17_bot_manager_without_the_captcha_api():
    r = FakeReaderWithApis(glob=fx("clean_global.xml"), apis={"orders": fx("no_connector_api.xml")}, nvs=NV_BM,
                           info={"orders": {"path": "orders", "subscription_required": True}})
    f = [x for x in lint.lint_instance(r) if x.code == "L17"]
    assert len(f) == 1 and "/7f7c01e221604f25/" in f[0].message and "securepath-captcha" in f[0].fix


def test_l17_clean_with_the_captcha_api_at_all_apis_scope():
    r = FakeReaderWithApis(glob=fx("clean_global.xml"), apis={"orders": fx("no_connector_api.xml"), "securepath-captcha": None},
                           nvs=NV_BM, info=CAPTCHA_INFO)
    assert lint.lint_instance(r) == []


def test_l17_not_reported_without_bot_manager_or_when_apis_are_unknown():
    r = FakeReaderWithApis(glob=fx("clean_global.xml"), apis={"orders": fx("no_connector_api.xml")},
                           info={"orders": {"path": "orders", "subscription_required": True}})
    assert lint.lint_instance(r) == []          # rdwr-bot-manager-enabled is not true
    r = FakeReader(glob=fx("clean_global.xml"), apis={"orders": fx("no_connector_api.xml")}, nvs=NV_BM)
    assert lint.lint_instance(r) == []          # the reader cannot list API paths: no guess


def test_l17_bot_manager_from_a_map_entry():
    nvs = dict(NV_OK, **{"rdwr-app-map": "{'shop.example.com': {'app_id': 'a', 'api_key': 'k', 'endpoint': 'a.oop.radwarecloud.net', 'bot_manager': true}}"})
    r = FakeReaderWithApis(glob=fx("clean_global.xml"), apis={"orders": fx("no_connector_api.xml")}, nvs=nvs,
                           backends=["https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net", "https://a.oop.radwarecloud.net"],
                           info={"orders": {"path": "orders", "subscription_required": True}})
    assert codes(lint.lint_instance(r)) == ["L17"]


def test_l17_captcha_api_requiring_a_key_or_without_the_connector():
    info = {"securepath-captcha": {"path": "/7f7c01e221604f25/", "subscription_required": True}}
    r = FakeReaderWithApis(glob=fx("clean_global.xml"), apis={"securepath-captcha": None}, nvs=NV_BM, info=info)
    f = [x for x in lint.lint_instance(r) if x.code == "L17"]
    assert len(f) == 1 and "subscription" in f[0].message
    # connector at API scope only (Form 2 / Form 3): the CAPTCHA API must carry it as well
    info = {"orders": {"path": "orders", "subscription_required": True},
            "securepath-captcha": {"path": "7f7c01e221604f25", "subscription_required": False}}
    r = FakeReaderWithApis(glob=None, apis={"orders": fx("clean_api.xml"), "securepath-captcha": None}, nvs=NV_BM, info=info)
    f = [x for x in lint.lint_instance(r) if x.code == "L17"]
    assert len(f) == 1 and "does not run" in f[0].message
    r = FakeReaderWithApis(glob=None, apis={"orders": fx("clean_api.xml"), "securepath-captcha": fx("clean_api.xml")}, nvs=NV_BM, info=info)
    assert [x for x in lint.lint_instance(r) if x.code == "L17"] == []


def test_l02_not_reported_for_two_different_apis():
    """Form 2 / Form 3 on two APIs (for example an API of yours and the CAPTCHA API): no request
    passes through both, so nothing is inspected twice."""
    r = FakeReader(glob=None, apis={"orders": fx("clean_api.xml"), "billing": fx("clean_api.xml")})
    assert "L02" not in codes(lint.lint_instance(r))


# ---------------------------------------------------------------- L18 inline mode settings

def _l18(nvs):
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs, backends=["https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net"])
    return [f for f in lint.lint_instance(r) if f.code == "L18"]


def _inline(**over):
    d = _nv(**{"rdwr-inline-trusted-sources": "##DISABLED##", "rdwr-inline-headers-enabled": "false"})
    d.update({k.replace("_", "-"): v for k, v in over.items()})
    return d


def test_L18_clean_when_unset_and_for_complete_settings():
    assert _l18(_inline()) == []
    assert _l18(_inline(rdwr_inline_mode="strip")) == []
    assert _l18(_inline(rdwr_inline_mode="Bypass", rdwr_inline_proof_addresses="203.0.113.0/24, 198.51.100.17,2001:db8::/32")) == []
    assert _l18(_inline(rdwr_inline_mode="bypass", rdwr_inline_proof_header="X-Edge-Auth: 0123456789abcdef0123")) == []
    assert _l18(_inline(rdwr_inline_mode="strip", rdwr_inline_proof_header="X-Azure-FDID: 11111111-2222-3333-4444-555555555555")) == []
    # two values while the value Cloud WAF sends is being changed
    assert _l18(_inline(rdwr_inline_mode="bypass", rdwr_inline_proof_header="X-Edge-Auth: 0123456789abcdef0123, fedcba9876543210fedc")) == []


def test_L18_mode_that_is_not_a_mode():
    f = _l18(_inline(rdwr_inline_mode="stripp"))
    assert len(f) == 1 and "rdwr-inline-mode 'stripp'" in f[0].message and "strip or bypass" in f[0].message


def test_L18_bypass_without_a_proof_bypasses_nothing():
    f = _l18(_inline(rdwr_inline_mode="bypass"))
    assert len(f) == 1 and "no request is bypassed" in f[0].message


def test_L18_secret_header_that_cannot_be_read():
    for bad in ("X-Edge-Auth", "X-Edge-Auth:", ": value", "X Edge: 0123456789abcdef", "X-Edge-Auth: 0123456789abcdef0123,,x",
                "X-Edge-Auth: " + ", ".join(["0123456789abcdef0123"] * 6)):
        f = _l18(_inline(rdwr_inline_mode="strip", rdwr_inline_proof_header=bad))
        assert len(f) == 1 and "Header-Name: value" in f[0].message, bad


def test_L18_short_secret_and_secret_without_a_mode():
    f = _l18(_inline(rdwr_inline_mode="bypass", rdwr_inline_proof_header="X-Edge-Auth: abc"))
    assert len(f) == 1 and "shorter than 16 characters" in f[0].message
    f = _l18(_inline(rdwr_inline_proof_header="X-Edge-Auth: 0123456789abcdef0123"))
    assert len(f) == 1 and "has no effect until rdwr-inline-mode" in f[0].message


def test_L18_map_entry_inline_value():
    m = "{'orders-api': {'app_id': 'a1', 'api_key': 'k', 'endpoint': 'a1.oop.radwarecloud.net', 'inline': 'bypas'}}"
    f = _l18(_inline(**{"rdwr-app-map": m}))
    assert len(f) == 1 and "rdwr-app-map entry 'orders-api' inline 'bypas'" in f[0].message
    ok = m.replace("bypas'", "off'")
    assert _l18(_inline(**{"rdwr-app-map": ok})) == []
    # an entry that asks for bypass needs a proof like the instance setting does
    byp = m.replace("bypas'", "bypass'")
    f = _l18(_inline(**{"rdwr-app-map": byp}))
    assert len(f) == 1 and "no request is bypassed" in f[0].message


def test_L07_names_the_inline_mode_values_as_new():
    nvs = _inline()
    del nvs["rdwr-inline-mode"]
    r = FakeReader(glob=fx("clean_global.xml"), nvs=nvs)
    f = [x for x in lint.lint_instance(r) if x.code == "L07"]
    assert len(f) == 1 and "rdwr-inline-mode" in f[0].message and "new in v1.6.0" in f[0].message


_API_WITH_OVERRIDE = """<policies>
    <inbound>
        %s
        <base />
        %s
    </inbound>
    <backend><base /></backend>
    <outbound><base /></outbound>
    <on-error><base /></on-error>
</policies>"""


def _l18_api(before="", after="", **nv):
    r = FakeReader(glob=fx("clean_global.xml"), apis={"orders": _API_WITH_OVERRIDE % (before, after)}, nvs=_inline(**nv),
                   backends=["https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net"])
    return [f for f in lint.lint_instance(r) if f.code == "L18"]


def test_L18_per_api_override_is_checked_where_it_is_written():
    ok = '<set-variable name="rdwrInlineModeOverride" value="strip" />'
    assert _l18_api(before=ok) == []
    assert _l18_api(before=ok.replace("strip", "off")) == []
    f = _l18_api(before=ok.replace("strip", "striip"))
    assert len(f) == 1 and f[0].scope == "api:orders" and "rdwrInlineModeOverride 'striip'" in f[0].message
    f = _l18_api(before=ok.replace("strip", "bypass"))
    assert len(f) == 1 and "rdwrInlineModeOverride is bypass" in f[0].message and "no request is bypassed" in f[0].message
    assert _l18_api(before=ok.replace("strip", "bypass"), rdwr_inline_proof_addresses="203.0.113.7") == []


def test_L18_per_api_override_after_the_connector_has_no_effect():
    f = _l18_api(after='<set-variable name="rdwrInlineModeOverride" value="strip" />')
    assert len(f) == 1 and "after the connector has run" in f[0].message and f[0].line == 5


def test_L18_secret_header_counts_as_used_by_a_per_api_or_per_application_mode():
    sec = "X-Edge-Auth: 0123456789abcdef0123"
    assert _l18_api(before='<set-variable name="rdwrInlineModeOverride" value="strip" />', rdwr_inline_proof_header=sec) == []
    m = "{'orders-api': {'app_id': 'a1', 'api_key': 'k', 'endpoint': 'a1.oop.radwarecloud.net', 'inline': 'bypass'}}"
    assert _l18(_inline(**{"rdwr-app-map": m, "rdwr-inline-proof-header": sec})) == []


def test_L18_never_prints_the_secret_value():
    for bad in ("X-Edge-Auth: abc", "X Edge: TOPSECRETVALUE123456", "X-Edge-Auth: TOPSECRET,VALUE123456"):
        for f in _l18(_inline(rdwr_inline_mode="bypass", rdwr_inline_proof_header=bad)):
            assert "TOPSECRET" not in f.message + f.fix and "abc" not in f.message, bad


def test_L10_map_entry_inline_must_be_a_string():
    m = "{'orders-api': {'app_id': 'a1', 'api_key': 'k', 'endpoint': 'a1.oop.radwarecloud.net', 'inline': true}}"
    r = FakeReader(glob=fx("clean_global.xml"), nvs=_inline(**{"rdwr-app-map": m}), backends=["https://a1.oop.radwarecloud.net"])
    f = [x for x in lint.lint_instance(r) if x.code == "L10"]
    assert len(f) == 1 and "inline is true" in f[0].message


def test_trace_redaction_covers_the_secret_header_setting():
    import inspect
    src = inspect.getsource(lint)
    assert '"rdwrinlinesecretheadercfg"' in src


def test_L18_proof_addresses_must_be_addresses_or_ranges():
    f = _l18(_inline(rdwr_inline_mode="bypass", rdwr_inline_proof_addresses="203.0.113.0/24, cloudwaf.example.com, 10.0.0.300"))
    assert len(f) == 1 and "cloudwaf.example.com" in f[0].message and "10.0.0.300" in f[0].message and "203.0.113.0/24" not in f[0].message


def test_L18_older_list_is_not_the_proof_of_a_mode():
    """Someone moving to rdwr-inline-mode who leaves the addresses in the older Named Value gets a
    mode with no proof: say which Named Value the modes read."""
    f = _l18(_inline(rdwr_inline_mode="bypass", rdwr_inline_trusted_sources="203.0.113.0/24"))
    msgs = " | ".join(x.message for x in f)
    assert "no request is bypassed" in msgs and "rdwr-inline-trusted-sources is not read where a mode applies" in msgs and len(f) == 2
    f = _l18(_inline(rdwr_inline_mode="strip", rdwr_inline_headers_enabled="true"))
    assert len(f) == 1 and "rdwr-inline-headers-enabled is not read where a mode applies" in f[0].message
    # the older settings on their own are not a finding
    assert _l18(_inline(rdwr_inline_trusted_sources="203.0.113.0/24", rdwr_inline_headers_enabled="true")) == []


OP_INLINE = ('<policies><inbound>%s<base />%s</inbound>'
             "<backend><base /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>")


def test_L18_reads_operation_policies_when_operations_are_checked():
    """A per-operation rdwrInlineModeOverride is checked like a per-API one, with --operations."""
    line = '<set-variable name="rdwrInlineModeOverride" value="%s" />\n'
    r = _op_reader(OP_INLINE % (line % "bypass", ""))
    assert [f for f in lint.lint_instance(r) if f.code == "L18"] == []            # default: operations are not read
    f = [x for x in lint.lint_instance(r, check_operations=True) if x.code == "L18"]
    assert len(f) == 1 and "operation get-item" in f[0].scope and "no request is bypassed" in f[0].message
    r = _op_reader(OP_INLINE % ("", "\n" + line % "strip"))
    f = [x for x in lint.lint_instance(r, check_operations=True) if x.code == "L18"]
    assert len(f) == 1 and "after the connector has run" in f[0].message
    r = _op_reader(OP_INLINE % (line % "strip", ""))
    assert [x for x in lint.lint_instance(r, check_operations=True) if x.code == "L18"] == []


_FORM2 = """<policies>
    <inbound>
        <base />
%s        <include-fragment fragment-id="securepath-app-map" />
%s        <include-fragment fragment-id="securepath-inbound" />
%s    </inbound>
    <backend><base /></backend>
    <outbound><base /><include-fragment fragment-id="securepath-outbound" /></outbound>
    <on-error><base /><include-fragment fragment-id="securepath-onerror" /></on-error>
</policies>"""
_LINE = '        <set-variable name="rdwrInlineModeOverride" value="strip" />\n'


def _l18_doc(doc):
    r = FakeReader(glob=None, apis={"orders": doc}, nvs=_inline(),
                   backends=["https://0123456789abcdef0123456789abcdef.oop.radwarecloud.net"])
    return [f for f in lint.lint_instance(r) if f.code == "L18"]


def test_L18_placement_when_the_document_itself_carries_the_connector():
    """Form 2 and Form 3: the connector's lines are in this document, after <base />. The per-API line
    belongs above THOSE lines; being below <base /> is where the README puts it, and it works there."""
    assert _l18_doc(_FORM2 % (_LINE, "", "")) == []          # right after <base />, above the connector's lines
    assert _l18_doc(_FORM2 % ("", _LINE, "")) == []          # between the two connector lines: still before the mode is read
    f = _l18_doc(_FORM2 % ("", "", _LINE))                   # below securepath-inbound: too late
    assert len(f) == 1 and "after the connector has run" in f[0].message
    form3 = ('<policies>\n    <inbound>\n        <base />\n%s        <set-variable name="rdwrInboundEntered" value="@(true)" />\n'
             '        <set-variable name="rdwrAppEpAddr" value="{{rdwr-app-ep-addr}}" />\n%s    </inbound>\n'
             "    <backend><base /></backend>\n    <outbound><base /></outbound>\n    <on-error><base /></on-error>\n</policies>")
    assert _l18_doc(form3 % (_LINE, "")) == []
    f = _l18_doc(form3 % ("", _LINE))
    assert len(f) == 1 and "after the connector has run" in f[0].message
