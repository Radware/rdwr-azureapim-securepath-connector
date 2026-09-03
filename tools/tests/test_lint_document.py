import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("lint", os.path.join(HERE, "..", "securepath-apim-lint.py"))
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)


def fx(name):
    with open(os.path.join(HERE, "fixtures", name), encoding="utf-8") as f:
        return f.read()


def codes(findings):
    return sorted(f.code for f in findings)


def test_split_sections_reports_opening_lines():
    s = lint.split_sections(fx("clean_api.xml"))
    assert set(s) == {"inbound", "backend", "outbound", "on-error"}
    assert s["inbound"][0] == 2 and s["outbound"][0] == 13


def test_clean_api_has_no_findings():
    assert lint.lint_document(fx("clean_api.xml"), "api", "orders-api") == []


def test_clean_global_has_no_findings():
    assert lint.lint_document(fx("clean_global.xml"), "global", "global") == []


def test_l04_jwt_before_connector():
    f = lint.lint_document(fx("jwt_before_fragment.xml"), "api", "orders-api")
    assert codes(f) == ["L04"]
    assert "validate-jwt" in f[0].message and f[0].line == 4


def test_l03_missing_base_in_inbound():
    f = lint.lint_document(fx("no_base_inbound.xml"), "api", "orders-api")
    assert codes(f) == ["L03"] and "inbound" in f[0].message


def test_l05_empty_set_variable():
    f = lint.lint_document(fx("empty_set_variable.xml"), "api", "orders-api")
    assert codes(f) == ["L05"] and "rdwrRenderedBlockPage" in f[0].message


def test_l06_inbound_without_outbound_and_onerror():
    f = lint.lint_document(fx("inbound_only.xml"), "api", "orders-api")
    assert codes(f) == ["L06", "L06"]
    assert {x.message.split()[0] for x in f} == {"securepath-outbound", "securepath-onerror"}


def test_no_connector_document_is_silent_by_itself():
    assert lint.lint_document(fx("no_connector_api.xml"), "api", "orders-api") == []


def test_inline_connector_counts_as_present():
    text = fx("clean_api.xml").replace(
        '<include-fragment fragment-id="securepath-inbound" />',
        '<set-variable name="rdwrAppEpAddr" value="{{rdwr-app-ep-addr}}" />')
    f = lint.lint_document(text, "api", "orders-api")
    assert codes(f) == []


def test_shipped_whole_documents_lint_clean():
    root = os.path.join(HERE, "..", "..")
    with open(os.path.join(root, "rdwr-azureapim-securepath-connector-v1.3.xml"), encoding="utf-8") as f:
        assert lint.lint_document(f.read(), "api", "shipped") == []
    with open(os.path.join(root, "rdwr-azureapim-securepath-connector-v1.3-all-apis-scope.xml"), encoding="utf-8") as f:
        assert lint.lint_document(f.read(), "global", "shipped-global") == []


def test_manual_merge_shape_yields_l04_and_l05():
    f = lint.lint_document(fx("merged_jwt_first.xml"), "api", "merged")
    assert codes(f) == ["L04", "L05"]
    l04 = [x for x in f if x.code == "L04"][0]
    assert l04.line == 4 and "validate-jwt" in l04.message
