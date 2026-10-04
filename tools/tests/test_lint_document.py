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
    assert s["inbound"][0] == 2 and s["outbound"][0] == 14


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
        '<set-variable name="rdwrAppEpAddr" value="{{rdwr-app-ep-addr}}" />', 1)
    f = lint.lint_document(text, "api", "orders-api")
    assert codes(f) == []


def test_shipped_v15_document_lints_clean_at_api_scope():
    root = os.path.join(HERE, "..", "..")
    with open(os.path.join(root, "rdwr-azureapim-securepath-connector-v1.5.xml"), encoding="utf-8") as f:
        doc = f.read()
    assert lint.document_has_connector(doc)
    assert lint.lint_document(doc, "api", "v1.5") == []


UNROUTED_BLOCK = ('<choose><when condition="@((bool)context.Variables.GetValueOrDefault("rdwrUnrouted", false))">'
                  '<include-fragment fragment-id="securepath-app-map" /><include-fragment fragment-id="securepath-inbound" />'
                  '<include-fragment fragment-id="securepath-outbound" /></when></choose>')
ONE_LINE_V140 = ('<policies><inbound><include-fragment fragment-id="securepath-app-map" /><include-fragment fragment-id="securepath-inbound" /></inbound>'
                 '<backend><forward-request /></backend><outbound><include-fragment fragment-id="securepath-outbound" /></outbound>'
                 '<on-error><include-fragment fragment-id="securepath-onerror" /></on-error></policies>')


def test_one_line_all_apis_policy_is_recognised():
    doc = ONE_LINE_V140.replace('<include-fragment fragment-id="securepath-onerror" />',
                                '<include-fragment fragment-id="securepath-onerror" />' + UNROUTED_BLOCK)
    assert lint.document_has_connector(doc)
    assert lint.lint_document(doc, "global", "global") == []


def test_l16_on_error_without_the_unrouted_block():
    # the v1.4.0 All APIs policy: requests API Management answers itself are never inspected
    f = lint.lint_document(ONE_LINE_V140, "global", "global")
    assert codes(f) == ["L16"] and "answers itself" in f[0].message


def test_l16_inbound_before_onerror_in_on_error():
    doc = ONE_LINE_V140.replace('<include-fragment fragment-id="securepath-onerror" />',
                                UNROUTED_BLOCK + '<include-fragment fragment-id="securepath-onerror" />')
    f = lint.lint_document(doc, "global", "global")
    assert codes(f) == ["L16"] and "sets rdwrUnrouted" in f[0].message


def _readme():
    with open(os.path.join(HERE, "..", "..", "README.md"), encoding="utf-8") as f:
        return f.read()


def test_readme_cli_all_apis_policy_lints_clean():
    import json
    import re
    m = re.search(r"printf '(\{\"properties\".*?)' > rdwr-global-policy\.json", _readme())
    assert m, "Form 1 printf block not found"
    doc = json.loads(m.group(1).replace('\\\\', '\\'))["properties"]["value"]
    assert lint.lint_document(doc, "global", "readme-form1-cli") == []


def test_readme_portal_and_form2_documents_lint_clean():
    import re
    blocks = re.findall(r"```xml\n(<policies>.*?</policies>)\n```", _readme(), re.S)
    with_connector = [b for b in blocks if 'fragment-id="securepath-inbound"' in b]
    assert len(with_connector) == 2, len(with_connector)   # Form 1 portal document, Form 2 snippet
    assert lint.lint_document(with_connector[0], "global", "readme-form1-portal") == []
    assert lint.lint_document(with_connector[1], "api", "readme-form2") == []


def test_bicep_all_apis_policy_lints_clean():
    import re
    with open(os.path.join(HERE, "..", "..", "deploy", "securepath-apim.bicep"), encoding="utf-8") as f:
        b = f.read()
    m = re.search(r"resource globalPolicy .*?value: '(.*?)'\n", b, re.S)
    assert m
    assert lint.lint_document(m.group(1), "global", "bicep") == []

def test_manual_merge_shape_yields_l04_and_l05():
    doc = fx("merged_jwt_first.xml")
    f = lint.lint_document(doc, "api", "merged")
    assert codes(f) == ["L04", "L05"]
    l04 = [x for x in f if x.code == "L04"][0]
    # The fixture is GENERATED (tools/tests/make_fixtures.py) from the shipped document,
    # so its line numbers move whenever the document does. Assert the finding POINTS AT
    # the <validate-jwt> element rather than at a hardcoded line number: a number that
    # has to be edited on every regeneration is how the fixture drifted out of date in
    # the first place.
    assert "validate-jwt" in doc.splitlines()[l04.line - 1]
    assert "validate-jwt" in l04.message
