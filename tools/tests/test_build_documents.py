import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, "..", f"{name}.py" if name != "lint" else "securepath-apim-lint.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


build = _load("build_documents")
lint = _load("lint")


def test_rendered_document_contains_all_three_bodies_and_lints_clean():
    doc = build.render()
    assert doc.count("<base />") == 4
    assert 'name="rdwrAppEpAddr"' in doc  # inbound body
    assert "x-rdwr-o2v-status" in doc  # outbound/on-error bodies
    assert "rdwrLogSent" in doc  # on-error body (log-once guard)
    assert doc.startswith("<!-- Radware SecurePath Connector for Azure API Management, v1.5.0 (policy document") and "{v}" not in doc
    assert "<fragment>" not in doc and "</fragment>" not in doc
    assert lint.lint_document(doc, "api", "generated") == []


def test_render_is_stable():
    assert build.render() == build.render()


def test_document_on_disk_is_current():
    with open(build.OUT, encoding="utf-8") as f:
        assert f.read() == build.render()
