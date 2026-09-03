import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
FR = os.path.join(HERE, "..", "..", "fragments")


def frag(name):
    with open(os.path.join(FR, f"securepath-{name}.fragment.xml"), encoding="utf-8") as f:
        return f.read()


def test_true_host_replaces_every_originalurl_host_use():
    for name in ("inbound", "outbound", "onerror"):
        t = frag(name)
        uses = [m.start() for m in re.finditer(r"context\.Request\.OriginalUrl\.Host", t)]
        # inbound keeps exactly one use: the definition of rdwrTrueHost
        assert len(uses) == (1 if name == "inbound" else 0), (name, len(uses))
        assert "rdwrTrueHost" in t


def test_inbound_declares_new_named_values():
    t = frag("inbound")
    for nv in ("rdwr-app-map", "rdwr-true-host-header", "rdwr-cloud-api-key", "rdwr-cloud-context",
               "rdwr-cloud-sync-ttl-seconds", "rdwr-cloud-sync-timeout-seconds"):
        assert "{{" + nv + "}}" in t, nv


def test_no_fail_closed_configuration_error_remains():
    t = frag("inbound")
    assert "InternalConfigurationError" not in t
    assert "no_app_mapping" in t and "config_incomplete" in t


def test_diag_header_is_emitted_outside_the_inspection_branch():
    t = frag("inbound")
    i_diag = t.rindex('name="X-Rdwr-Diag"')
    i_tier1_close = t.rindex("<!-- ====== End tier-1 path ====== -->")
    assert i_diag > i_tier1_close


def test_plugin_info_fallback_is_v140():
    for name in ("outbound", "onerror"):
        assert "700-v1.4.0" in frag(name) and "700-v1.3" not in frag(name)
