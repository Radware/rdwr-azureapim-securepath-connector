import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
FR = os.path.join(HERE, "..", "..", "fragments")


def frag(name):
    with open(os.path.join(FR, f"securepath-{name}.fragment.xml"), encoding="utf-8") as f:
        return f.read()


def test_true_host_replaces_every_originalurl_host_use():
    """The host API Management received may be read ONLY where the client-facing host is being
    resolved (as the gateway fallback, and in the trace line that reports the choice). Everywhere
    else — the sideband Host, the application map, the response-phase logs — must use the
    resolved rdwrTrueHost, or the two can disagree."""
    for name in ("inbound", "outbound", "onerror"):
        t = frag(name)
        uses = [m.start() for m in re.finditer(r"context\.Request\.OriginalUrl\.Host", t)]
        if name != "inbound":
            assert uses == [], (name, len(uses))
            assert "rdwrTrueHost" in t
            continue
        start = t.index('name="rdwrHostResolved"')
        end = t.index('name="rdwrTrueHost"', start)
        end = t.index("</choose>", end)  # the trace line that names the source
        assert all(start < u < end for u in uses), [u for u in uses if not (start < u < end)]
        assert "rdwrTrueHost" in t


def test_inbound_declares_new_named_values():
    t = frag("inbound")
    for nv in ("rdwr-app-map", "rdwr-true-host-header", "rdwr-host-fallback", "rdwr-custom-bot-block-statuses"):
        assert "{{" + nv + "}}" in t, nv


def test_no_fail_closed_configuration_error_remains():
    t = frag("inbound")
    assert "InternalConfigurationError" not in t
    assert "no_app_mapping" in t and "config_incomplete" in t


def test_diag_header_is_emitted_outside_the_inspection_branch():
    t = frag("inbound")
    i_diag = t.rindex('name="X-Rdwr-Diag"')
    i_tier1_close = t.rindex("<!-- ====== End of the inspected path ====== -->")
    assert i_diag > i_tier1_close


def test_no_cloud_fetch_on_the_request_path():
    t = frag("inbound")
    assert "api.radwarecloud.app" not in t and "cache-lookup-value" not in t and "rdwr-cloud" not in t


def test_plugin_info_fallback_is_v140():
    for name in ("outbound", "onerror"):
        assert "700-v1.4.0" in frag(name) and "700-v1.3" not in frag(name)


def test_unknown_securepath_status_fails_open_audibly():
    t = frag("inbound")
    assert "unexpected_status_" in t  # fail-open marker for statuses outside the verdict tree


def test_uzmcr_relay_is_not_gated_on_bot_manager_flag():
    t = frag("outbound")
    gate = t.index('GetValueOrDefault("rdwrBotManagerEnabled", false)')
    gate_close = t.index("    </choose>", gate)
    assert t.index('name="uzmcr"') > gate_close


def test_403_block_enforcement_branch_is_present():
    t = frag("inbound")
    assert t.count('reason="Forbidden"') >= 3  # reserved header, JSON block, implicit block, 403
    assert t.index('== 403)">') < t.index("unexpected_status_")


def test_inbound_reads_the_generated_map_but_never_includes_a_fragment():
    t = frag("inbound")
    assert "include-fragment" not in t  # API Management rejects a fragment that includes a fragment
    assert "rdwrAppMapGenerated" in t and "merged[p.Name] = p.Value" in t


def test_default_app_map_fragment_is_disabled():
    t = frag("app-map")
    assert 'name="rdwrAppMapGenerated" value="##DISABLED##"' in t
