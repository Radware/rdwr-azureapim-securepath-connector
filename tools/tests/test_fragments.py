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


def test_chunked_is_detected_as_a_token():
    """Transfer-Encoding is a comma-separated, case-insensitive list ("gzip, chunked", "Chunked");
    the connector must tokenise it."""
    t = frag("inbound")
    assert 'name="origTransferChunked"' in t
    assert '.Trim() == "chunked"' in t
    # the old first-value, exact-match compares (multipart branch and chunked branch)
    assert 'GetValueOrDefault("origTransferEncoding", "")).ToLower() == "chunked"' not in t
    assert 'Variables["origTransferEncoding"]) == "chunked"' not in t
    assert "?.FirstOrDefault()?.ToLower()" not in t.split('name="origTransferEncoding"')[1].split("/>")[0]
    assert t.count('<send-request mode="copy"') == 2


def test_no_policy_touches_transfer_encoding():
    """API Management rejects a set-header on Transfer-Encoding at save time ("Header name is
    invalid or restricted from modification", rig 2026-09-22); the gateway frames the inspection
    call's body itself. A fragment carrying one registers as a silent no-op (the old fragment
    stays live), so guard it here."""
    for name in ("inbound", "outbound", "onerror"):
        t = frag(name)
        assert re.search(r'<set-header name="transfer-encoding"', t, re.I) is None, name


def test_uzmcr_passthrough_is_traced():
    t = frag("inbound")
    i = t.index('value="@("uzmcr_allow")"')
    branch = t[i:t.index("</when>", i)]
    assert '<trace source="securepath" severity="error">' in branch
    for must in ("rwStatus", "oopRequestStatusHeader", "rdwrOopId"):
        assert must in branch, must


def test_custom_bot_block_status_list_is_validated_and_reported():
    t = frag("inbound")
    assert 'name="rdwrCustomBotBlockStatusesProblem"' in t
    assert 'return "invalid"' in t and '"no_effect:"' in t
    assert "ignored for this request (README 3e)" in t
    assert "which has no effect there" in t
    # the fail-open line for an unlisted status names the ignored setting
    i = t.index("unexpected_status_")
    assert "is not a status-code list, so it was ignored" in t[i:t.index("</trace>", i)]


def test_partial_body_header_is_gated_not_nulled():
    """A null <value> inside send-request still emits an EMPTY header (rig 2026-09-22: every
    non-truncated inspection call carried 'x-rdwr-partial-body:'); the set-header must be inside
    a <when> on setPartialBodyHeader, the way the outbound fragment gates its x-rdwr-o2h-* headers."""
    t = frag("inbound")
    assert 'return isPartial ? "true" : null;' not in t
    n = t.count('<set-header name="X-Rdwr-Partial-Body"')
    assert n == 2
    gate = '<when condition="@((bool)context.Variables.GetValueOrDefault("setPartialBodyHeader", false))">'
    for i in [m for m in range(len(t)) if t.startswith('<set-header name="X-Rdwr-Partial-Body"', m)]:
        assert gate in t[i - 400:i], "X-Rdwr-Partial-Body set-header is not gated"


def test_true_host_rejects_control_characters():
    t = frag("inbound")
    start = t.index('name="rdwrHostResolved"')
    end = t.index('name="rdwrTrueHostSource"', start)
    body = t[start:end]
    assert "(char)0x20" in body and "(char)0x7f" in body
    assert "bool usable = !ctl &&" in body
