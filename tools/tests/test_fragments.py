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


def test_plugin_info_fallback_is_v150():
    for name in ("outbound", "onerror"):
        assert "700-v1.5.0" in frag(name) and "700-v1.4" not in frag(name) and "700-v1.3" not in frag(name)


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
    non-truncated inspection call carried 'x-rdwr-partial-body:'), and since 2026-10-04 API
    Management refuses a <choose> inside send-request, so the header is removed by an exists-action
    expression on setPartialBodyHeader (executed on the rig: 'delete' leaves the header out
    entirely)."""
    t = frag("inbound")
    assert 'return isPartial ? "true" : null;' not in t
    n = t.count('<set-header name="X-Rdwr-Partial-Body"')
    assert n == 2
    gate = ('<set-header name="X-Rdwr-Partial-Body" exists-action="@((bool)context.Variables.GetValueOrDefault('
            '"setPartialBodyHeader", false) ? "override" : "delete")">')
    assert t.count(gate) == 2


def test_optional_log_headers_are_removed_not_sent_empty():
    """x-rdwr-o2h-* (sent only when the origin sent the header) and the body-sample content-type /
    content-transfer-encoding are dropped by their exists-action, never by a choose (refused inside
    send-one-way-request) and never by a null value (sent as an empty header)."""
    out = frag("outbound")
    for h in ("x-rdwr-o2h-content-type", "x-rdwr-o2h-server", "x-rdwr-o2h-set-cookie", "x-rdwr-o2h-x-aspnet-version",
              "x-rdwr-o2h-transfer-encoding", "x-rdwr-o2h-content-encoding"):
        i = out.index(f'<set-header name="{h}"')
        assert out[i:i + 300].count('? "delete" : "override")') == 1, h
    assert out.count('<set-header name="x-rdwr-o2h-') == 21
    for h in ("content-type", "content-transfer-encoding"):
        assert f'<set-header name="{h}" exists-action="@((bool)context.Variables["rdwrRespSample"] ? "override" : "delete")">' in out, h
    assert "return null;" not in out
    err = frag("onerror")
    i = err.index('<set-header name="x-rdwr-o2h-content-type"')
    assert '? "delete" : "override")' in err[i:i + 300]


def test_true_host_rejects_control_characters():
    t = frag("inbound")
    start = t.index('name="rdwrHostResolved"')
    end = t.index('name="rdwrTrueHostSource"', start)
    body = t[start:end]
    assert "(char)0x20" in body and "(char)0x7f" in body
    assert "bool usable = !ctl &&" in body


def test_inbound_sentinel_is_the_first_element():
    # on-error tells "rejected before any policy" from "rejected after inspection" by this
    # variable; anything ahead of it could throw and let on-error inspect the request twice
    t = frag("inbound")
    body = t[t.index("<fragment>") + len("<fragment>"):]
    first = re.search(r"<(?!!--)([a-z-]+)\b[^>]*>", re.sub(r"<!--.*?-->", "", body, flags=re.S))
    assert first.group(0) == '<set-variable name="rdwrInboundEntered" value="@(true)" />'


def test_diag_header_never_set_when_running_from_on_error():
    t = frag("inbound")
    tail = t[t.rindex("<!-- ====== End of the inspected path ====== -->"):]
    header_when = tail[:tail.index('<set-header name="X-Rdwr-Diag"')]
    assert '!(bool)context.Variables.GetValueOrDefault("rdwrUnrouted", false)' in header_when
    # the unrouted fail-open is still audible
    assert "was not inspected" in tail and 'severity="error"' in tail


def test_onerror_marks_only_the_proven_pre_policy_rejections():
    t = frag("onerror")
    decl = t[t.index('<set-variable name="rdwrUnrouted"'):]
    decl = decl[:decl.index('" />') ]
    assert 'ContainsKey("rdwrInboundEntered")' in decl
    for reason in ("OperationNotFound", "SubscriptionKeyNotFound", "SubscriptionKeyInvalid"):
        assert f'"{reason}"' in decl
    assert decl.count('reason == "') == 3
    # decided before the response-phase log branch, which must not fire for these
    assert t.index('name="rdwrUnrouted"') < t.index("<send-one-way-request")


def test_outbound_never_reads_the_response_body_except_a_bounded_sample():
    """Reading context.Response.Body makes API Management hold the whole response before the client
    gets its first byte (a server-sent-events stream, a long poll, a large download). Byte counts come
    from Content-Length; the one read is the body sample, and only for a response that declares a
    length within rdwr-body-max-size-bytes (rdwrRespSample)."""
    out = frag("outbound")
    assert out.count("context.Response.Body.As<") == 1
    i = out.index("context.Response.Body.As<")
    assert 'if ((bool)context.Variables["rdwrRespSample"]) {' in out[out.rindex("<set-body>", 0, i):i]
    decl = out[out.index('name="rdwrRespSample"'):]
    decl = decl[:decl.index('}" />')]
    assert "declared > 0 && declared <= maxBody" in decl and '!= "3"' in decl
    lengths = out[out.index('name="rdwrRespDeclaredLength"'):]
    lengths = lengths[:lengths.index('}" />')]
    assert '"HEAD"' in lengths and "Content-Length" in lengths


def test_securepath_body_is_read_only_when_a_routed_verdict_uses_it():
    """The inspection call's timeout bounds SecurePath's status and headers only; reading its body is
    unbounded, and a failed read is an error API Management turns into a 500. So an allow or a
    fail-open never reads it, and a request API Management answered itself (running from on-error,
    where an error cannot be handled) never reads it either."""
    t = frag("inbound")
    decl = t[t.index('<set-variable name="rdwrVerdictNeedsBody"'):]
    decl = decl[:decl.index('}" />')]
    first = decl[decl.index("@{") + 2:].strip().splitlines()
    code = [ln.strip() for ln in first if ln.strip() and not ln.strip().startswith("//")]
    assert code[0] == 'if ((bool)context.Variables.GetValueOrDefault("rdwrUnrouted", false)) { return false; }'
    assert t.count("((IResponse)context.Variables[\"radwareResponse\"]).Body.As<") == 1
    i_read = t.index("((IResponse)context.Variables[\"radwareResponse\"]).Body.As<")
    gate = t.rindex('<when condition="@((bool)context.Variables["rdwrVerdictNeedsBody"])">', 0, i_read)
    assert t.index('name="rdwrBlockPageBase"') < gate  # the page exists before the read
    pending = t.index('<set-variable name="rdwrBlockBodyPending" value="@{', gate)
    cleared = t.index('<set-variable name="rdwrBlockBodyPending" value="@(0)" />', i_read)
    assert gate < pending < i_read < cleared


def test_json_block_relays_securepath_json_only_when_its_body_was_read():
    t = frag("inbound")
    assert t.count('GetValueOrDefault("rdwrSpBodyRead", false)') == 5


def test_onerror_enforces_a_block_whose_body_could_not_be_read():
    t = frag("onerror")
    i_rec = t.index('<when condition="@((int)context.Variables.GetValueOrDefault("rdwrBlockBodyPending", 0) > 0)">')
    i_log = t.index("<!-- ====== SecurePath response-phase log from the on-error section ======")
    assert t.index('name="rdwrUnrouted"') < i_rec < i_log
    branch = t[i_rec:t.index("</return-response>", i_rec)]
    assert "<return-response>" in branch and 'name="rdwrLogSent" value="@(true)"' in branch
    assert "<value>blocked</value>" in branch and 'rdwrRecoveredPage' in branch


def test_inspection_copy_is_fitted_to_the_endpoint_header_limits():
    """OI-36: the SecurePath endpoint answers 503 above 100 header lines and 400 to a header block it
    cannot buffer, and the connector fails open on both. API Management admits far more; the
    inspection copy is fitted (rdwrFitDrop) and the drop is applied in each send-request by a fixed
    set of delete-slots (send-request takes no choose). The kept list, the method, path, query, body
    and the request to the backend are untouched."""
    t = frag("inbound")
    comp = t[t.index('name="rdwrFitDrop"'):]
    comp = comp[:comp.index('}" />')]
    assert "lines > 100" in comp and "16384" in comp
    for kept in ('"host"', '"cookie"', '"user-agent"', '"authorization"', '"x-forwarded-for"', '"content-type"'):
        assert kept in comp, kept
    assert "configuredHeaderNameForClientIp" in comp  # the configured client-IP header is kept
    assert 'n.StartsWith("x-rdwr-")' in comp           # the connector's own are never dropped
    # the drop list is padded to a fixed length and applied by that many delete-slots in EACH of the
    # two send-request branches (send-request takes no choose)
    assert "name=\"rdwrFitDropPad\"" in t
    pad_slots = t.count('(string[])context.Variables["rdwrFitDropPad"])[')
    assert pad_slots >= 2 * 120 and pad_slots % 2 == 0, pad_slots   # >=120 per branch, both branches
    assert '"x-rdwr-fit-slot-" + i' in t                            # pad filler builds unique no-op names
    # the backend forward path is not touched by the fit (no fit var feeds a backend set-header)
    assert "rdwrFitDrop" not in frag("outbound") and "rdwrFitDrop" not in frag("onerror")


def test_a_kept_header_over_the_line_limit_is_cut_not_sent_oversized():
    """OI-36 (fleet rule): a kept header is never left out, but one whose single line would exceed the
    endpoint's ~8 KB limit, or kept headers that together exceed the 16384-byte block, are CUT in the
    inspection copy only. Cookie keeps the Bot Manager cookies first; the others truncate at a byte
    boundary. The request to the backend is never changed."""
    t = frag("inbound")
    comp = t[t.index('name="rdwrKeptCut"'):]
    comp = comp[:comp.index('}" />')]
    # cookie rebuild puts the Bot Manager cookies first, then the rest in order
    assert '"__uzm"' in comp and '"uzmcr"' in comp
    assert "cookieOrdered" in comp and "bm.AddRange" not in comp  # bm added before rest
    assert comp.index("bm.Add(part)") < comp.index("rest.Add(part)")
    assert "cookieOrdered.AddRange(bm); cookieOrdered.AddRange(rest);" in comp
    # per-line ~8 KB limit and the 16384-byte block limit are both enforced
    assert "8190" in comp and "16384" in comp
    # the 16384 total-block rule cuts the longest kept to a common byte cap (binary search on Lcap)
    assert "Lcap" in comp and "allowedKeptVal" in comp
    # the cut value is applied in BOTH send-request branches via precomputed scalars (no generic
    # type in element text, which XML forbids), as override/skip/delete
    for hl in ("cookie", "authorization", "user-agent", "x-forwarded-for", "content-type"):
        assert t.count(f'name="rdwrCutVal_{hl}"') == 1, hl          # one scalar each
        assert t.count(f'context.Variables["rdwrCutVal_{hl}"]') == 2, hl   # used in both branches
        assert t.count(f'context.Variables["rdwrCutAct_{hl}"]') == 2, hl
    assert t.count('context.Variables["rdwrCutVal_cip"]') == 2      # configured client-IP header too
    # no kept-header cut touches the backend-facing forward path
    assert "rdwrKeptCut" not in frag("outbound") and "rdwrKeptCut" not in frag("onerror")


def test_header_fit_never_targets_a_restricted_header():
    """API Management refuses set-header on connection-management/framing headers (Connection,
    Content-Length, Transfer-Encoding, ...). A delete-slot or a cut on one throws and turns a normal
    request into a 500 (found on the rig: a client Connection: keep-alive dropped by the fit 500'd).
    The fit must skip them from the drop candidates and from the kept-cut accounting."""
    t = frag("inbound")
    fd = t[t.index('name="rdwrFitDrop"'):]; fd = fd[:fd.index('}" />')]
    assert '"connection"' in fd and '"content-length"' in fd and '"transfer-encoding"' in fd
    assert 'restricted.Contains(n)) { continue; }' in fd   # skipped before being added to the drop list
    kc = t[t.index('name="rdwrKeptCut"'):]; kc = kc[:kc.index('}" />')]
    assert 'restricted.Contains(n)' in kc                   # same headers excluded from the block accounting
    # the cut set-headers only target application headers, none of them restricted
    for restricted in ('name="Connection"', 'name="Content-Length"', 'name="Transfer-Encoding"', 'name="Keep-Alive"'):
        assert restricted not in t, restricted


def test_static_bypass_ignores_path_parameters_and_is_case_sensitive():
    """Fleet rule (matches the NGINX reference): a last path segment carrying a path parameter (';',
    e.g. /admin;.js) is never static, and the extension is read from the raw path and compared
    case-sensitively, so /x.PNG is inspected while the lowercase list is authored lowercase."""
    t = frag("inbound")
    fe = t[t.index('name="fileExt"'):]; fe = fe[:fe.index('}" />')]
    assert "IndexOf(';')" in fe                      # a ';' in the last segment blocks the static treatment
    assert "lastSlash" in fe and "lastSeg" in fe
    # the extension source path is the raw OriginalUrl.Path, not a lowercased copy
    assert 'name="reqPathForExt" value="@(context.Request.OriginalUrl.Path ?? "")" />' in t
    assert 'context.Request.Url.Path.ToLower()' not in t
    # the list comparison is case-sensitive (no ToLower on the configured list)
    be = t[t.index('name="isBypassCandidateExtension"'):]; be = be[:be.index('}" />')]
    assert '.ToLower()' not in be


def test_a_bare_percent_in_the_path_is_escaped_for_inspection_only():
    """Fleet rule: a bare '%' in the PATH (not a %XX escape) draws a 400 from the endpoint, which the
    connector treats as fail-open, so it is escaped to %25 in the inspection copy. The query stays raw
    and the request to the backend is unchanged."""
    t = frag("inbound")
    raw = t[t.index('name="rdwrTargetRaw"'):]
    raw = raw[:raw.index('}" />')]
    assert "%25" in raw and "okEsc" in raw
    # the escape runs on the path only, before the query is appended
    assert raw.index("path = pfix.ToString();") < raw.index("var qs = context.Request.OriginalUrl.QueryString;")


def test_query_is_sent_to_securepath_as_received():
    """OI-36: the query must reach SecurePath exactly as the client sent it (no decode/re-encode),
    so the inspection request line is no longer than the one API Management admitted."""
    t = frag("inbound")
    raw = t[t.index('name="rdwrTargetRaw"'):]
    raw = raw[:raw.index('}" />')]
    assert "context.Request.OriginalUrl.QueryString" in raw
    assert "GetQueryParameters" not in raw and "ParseQueryString" not in raw and "UrlEncode" not in raw and "UrlDecode" not in raw
    # the fitted target only truncates the query (never a %-escape) to fit the 8192-byte request line
    fit = t[t.index('name="rdwrTargetDropped"'):]
    fit = fit[:fit.index('}" />')]
    assert "8192" in fit and "do not split a %-escape" in fit
    use = t[t.index('name="urlPathAndQueryToUse"'):]
    use = use[:use.index('}" />')]
    assert "rdwrTargetRaw" in use and "Substring(0, qs.Length - dropped)" in use


def test_multipart_follows_the_partial_body_rules_and_chunked_multipart_honours_the_list():
    """Multipart is not opaque any more: a declared length goes through the normal partial-body path
    (as in the reference); rdwr-multipart-max-size-bytes only makes a larger declared multipart
    headers-only; a CHUNKED multipart body is read only when multipart/form-data is listed."""
    t = frag("inbound")
    assert "Multipart is treated as opaque" not in t
    assert "Unknown size multipart with chunked TE: avoid buffering entire body" not in t
    i = t.index('<set-variable name="multipartContentLength"')
    assert i < t.index('<when condition="@((bool)context.Variables.GetValueOrDefault("isMultipart", false) && (long)context.Variables.GetValueOrDefault("multipartContentLength", -1L)')
    assert 'name="multipartHeadersOnly" value="@((bool)context.Variables.GetValueOrDefault("isMultipart", false))"' in t


def test_default_chunked_list_covers_the_api_body_types():
    root = os.path.join(HERE, "..", "..")
    want = "application/json,application/x-www-form-urlencoded,text/plain,application/soap+xml,text/xml,application/xml,xml/text"
    with open(os.path.join(root, "README.md"), encoding="utf-8") as f:
        assert f'"chunked-request-allowed-content-types={want}"' in f.read()
    with open(os.path.join(root, "deploy", "securepath-apim.bicep"), encoding="utf-8") as f:
        assert f"value: '{want}'" in f.read()
