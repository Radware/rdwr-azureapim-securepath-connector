import importlib.util
import json
import os
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("lint", os.path.join(HERE, "..", "securepath-apim-lint.py"))
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)

OOP = "https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net/orders/1"
V1 = "https://afa37f7d53ce4e76a4988c4955c2d7e5.v1.radwarecloud.net/orders/1"
CERT_ERR = "The remote certificate was rejected by the provided RemoteCertificateValidationCallback."


# ---------------------------------------------------------------- builders (shapes taken from real traces)

def e(source, data):
    return {"source": source, "timestamp": "2026-09-03T15:24:50Z", "elapsed": "00:00:00.01", "data": data}


def inspector(api="/orders", method="GET", uri="/*"):
    return e("api-inspector", {"configuration": {"api": {"from": api, "revision": "1"},
                                                 "operation": {"method": method, "uriTemplate": uri}}})


def enter_fragment(name="securepath-inbound"):
    return e("include-fragment", f"Entering policy fragment '{name}'")


def leave_fragment(name="securepath-inbound"):
    return e("include-fragment", f"Leaving policy fragment '{name}'")


def setvar(name, value):
    return e("set-variable", {"message": "Context variable was successfully set.", "name": name, "value": value})


def sideband_sent(url=OOP, status=200, headers=None):
    hdrs = [{"name": k, "value": v} for k, v in (headers or {"x-rdwr-oop-request-status": "allowed"}).items()]
    return [e("request-forwarder", {"message": "Request is being forwarded to the backend service.",
                                    "request": {"url": url, "method": "POST", "headers": []}}),
            e("send-request", {"response": {"status": {"code": status, "reason": "OK"}, "headers": hdrs}})]


def sideband_failed(url=V1, reason=CERT_ERR):
    return [e("send-request", f"POST request to '{url}' resulted in error, error ignored: {reason}")]


def verdict_allow():
    return [setvar("radwareDiag", ""), setvar("rwStatus", 200), setvar("oopRequestStatusHeader", "allowed"),
            setvar("rdwrOopId", "24b61978ec0c4a90bbfbbf17496d38a9"), setvar("rdwrOopLog", "2")]


def diag(value):
    return [setvar("radwareDiag", ""), setvar("radwareDiag", value),
            e("set-header", {"header": {"name": "X-Rdwr-Diag", "value": value}, "message": "assigned"})]


def one_way(url=OOP):
    return e("send-one-way-request", f"One way request was successfully send to {url}.")


def origin(status=200):
    return [e("request-forwarder", {"message": "forwarding", "request": {"url": "https://origin.example.net/"}}),
            e("forward-request", {"response": {"status": {"code": status, "reason": "OK"}, "headers": []}})]


def trace(inbound, outbound=None, backend=None, on_error=None):
    return {"serviceName": "apim", "traceId": "t-1",
            "traceEntries": {"inbound": inbound, "backend": backend if backend is not None else origin(),
                             "outbound": outbound or [], "onError": on_error or []}}


def healthy():
    return trace([inspector(), enter_fragment("securepath-app-map"), leave_fragment("securepath-app-map"),
                  enter_fragment()] + sideband_sent() + verdict_allow() + [leave_fragment()],
                 outbound=[enter_fragment("securepath-outbound"), one_way(), leave_fragment("securepath-outbound")])


def codes(findings):
    return [f.code for f in findings]


# ---------------------------------------------------------------- summary

def test_healthy_summary_and_no_findings():
    t = healthy()
    s = lint.summarize_trace(t)
    assert s["connector_ran"] and s["connector_form"] == "fragments"
    assert s["before_connector"] == []
    assert s["sideband_url"] == OOP and s["sideband_status"] == 200 and s["sideband_error"] is None
    assert s["verdict_status"] == 200 and s["oop_request_status"] == "allowed"
    assert s["response_log"] == "sent" and s["origin_status"] == 200
    assert s["api"] == "/orders" and s["operation"] == "GET /*"
    assert lint.lint_trace(t) == []
    text = lint.format_trace_summary(s)
    assert "connector ran:          yes (fragments)" in text and "verdict:                allow" in text


def test_document_form_detected_by_rdwrAppEpAddr():
    t = trace([inspector(), setvar("rdwrAppEpAddr", "x.oop.radwarecloud.net"), setvar("rdwrAppId", "x")]
              + sideband_sent() + verdict_allow())
    assert lint.summarize_trace(t)["connector_form"] == "document"
    assert lint.lint_trace(t) == []


def test_response_log_not_requested_when_oop_log_absent():
    t = trace([inspector(), enter_fragment()] + sideband_sent() + [setvar("rwStatus", 200),
              setvar("oopRequestStatusHeader", "allowed"), setvar("rdwrOopLog", "")])
    assert lint.summarize_trace(t)["response_log"] == "not requested"


def test_response_log_not_sent_when_requested_but_missing():
    t = trace([inspector(), enter_fragment()] + sideband_sent() + verdict_allow())
    assert lint.summarize_trace(t)["response_log"] == "not sent"


# ---------------------------------------------------------------- findings

def test_T01_connector_did_not_run():
    t = trace([inspector(), e("validate-jwt", {"message": "JWT validation succeeded."})])
    f = lint.lint_trace(t)
    assert codes(f) == ["T01"] and "/orders" in f[0].message


def test_T02_request_ending_policy_before_connector():
    t = trace([inspector(), e("validate-jwt", {"message": "JWT validation succeeded."}), enter_fragment()]
              + sideband_sent() + verdict_allow())
    f = lint.lint_trace(t)
    assert codes(f) == ["T02"] and "validate-jwt" in f[0].message


def test_T02_not_raised_when_jwt_runs_after_connector():
    t = trace([inspector(), enter_fragment()] + sideband_sent() + verdict_allow()
              + [leave_fragment(), e("validate-jwt", {"message": "JWT validation succeeded."})])
    assert codes(lint.lint_trace(t)) == []


def test_field_shape_v1_host_and_certificate_rejected():
    # connector in the right place, endpoint Named Value holds the .v1 front-end host, no trust for it
    t = trace([inspector("/orders", "POST", "/api/x"), setvar("rdwrAppEpAddr", "afa37f7d53ce4e76a4988c4955c2d7e5.v1.radwarecloud.net")]
              + sideband_failed() + diag("sideband_error_or_timeout")
              + [e("validate-jwt", {"message": "JWT validation succeeded."})])
    s = lint.summarize_trace(t)
    assert s["sideband_url"] == V1 and s["sideband_error"].startswith("The remote certificate")
    assert s["diag"] == "sideband_error_or_timeout" and s["before_connector"] == []
    f = lint.lint_trace(t)
    assert codes(f) == ["T03", "T04"]
    assert ".v1.radwarecloud.net" in f[0].message
    assert "fix T03 first" in f[1].fix and "Path B" in f[1].fix
    assert "served uninspected (X-Rdwr-Diag = sideband_error_or_timeout)" in lint.format_trace_summary(s)


def test_T04_certificate_rejected_on_correct_host_points_at_step_1_only():
    t = trace([inspector(), enter_fragment()] + sideband_failed(url=OOP) + diag("sideband_error_or_timeout"))
    f = lint.lint_trace(t)
    assert codes(f) == ["T04"] and "fix T03 first" not in f[0].fix


def test_T04_timeout_classified():
    t = trace([inspector(), enter_fragment()]
              + sideband_failed(url=OOP, reason="The request was canceled due to the configured HttpClient.Timeout of 10 seconds elapsing.")
              + diag("sideband_error_or_timeout"))
    f = lint.lint_trace(t)
    assert codes(f) == ["T04"] and "rdwr-app-ep-timeout-seconds" in f[0].message


def test_T04_dns_classified():
    t = trace([inspector(), enter_fragment()]
              + sideband_failed(url="https://typo.oop.radwarecloud.net/x", reason="No such host is known.")
              + diag("sideband_error_or_timeout"))
    f = lint.lint_trace(t)
    assert codes(f) == ["T04"] and "does not resolve" in f[0].message


def test_T05_wrong_api_key_redirect():
    t = trace([inspector(), enter_fragment()]
              + sideband_sent(status=302, headers={"location": "https://x.radwarecloud.net/wrong-api-key"})
              + [setvar("rwStatus", 302)] + diag("wrong_api_key_redirect"))
    f = lint.lint_trace(t)
    assert codes(f) == ["T05"]


def test_T06_securepath_5xx():
    t = trace([inspector(), enter_fragment()] + sideband_sent(status=503, headers={})
              + [setvar("rwStatus", 503)] + diag("sideband_error_failopen_5xx"))
    f = lint.lint_trace(t)
    assert codes(f) == ["T06"] and "503" in f[0].message


def test_T07_no_app_mapping():
    t = trace([inspector(), enter_fragment()] + diag("no_app_mapping"))
    f = lint.lint_trace(t)
    assert codes(f) == ["T07"] and "no application map entry" in f[0].message


def test_T07_unusable_redirect():
    t = trace([inspector(), enter_fragment()] + sideband_sent(status=302, headers={})
              + [setvar("rwStatus", 302)] + diag("unusable_redirect_302"))
    f = lint.lint_trace(t)
    assert codes(f) == ["T07"] and "without a usable Location" in f[0].message
    assert lint._is_fail_open("unusable_redirect_302")  # the readout's verdict line says "served uninspected"


def test_bypass_by_rule_is_not_a_finding():
    t = trace([inspector(), enter_fragment(), setvar("shouldBypassRadware", True), leave_fragment()])
    assert lint.lint_trace(t) == []
    assert "a bypass rule matched" in lint.format_trace_summary(lint.summarize_trace(t))


def test_block_verdict_summary():
    t = trace([inspector(), enter_fragment()] + sideband_sent(status=403, headers={})
              + [setvar("radwareDiag", ""), setvar("rwStatus", 403), setvar("oopRequestStatusHeader", "")], backend=[])
    s = lint.summarize_trace(t)
    assert lint.lint_trace(t) == [] and "block (403" in lint.format_trace_summary(s)


# ---------------------------------------------------------------- CLI

def test_cli_trace_mode(capsys):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(healthy(), f)
    try:
        assert lint.main(["--trace", f.name]) == 0
        out = capsys.readouterr().out
        assert "Trace summary" in out and out.strip().endswith("clean")
        assert lint.main(["--trace", f.name, "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["connector_ran"] is True and payload["findings"] == []
    finally:
        os.unlink(f.name)


def test_cli_rejects_non_trace_json(capsys):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"value": []}, f)
    try:
        assert lint.main(["--trace", f.name]) == 2
        assert "not an API Management trace" in capsys.readouterr().err
    finally:
        os.unlink(f.name)


def test_cli_trace_with_bom(capsys):
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as f:
        f.write(b"\xef\xbb\xbf" + json.dumps(healthy()).encode())
    try:
        assert lint.main(["--trace", f.name]) == 0
    finally:
        os.unlink(f.name)


def test_enforced_403_is_a_block_not_a_fail_open():
    t = trace([inspector(), enter_fragment()] + sideband_sent(status=403, headers={})
              + [setvar("radwareDiag", ""), setvar("rwStatus", 403), setvar("oopRequestStatusHeader", ""),
                 setvar("radwareDiag", "action_enforced_status_403")], backend=[])
    s = lint.summarize_trace(t)
    assert s["diag"] is None and s["enforced"] == "action_enforced_status_403"
    assert lint.lint_trace(t) == [] and "block (403" in lint.format_trace_summary(s)


def test_custom_bot_block_relay_summary():
    t = trace([inspector(), enter_fragment()] + sideband_sent(status=429, headers={"retry-after": "30"})
              + [setvar("radwareDiag", ""), setvar("rwStatus", 429), setvar("oopRequestStatusHeader", ""),
                 setvar("radwareDiag", "custom_bot_block_status_429")], backend=[])
    s = lint.summarize_trace(t)
    assert lint.lint_trace(t) == []
    assert "block (custom Bot Manager status 429 relayed to the client)" in lint.format_trace_summary(s)


# ---------------------------------------------------------------- diag classification and T01 wording

def test_every_connector_diag_value_is_classified():
    fail_open = ["sideband_error_or_timeout", "sideband_error_failopen_503", "wrong_api_key_redirect",
                 "unexpected_status_418", "no_app_mapping", "config_incomplete", "app_map_invalid"]
    for d in fail_open:
        t = trace([inspector(), enter_fragment()] + sideband_sent() + diag(d))
        s = lint.summarize_trace(t)
        assert s["diag"] == d and "served uninspected" in lint.format_trace_summary(s), d
    for d, text in (("uzmcr_allow", "mobile exception"), ("multipart_headers_only", "headers-only")):
        t = trace([inspector(), enter_fragment()] + sideband_sent() + [setvar("rwStatus", 200), setvar("radwareDiag", d)])
        s = lint.summarize_trace(t)
        assert s["diag"] is None and s["note"] == d and text in lint.format_trace_summary(s) and lint.lint_trace(t) == [], d
    t = trace([inspector(), enter_fragment()] + sideband_sent(status=302, headers={"location": "https://challenge.example/"})
              + [setvar("rwStatus", 302), setvar("radwareDiag", "redirect_issued_302")], backend=[])
    s = lint.summarize_trace(t)
    assert s["enforced"] == "redirect_issued_302" and "redirect (302 from SecurePath)" in lint.format_trace_summary(s)
    assert lint.lint_trace(t) == []


def test_T01_names_the_policy_that_ended_the_request():
    t = trace([inspector(), e("validate-jwt", {"message": "JWT validation failed."})], backend=[])
    f = lint.lint_trace(t)
    assert codes(f) == ["T01"] and "'validate-jwt' ran and the connector was never reached" in f[0].message


def test_redact_replaces_credentials_everywhere():
    t = trace([inspector(), e("api-inspector", {"request": {"headers": [{"name": "Authorization", "value": "Bearer abc"},
                                                                      {"name": "Cookie", "value": "__uzma=1"},
                                                                      {"name": "Apim-Debug-Authorization", "value": "tok"}]}}),
               enter_fragment(), e("set-header", {"header": {"name": "X-Rdwr-Api-Key", "value": "k-secret"}, "message": "assigned"}),
               setvar("rdwrApiKey", "k-secret")] + sideband_sent())
    n = lint.redact_trace(t)
    dumped = json.dumps(t)
    assert n >= 5 and "Bearer abc" not in dumped and "k-secret" not in dumped and "tok" not in dumped and "__uzma=1" not in dumped
    assert lint.summarize_trace(t)["connector_ran"]  # still readable


def test_cli_redact_in_place(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps(trace([inspector(), e("api-inspector", {"request": {"headers": [{"name": "authorization", "value": "x"}]}}), enter_fragment()] + sideband_sent())))
    assert lint.main(["--redact", str(f)]) == 0
    assert "<redacted>" in f.read_text() and '"x"' not in f.read_text()
