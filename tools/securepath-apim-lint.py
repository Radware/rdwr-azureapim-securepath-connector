#!/usr/bin/env python3
"""Radware SecurePath connector for Azure API Management: install lint.

Checks a policy document (--file) or a live instance (--live) for the ways an
install can be silently ineffective: the connector missing or installed twice,
an API policy without <base /> skipping a global connector, a request-ending
policy placed ahead of the connector, an empty set-variable left by a manual
merge, an incomplete fragment set, missing or malformed Named Values, an invalid
application map, and a missing backend entity on v2 tiers. With --trace it reads
one API Management trace (the JSON returned by listTrace, or saved from the
Portal) and says what happened to that request: whether the connector ran,
what ran before it, where the inspection call went and how it ended, the
verdict, and why a request was served uninspected.

Text-based on purpose: API Management policy documents are not well-formed
XML (Named Value references and C# expressions sit inside attribute values).

Exit codes: 0 clean, 1 findings, 2 could not read.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

API_VERSION = "2024-05-01"
SECTIONS = ("inbound", "backend", "outbound", "on-error")
FRAGMENT_SECTION = {"securepath-inbound": "inbound", "securepath-outbound": "outbound",
                    "securepath-onerror": "on-error"}
INLINE_MARKER = 'name="rdwrAppEpAddr"'
REQUEST_ENDING = ("validate-jwt", "validate-azure-ad-token", "check-header", "ip-filter",
                  "rate-limit", "rate-limit-by-key", "quota", "quota-by-key", "return-response",
                  "validate-content", "validate-parameters", "validate-headers",
                  "validate-client-certificate")
REQUIRED_NAMED_VALUES = (
    "rdwr-app-id", "rdwr-app-ep-addr", "rdwr-api-key", "rdwr-app-ep-port", "rdwr-app-ep-ssl",
    "rdwr-app-ep-timeout-seconds", "rdwr-body-max-size-bytes", "rdwr-partial-body-size-bytes",
    "rdwr-multipart-max-size-bytes", "rdwr-true-client-ip-header", "rdwr-api-base-path",
    "rdwr-bot-manager-enabled", "plugin-version-info", "static-extensions-enabled",
    "static-list-of-methods-not-to-inspect", "static-list-of-bypassed-extensions",
    "static-inspect-if-query-string-exists", "chunked-request-allowed-content-types",
    "rdwr-inline-trusted-sources", "rdwr-inline-headers-enabled",
    # v1.4.0
    "rdwr-app-map", "rdwr-true-host-header", "rdwr-custom-bot-block-statuses")
NEW_IN_140 = {"rdwr-app-map", "rdwr-true-host-header", "rdwr-custom-bot-block-statuses"}
# the fragments shipped next to this tool (package layout: tools/ and fragments/ side by side)
SHIPPED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fragments")
SHIPPED_FRAGMENTS = ("securepath-inbound", "securepath-outbound", "securepath-onerror")
STANDARD_VERDICT_STATUSES = (200, 301, 302, 403)
DISABLE_TOKENS = {"", "-", "disabled", "off", "false", "none", "~", "##disabled##"}

_BASE_RE = re.compile(r"<base\s*/>")
_INCLUDE_RE = re.compile(r'<include-fragment\s+fragment-id="([^"]+)"')
_TAG_RE = re.compile(r"^\s*<([a-z][a-z0-9-]*)\b")
_EMPTY_SETVAR_RE = re.compile(r'<set-variable\b(?![^>]*\bvalue=)[^>]*name="([^"]+)"[^>]*/>')


@dataclass
class Finding:
    code: str
    scope: str
    line: Optional[int]
    message: str
    fix: str

    def __str__(self):
        where = f" line {self.line}" if self.line else ""
        return f"{self.code} [{self.scope}]{where}: {self.message}. Fix: {self.fix}"


# ---------------------------------------------------------------- documents

def normalize_document(text: str) -> str:
    """A policy written on one line (the All APIs policy from README Step 4 / the Bicep
    template) gets one element per line so the line-based checks can see its sections."""
    if re.search(r"^\s*<inbound\b", text, re.M):
        return text
    return re.sub(r">\s*<", ">\n<", text)


def split_sections(text: str) -> Dict[str, Tuple[int, List[str]]]:
    """Section name -> (1-based line of its opening tag, the lines inside it)."""
    lines = normalize_document(text).splitlines()
    out: Dict[str, Tuple[int, List[str]]] = {}
    for name in SECTIONS:
        open_re = re.compile(rf"^\s*<{name}(\s*/>|\s*>)")
        close_re = re.compile(rf"^\s*</{name}\s*>")
        start = None
        for i, ln in enumerate(lines):
            m = open_re.match(ln)
            if m and start is None:
                if m.group(1).strip() == "/>":
                    out[name] = (i + 1, [])
                    break
                start = i
                continue
            if start is not None and close_re.match(ln):
                out[name] = (start + 1, lines[start + 1:i])
                break
    return out


def connector_in(section_lines: List[str]) -> Optional[int]:
    """0-based index of the first line that brings the connector into this section."""
    for i, ln in enumerate(section_lines):
        m = _INCLUDE_RE.search(ln)
        if (m and m.group(1) in FRAGMENT_SECTION) or INLINE_MARKER in ln:
            return i
    return None


def _first_request_ending(section_lines: List[str]) -> Optional[Tuple[int, str]]:
    for i, ln in enumerate(section_lines):
        m = _TAG_RE.match(ln)
        if m and m.group(1) in REQUEST_ENDING:
            return i, m.group(1)
    return None


def document_has_connector(text: str) -> bool:
    return connector_in(split_sections(text).get("inbound", (None, []))[1]) is not None


def lint_document(text: str, scope: str, label: str) -> List[Finding]:
    """Findings for one policy document. scope is global, product or api."""
    findings: List[Finding] = []
    sections = split_sections(text)
    inbound = sections.get("inbound", (None, []))[1]
    present_in = {name: connector_in(sections.get(name, (None, []))[1]) is not None
                  for name in ("inbound", "outbound", "on-error")}

    # L03: <base /> missing from a section (non-global scopes only)
    if scope != "global":
        for name in ("inbound", "outbound", "on-error"):
            start, body = sections.get(name, (None, None))
            if body is None:
                continue
            if not any(_BASE_RE.search(ln) for ln in body):
                findings.append(Finding(
                    "L03", label, start,
                    f"<{name}> has no <base />; a connector installed at All APIs (or product) "
                    f"scope is skipped for this {scope}",
                    f"add <base /> as the first element of <{name}>"))

    # L04: a request-ending policy ahead of the connector in inbound
    conn_idx = connector_in(inbound)
    if conn_idx is not None:
        ender = _first_request_ending(inbound[:conn_idx])
        if ender is not None:
            abs_line = sections["inbound"][0] + 1 + ender[0]
            findings.append(Finding(
                "L04", label, abs_line,
                f"<{ender[1]}> runs before the SecurePath connector; requests it rejects are never inspected",
                "move the securepath-inbound include (or the connector block) directly after <base />, "
                "before your own policies"))

    # L05: set-variable without a value (manual merge damage)
    for i, ln in enumerate(normalize_document(text).splitlines(), start=1):
        m = _EMPTY_SETVAR_RE.search(ln)
        if m:
            findings.append(Finding(
                "L05", label, i, f'<set-variable name="{m.group(1)}"> has no value attribute',
                "restore the value from the shipped policy, or install the fragments instead of a merged document"))

    # L06: incomplete fragment set. Only for fragment-based installs: a whole
    # policy document carries its outbound code inline and is complete by itself.
    uses_fragments = any(_INCLUDE_RE.search(ln) and _INCLUDE_RE.search(ln).group(1) in FRAGMENT_SECTION
                         for body in (sections.get(n, (None, []))[1] for n in ("inbound", "outbound", "on-error"))
                         for ln in body)
    if uses_fragments:
        for frag, name in FRAGMENT_SECTION.items():
            if not present_in[name]:
                findings.append(Finding(
                    "L06", label, sections.get(name, (None, []))[0],
                    f"{frag} is not referenced in <{name}> while the connector is present elsewhere in this document",
                    f'add <include-fragment fragment-id="{frag}" /> after <base /> in <{name}>'))
    return findings


# ---------------------------------------------------------------- instances

class Reader:
    """What lint needs from an instance. AzReader talks to Azure; tests fake it."""

    def sku(self) -> str: raise NotImplementedError
    def global_policy(self) -> Optional[str]: raise NotImplementedError
    def apis(self) -> List[str]: raise NotImplementedError
    def api_policy(self, api_id: str) -> Optional[str]: raise NotImplementedError
    def products(self) -> List[str]: raise NotImplementedError
    def product_policy(self, product_id: str) -> Optional[str]: raise NotImplementedError
    def named_values(self) -> Dict[str, Optional[str]]: raise NotImplementedError
    def backends(self) -> List[str]: raise NotImplementedError
    def fragment(self, fragment_id: str) -> Optional[str]: return None  # text, or None when absent


class AzReader(Reader):
    """Reads through the Azure CLI (az rest). Requires an active az login."""

    def __init__(self, rg: str, apim: str):
        sub = self._az(["account", "show", "--query", "id", "-o", "tsv"]).strip()
        if not sub:
            raise RuntimeError("az account show returned nothing; run az login")
        self.base = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
                     f"/providers/Microsoft.ApiManagement/service/{apim}")

    @staticmethod
    def _az(args: List[str]) -> str:
        if args and args[0] == "rest" and "-o" not in args and "--output" not in args:
            args = list(args) + ["-o", "json"]  # never depend on the user's default output format
        p = subprocess.run(["az"] + args, capture_output=True, text=True)
        if p.returncode != 0:
            err = p.stderr or ""
            if "404" in err or "NotFound" in err or "ResourceNotFound" in err:
                return ""
            raise RuntimeError(err.strip() or f"az {' '.join(args)} failed")
        return p.stdout

    def _get(self, path: str, query: str = "") -> dict:
        raw = self._az(["rest", "--method", "GET",
                        "--uri", f"{self.base}{path}?api-version={API_VERSION}{query}"])
        return self._parse(raw)

    def _list(self, path: str) -> List[dict]:
        """Every item of a paged ARM collection (nextLink followed)."""
        items: List[dict] = []
        page = self._get(path)
        while True:
            items.extend(page.get("value", []))
            link = page.get("nextLink")
            if not link:
                return items
            page = self._parse(self._az(["rest", "--method", "GET", "--uri", link]))

    @staticmethod
    def _parse(raw: str) -> dict:
        # Policy responses carry a UTF-8 byte-order mark; az rest passes it through.
        raw = (raw or "").lstrip("﻿").strip()
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError as e:
            raise RuntimeError(f"unexpected response from az rest: {e}: {raw[:120]!r}") from e

    def _policy(self, path: str) -> Optional[str]:
        # API Management answers a rawxml policy GET with the document itself
        # (content type application/vnd.ms-azure-apim.policy.raw+xml), which az rest
        # prints verbatim. Accept that, and the JSON envelope, and 404 (no policy).
        raw = (self._az(["rest", "--method", "GET",
                         "--uri", f"{self.base}{path}/policies/policy?api-version={API_VERSION}&format=rawxml"])
               or "").lstrip("﻿").strip()
        if not raw:
            return None
        if raw.startswith("<"):
            return raw
        v = (self._parse(raw).get("properties") or {}).get("value")
        return v.lstrip("﻿") if v else None

    def sku(self) -> str:
        return (self._get("").get("sku") or {}).get("name", "")

    def global_policy(self):
        return self._policy("")

    def apis(self):
        return [a["name"] for a in self._list("/apis")]

    def api_policy(self, api_id):
        return self._policy(f"/apis/{api_id}")

    def products(self):
        return [p["name"] for p in self._list("/products")]

    def product_policy(self, product_id):
        return self._policy(f"/products/{product_id}")

    def named_values(self):
        # Secret values are read only for the connector's own Named Values; other workloads'
        # secrets on the instance are listed by name and never read.
        out: Dict[str, Optional[str]] = {}
        for nv in self._list("/namedValues"):
            name, props = nv["name"], nv.get("properties") or {}
            ours = name in REQUIRED_NAMED_VALUES or name.startswith("rdwr-app-key-")
            if props.get("secret") and not ours:
                out[name] = None
            elif props.get("secret"):
                raw = self._az(["rest", "--method", "POST", "--uri",
                                f"{self.base}/namedValues/{name}/listValue?api-version={API_VERSION}"])
                out[name] = self._parse(raw).get("value")
            else:
                out[name] = props.get("value")
        return out

    def backends(self):
        return [(b.get("properties") or {}).get("url", "") for b in self._list("/backends")]

    def fragment(self, fragment_id):
        raw = (self._az(["rest", "--method", "GET", "--uri",
                         f"{self.base}/policyFragments/{fragment_id}?api-version={API_VERSION}&format=rawxml"]) or "").lstrip("\ufeff").strip()
        if not raw:
            return None
        if raw.startswith("<"):
            return raw
        return (self._parse(raw).get("properties") or {}).get("value")


def parse_app_map(raw: str) -> dict:
    """The application map is single-quoted JSON (a Named Value is substituted inside
    an XML attribute, so it cannot carry double quotes). Accept both forms."""
    raw = (raw or "").strip()
    try:
        return json.loads(raw)
    except ValueError:
        if '"' in raw:
            raise
        return json.loads(raw.replace("'", '"'))


def _host_of(url: str) -> str:
    return re.sub(r"^https?://", "", url or "").split("/")[0].split(":")[0].lower()


def shipped_fragment(fragment_id: str) -> Optional[str]:
    path = os.path.join(SHIPPED_DIR, f"{fragment_id}.fragment.xml")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8-sig") as f:
        return f.read()


def _norm_xml(text: str) -> str:
    # the instance stores a fragment re-indented (tabs, CRLF): compare content, not layout
    return "\n".join(line.strip() for line in (text or "").replace("\r\n", "\n").strip().split("\n") if line.strip())


def check_shipped_fragments(reader: Reader, uses_fragments: bool) -> List[Finding]:
    """L14: a connector fragment on the instance must be the one shipped in this package. A
    fragment PUT is asynchronous — the CLI reports success before validation finishes — so a
    rejected registration leaves the previous fragment in place without any error."""
    out: List[Finding] = []
    if not uses_fragments:
        return out
    for fid in SHIPPED_FRAGMENTS:
        shipped = shipped_fragment(fid)
        if shipped is None:
            continue
        live = reader.fragment(fid)
        if live is None:
            out.append(Finding("L14", "fragments", None, f"the {fid} fragment is referenced but not registered on the instance",
                               f"register fragments/{fid}.fragment.xml (README Step 4, Form 1)"))
        elif _norm_xml(live) != _norm_xml(shipped):
            out.append(Finding("L14", "fragments", None,
                               f"the {fid} fragment on the instance differs from fragments/{fid}.fragment.xml in this package",
                               "re-register it from this package and run this check again: a fragment registration is asynchronous and "
                               "the CLI reports success before validation, so a rejected upload silently keeps the previous fragment"))
    return out


def check_bot_block_statuses(value: str, bot_manager: str, where: str) -> List[Finding]:
    """L13: rdwr-custom-bot-block-statuses (or a map entry's bot_block_statuses) must be a disable
    token, "*", or a comma-separated list of status codes; 200/301/302/403 have no effect there,
    5xx is never applied, and the whole setting is ignored unless Bot Manager is enabled."""
    out: List[Finding] = []
    v = (value or "").strip()
    if v.lower() in DISABLE_TOKENS:
        return out
    if v != "*":
        parts = [p.strip() for p in v.split(",") if p.strip()]
        bad = [p for p in parts if not p.isdigit()]
        if bad or not parts:
            out.append(Finding("L13", "named-values", None,
                               f"{where} '{v}' is not a status-code list: the connector ignores the setting",
                               "use a comma-separated list of status codes such as 429,418, or * for any, or ##DISABLED##"))
            return out
        codes = [int(p) for p in parts]
        no_effect = sorted({c for c in codes if c in STANDARD_VERDICT_STATUSES})
        if no_effect:
            out.append(Finding("L13", "named-values", None,
                               f"{where} lists {', '.join(map(str, no_effect))}, which the connector handles as standard verdicts before this list is consulted",
                               "remove them; the list is for statuses outside 200/301/302/403"))
        fivexx = sorted({c for c in codes if c >= 500})
        if fivexx:
            out.append(Finding("L13", "named-values", None,
                               f"{where} lists {', '.join(map(str, fivexx))}: a 5xx from SecurePath is an endpoint problem and is never relayed as a block",
                               "remove them; a 5xx always fails open"))
    if (bot_manager or "").strip().lower() != "true":
        out.append(Finding("L13", "named-values", None,
                           f"{where} is set but rdwr-bot-manager-enabled is not true, so it is ignored",
                           "set rdwr-bot-manager-enabled=true if Bot Manager is enabled on the application, or set the list to ##DISABLED##"))
    return out


def lint_instance(reader: Reader) -> List[Finding]:
    findings: List[Finding] = []
    docs: List[Tuple[str, str, Optional[str]]] = [("global", "global", reader.global_policy())]
    docs += [("product", f"product:{p}", reader.product_policy(p)) for p in reader.products()]
    docs += [("api", f"api:{a}", reader.api_policy(a)) for a in reader.apis()]

    with_connector = [(scope, label) for scope, label, text in docs if text and document_has_connector(text)]
    global_has = any(scope == "global" for scope, _ in with_connector)

    if not with_connector:
        findings.append(Finding(
            "L01", "instance", None, "the SecurePath connector is not installed at any scope",
            "install the fragments at All APIs scope (see deploy/) or reference them from one API or product policy"))
    if len(with_connector) > 1:
        for scope, label in with_connector:
            others = ", ".join(lab for _, lab in with_connector if lab != label)
            findings.append(Finding(
                "L02", label, None,
                f"connector also present at {others}: every request is inspected more than once",
                "keep the connector at one scope only"))

    for scope, label, text in docs:
        if not text:
            continue
        product_has = any(sc == "product" for sc, _ in with_connector)
        for f in lint_document(text, scope, label):
            if f.code == "L03" and not (global_has or (scope == "api" and product_has)):
                continue  # <base /> only matters when a wider scope carries the connector
            findings.append(f)

    nvs = reader.named_values()
    for name in REQUIRED_NAMED_VALUES:
        if name not in nvs:
            new = " (new in v1.4.0)" if name in NEW_IN_140 else ""
            findings.append(Finding(
                "L07", "named-values", None, f"required Named Value {name} is missing{new}",
                "create it (README Step 3); the policy upload is rejected without it"))
    app_id = (nvs.get("rdwr-app-id") or "").strip()
    ep = (nvs.get("rdwr-app-ep-addr") or "").strip()
    ep_ssl = (nvs.get("rdwr-app-ep-ssl") or "true").strip().lower() != "false"
    if app_id and "." in app_id:
        findings.append(Finding(
            "L08", "named-values", None,
            f"rdwr-app-id '{app_id}' contains a dot; that is a hostname, not the Application ID",
            "set rdwr-app-id to the bare Application ID from the Radware Cloud portal"))
    if ep and not ep.lower().endswith(".oop.radwarecloud.net"):
        findings.append(Finding(
            "L08", "named-values", None, f"rdwr-app-ep-addr '{ep}' is not an inspection endpoint",
            "use the hostname ending in .oop.radwarecloud.net (not .v1)"))

    # endpoints that need trust: the default one (when TLS is on) plus every map entry
    endpoints = {ep.lower()} if (ep and ep_ssl) else set()

    # generated application map (tools/securepath-apim-sync.py) in the securepath-app-map fragment
    uses_fragments = any(text and 'fragment-id="securepath-inbound"' in text for _, _, text in docs)
    for scope, label, text in docs:
        if not text or 'fragment-id="securepath-inbound"' not in text:
            continue
        i_in = text.index('fragment-id="securepath-inbound"')
        i_map = text.find('fragment-id="securepath-app-map"')
        if i_map < 0 or i_map > i_in:
            findings.append(Finding("L11", label, None,
                                    "securepath-inbound is referenced without securepath-app-map before it (fragments cannot include fragments, so the policy must)",
                                    'add <include-fragment fragment-id="securepath-app-map" /> immediately before the securepath-inbound line'))
    gen_text = reader.fragment("securepath-app-map")
    if uses_fragments and gen_text is None:
        findings.append(Finding("L11", "fragments", None, "the securepath-app-map fragment is not registered; the inbound fragment references it",
                                "register fragments/securepath-app-map.fragment.xml (README Step 4, Form 1) before the inbound fragment"))
    if gen_text:
        m = re.search(r'name="rdwrAppMapGenerated" value="(.*?)" />', gen_text, re.S)
        raw = (m.group(1).strip() if m else "")
        if not m:
            findings.append(Finding("L11", "fragments", None, "the securepath-app-map fragment does not set rdwrAppMapGenerated",
                                    "re-register fragments/securepath-app-map.fragment.xml or run securepath-apim-sync apply"))
        elif raw.lower() not in DISABLE_TOKENS:
            try:
                gen = parse_app_map(raw)
                if not isinstance(gen, dict):
                    raise ValueError("top level must be an object")
                for key, entry in gen.items():
                    for field in ("app_id", "api_key", "endpoint"):
                        if not isinstance(entry, dict) or not entry.get(field):
                            findings.append(Finding("L10", "fragments", None, f"generated map entry '{key}' lacks '{field}'",
                                                    "run securepath-apim-sync apply again"))
                    if isinstance(entry, dict):
                        ref = str(entry.get("api_key", ""))
                        if ref.startswith("{{") and ref.endswith("}}") and ref[2:-2] not in nvs:
                            findings.append(Finding("L12", "named-values", None, f"generated map entry '{key}' references the key Named Value {ref[2:-2]}, which does not exist",
                                                    "run securepath-apim-sync apply (it writes the key Named Values before the fragment)"))
                        if entry.get("endpoint") and entry.get("ssl", True) is not False:
                            endpoints.add(str(entry["endpoint"]).lower())
            except ValueError as e:
                findings.append(Finding("L10", "fragments", None, f"the generated map is not valid JSON ({e})",
                                        "run securepath-apim-sync apply again"))
    findings.extend(check_shipped_fragments(reader, uses_fragments))
    app_map_raw = nvs.get("rdwr-app-map")
    app_map = {}
    if app_map_raw is not None and app_map_raw.strip().lower() not in DISABLE_TOKENS:
        try:
            app_map = parse_app_map(app_map_raw)
            if not isinstance(app_map, dict):
                raise ValueError("top level must be an object")
            for key, entry in app_map.items():
                if not isinstance(entry, dict):
                    findings.append(Finding("L10", "named-values", None, f"rdwr-app-map entry '{key}' is not an object",
                                            "each entry is an object with app_id, api_key and endpoint"))
                    continue
                for field in ("app_id", "api_key", "endpoint"):
                    if not entry.get(field):
                        findings.append(Finding("L10", "named-values", None, f"rdwr-app-map entry '{key}' lacks '{field}'",
                                                "each entry needs app_id, api_key and endpoint"))
                if isinstance(entry, dict):
                    bp = entry.get("base_path")
                    if bp is not None and not str(bp).startswith("/"):
                        findings.append(Finding("L10", "named-values", None, f"rdwr-app-map entry '{key}' base_path '{bp}' must start with /",
                                                "use the API's path prefix, for example /orders"))
                    for field, ok, want in (("port", lambda v: isinstance(v, int) and not isinstance(v, bool), "a number such as 443"),
                                            ("ssl", lambda v: isinstance(v, bool), "true or false"),
                                            ("bot_manager", lambda v: isinstance(v, bool), "true or false"),
                                            ("bot_block_statuses", lambda v: isinstance(v, str), "a quoted list such as '429,418'")):
                        if entry.get(field) is not None and not ok(entry[field]):
                            findings.append(Finding("L10", "named-values", None,
                                                    f"rdwr-app-map entry '{key}' {field} is {json.dumps(entry[field])}, not {want}",
                                                    "the connector treats a mistyped entry as invalid and serves that application's requests uninspected (X-Rdwr-Diag: app_map_invalid)"))
                    if entry.get("endpoint") and entry.get("ssl", True) is not False:
                        endpoints.add(str(entry["endpoint"]).lower())
        except ValueError as e:
            findings.append(Finding("L10", "named-values", None, f"rdwr-app-map is not valid JSON ({e})",
                                    "fix the JSON (single quotes, no double quotes) or set the Named Value to ##DISABLED##"))
    if reader.sku().lower().endswith("v2") and endpoints:
        backend_hosts = {_host_of(u) for u in reader.backends()}
        for host in sorted(endpoints):
            if host not in backend_hosts:
                findings.append(Finding(
                    "L09", "backends", None,
                    f"no backend entity matches endpoint {host}; on v2 tiers the inspection call fails "
                    f"TLS validation and traffic is served uninspected",
                    "create the backend entity for this endpoint (README Step 1, Path B)"))
    if "rdwr-custom-bot-block-statuses" in nvs:
        findings.extend(check_bot_block_statuses(nvs.get("rdwr-custom-bot-block-statuses", ""), nvs.get("rdwr-bot-manager-enabled", ""), "rdwr-custom-bot-block-statuses"))
    for key, entry in (app_map.items() if isinstance(app_map, dict) else []):
        if isinstance(entry, dict) and entry.get("bot_block_statuses") is not None:
            bm = entry.get("bot_manager")
            bm_str = "true" if bm is True else ("false" if bm is False else nvs.get("rdwr-bot-manager-enabled", ""))
            findings.extend(check_bot_block_statuses(str(entry["bot_block_statuses"]), bm_str, f"rdwr-app-map entry '{key}' bot_block_statuses"))
    return findings


# ---------------------------------------------------------------- CLI

# ---------------------------------------------------------------- traces

OOP_SUFFIX = ".oop.radwarecloud.net"
_ERR_IGNORED_RE = re.compile(r"request to '([^']+)' resulted in error, error ignored: (.*)", re.S)
FAIL_OPEN_DIAGS = ("sideband_error_or_timeout", "wrong_api_key_redirect", "no_app_mapping", "config_incomplete", "app_map_invalid")
FAIL_OPEN_PREFIXES = ("sideband_error_failopen_", "unexpected_status_")
ENFORCED_PREFIXES = ("action_enforced_status_", "custom_bot_block_status_", "redirect_issued_")
INFO_DIAGS = {"uzmcr_allow": "allow (Bot Manager mobile exception: uzmcr)", "multipart_headers_only": "allow (multipart body: headers-only inspection)"}


def _is_fail_open(diag: str) -> bool:
    return diag in FAIL_OPEN_DIAGS or diag.startswith(FAIL_OPEN_PREFIXES)


_DIAG_MEANING = {
    "sideband_error_or_timeout": "the inspection call failed or timed out",
    "sideband_error_failopen_5xx": "SecurePath answered with a server error",
    "wrong_api_key_redirect": "SecurePath did not recognise the Application ID / API key pair",
    "no_app_mapping": "no application map entry matched this request (Step 3d)",
    "config_incomplete": "the selected application has no Application ID, API key or endpoint (Step 3a / 3d)",
    "app_map_invalid": "rdwr-app-map or the generated map is not valid JSON (Step 3d)",
}


def load_trace(path: str) -> dict:
    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "traceEntries" not in data:
        raise RuntimeError(f"{path} is not an API Management trace (no traceEntries)")
    return data


def _trace_entries(trace: dict):
    te = trace.get("traceEntries") or {}
    for sec in ("inbound", "backend", "outbound", "onError", "on-error"):
        for e in te.get(sec) or []:
            data = e.get("data")
            text = data if isinstance(data, str) else (json.dumps(data) if data is not None else "")
            yield sec, (e.get("source") or ""), text, (data if isinstance(data, dict) else {})


def summarize_trace(trace: dict) -> dict:
    """One dict describing what happened to the request, read from the trace entries."""
    s = {"trace_id": trace.get("traceId"), "api": None, "operation": None,
         "connector_ran": False, "connector_form": None, "before_connector": [],
         "bypassed": False, "sideband_url": None, "sideband_error": None, "sideband_status": None,
         "verdict_status": None, "oop_request_status": None, "diag": None, "enforced": None, "note": None, "wrong_api_key": False,
         "oop_log": None, "response_log": None, "origin_status": None}
    seen = False
    for sec, src, text, data in _trace_entries(trace):
        if src == "api-inspector" and isinstance(data.get("configuration"), dict):
            cfg = data["configuration"]
            s["api"] = (cfg.get("api") or {}).get("from")
            op = cfg.get("operation") or {}
            if op.get("method") or op.get("uriTemplate"):
                s["operation"] = f"{op.get('method', '')} {op.get('uriTemplate', '')}".strip()
        if sec == "inbound":
            if not seen:
                if src == "include-fragment" and "Entering policy fragment 'securepath-inbound'" in text:
                    seen, s["connector_form"] = True, "fragments"
                elif src == "set-variable" and data.get("name") == "rdwrAppEpAddr":
                    seen, s["connector_form"] = True, "document"
                elif src in REQUEST_ENDING and src not in s["before_connector"]:
                    s["before_connector"].append(src)
                continue
            if src == "set-variable":
                n, v = data.get("name"), data.get("value")
                if n == "shouldBypassRadware" and v is True:
                    s["bypassed"] = True
                elif n == "rwStatus":
                    s["verdict_status"] = v
                elif n == "oopRequestStatusHeader":
                    s["oop_request_status"] = v
                elif n == "rdwrOopLog":
                    s["oop_log"] = v
                elif n == "radwareDiag" and v:
                    v = str(v)
                    if v.startswith(ENFORCED_PREFIXES):
                        s["enforced"] = v
                    elif v in INFO_DIAGS:
                        s["note"] = v
                    elif _is_fail_open(v):
                        s["diag"] = v
                    else:
                        s["diag"] = v  # unknown value: treat as a fail-open so it is never hidden
            elif src == "request-forwarder" and isinstance(data.get("request"), dict) and not s["sideband_url"]:
                s["sideband_url"] = data["request"].get("url")
            elif src == "send-request":
                m = _ERR_IGNORED_RE.search(text)
                if m:
                    s["sideband_url"] = s["sideband_url"] or m.group(1)
                    s["sideband_error"] = m.group(2).strip().rstrip(".")
                elif isinstance(data.get("response"), dict):
                    resp = data["response"]
                    s["sideband_status"] = (resp.get("status") or {}).get("code")
                    for h in resp.get("headers") or []:
                        if (h.get("name") or "").lower() == "location" and "wrong-api-key" in (h.get("value") or ""):
                            s["wrong_api_key"] = True
        elif sec == "backend" and src == "forward-request" and isinstance(data.get("response"), dict):
            s["origin_status"] = (data["response"].get("status") or {}).get("code")
        if src == "send-one-way-request" and "One way request was successfully send" in text:
            s["response_log"] = "sent"
    s["connector_ran"] = seen
    if s["diag"] == "wrong_api_key_redirect":
        s["wrong_api_key"] = True
    if s["response_log"] is None and seen:
        s["response_log"] = "not requested" if s["oop_log"] not in ("2", "3") else "not sent"
    return s


def lint_trace(trace: dict) -> List[Finding]:
    s = summarize_trace(trace)
    out: List[Finding] = []
    where = "trace"
    if not s["connector_ran"]:
        if s["before_connector"]:
            out.append(Finding("T01", where, None,
                               f"'{s['before_connector'][0]}' ran and the connector was never reached (API {s['api'] or '?'}, {s['operation'] or '?'}): "
                               "a policy ahead of the connector ended the request",
                               "move the connector's include lines directly after <base /> so it runs first (Step 4); "
                               "if the connector is not installed at all, install it at a scope that covers this API"))
        else:
            out.append(Finding("T01", where, None,
                               f"the connector did not run on this request (API {s['api'] or '?'}, {s['operation'] or '?'})",
                               "install the connector at a scope that covers this API (Step 4), make sure the API's own "
                               "inbound policy keeps <base /> (Step 2b), and confirm the request matched the API you expect"))
        return out
    for p in s["before_connector"]:
        out.append(Finding("T02", where, None,
                           f"'{p}' ran before the connector; every request it rejects is never inspected",
                           "move the connector's include lines directly after <base /> so it runs first (Step 4)"))
    host = _host_of(s["sideband_url"] or "")
    if host and not host.lower().endswith(OOP_SUFFIX):
        out.append(Finding("T03", where, None,
                           f"the inspection call went to '{host}', which is not a SecurePath inspection endpoint",
                           f"set rdwr-app-ep-addr (or the application-map entry) to <APP_ID>{OOP_SUFFIX} — the "
                           "'.v1.radwarecloud.net' hostname is the application's front-end address (Step 3a, Step 3c)"))
    err = s["sideband_error"] or ""
    if err:
        low = err.lower()
        if "certificate" in low:
            fix = ("establish trust for exactly this host (Step 1): CA certificates on Developer/Basic/Standard/"
                   "Premium (Path A), a backend entity with certificate validation disabled on Standard v2/Premium v2 "
                   "(Path B)")
            if host and not host.lower().endswith(OOP_SUFFIX):
                fix += "; fix T03 first — a backend entity created for the .oop host does not apply to this URL"
            out.append(Finding("T04", where, None,
                               f"the inspection call was rejected on TLS ({err}); the request was served uninspected", fix))
        elif "timed out" in low or "timeout" in low or "canceled" in low or "cancelled" in low:
            out.append(Finding("T04", where, None,
                               f"the inspection endpoint did not answer within rdwr-app-ep-timeout-seconds ({err})",
                               f"check that the gateway can reach {host or 'the endpoint'} on port 443 (VNet, NSG, "
                               "firewall, forced tunnelling) and that the hostname is right (Step 3c)"))
        elif "no such host" in low or "resolve" in low or "name resolution" in low or "nodename" in low:
            out.append(Finding("T04", where, None, f"the inspection endpoint hostname does not resolve ({err})",
                               "check rdwr-app-ep-addr for a typo (Step 3a, Step 3c)"))
        else:
            out.append(Finding("T04", where, None, f"the inspection call failed ({err}); the request was served uninspected",
                               "check the endpoint host, port and TLS settings (Step 1, Step 3a); contact Radware with this trace"))
    if s["wrong_api_key"]:
        out.append(Finding("T05", where, None,
                           "SecurePath redirected to wrong-api-key: the Application ID / API key pair is not recognised",
                           "compare rdwr-app-id and rdwr-api-key with the application in the Radware Cloud portal (Step 3a, 3c)"))
    vs = s["verdict_status"]
    if isinstance(vs, int) and vs >= 500:
        out.append(Finding("T06", where, None, f"SecurePath answered {vs}; the request was served uninspected",
                           "usually transient on the SecurePath side; if it persists, contact Radware support with this trace"))
    diag = s["diag"]
    if diag and not out:
        out.append(Finding("T07", where, None,
                           f"inspection did not complete: X-Rdwr-Diag = {diag} ({_DIAG_MEANING.get(diag, 'see the X-Rdwr-Diag table')})",
                           "see the X-Rdwr-Diag table in Step 5 (5c)"))
    return out


REDACT_HEADERS = {"authorization", "x-rdwr-api-key", "apim-debug-authorization", "ocp-apim-subscription-key",
                  "cookie", "set-cookie", "proxy-authorization"}


def redact_trace(trace: dict) -> int:
    """Replace, in place, the values of credential-carrying headers anywhere in the trace
    (the request's Authorization / subscription key / cookies, the debug token, and the
    SecurePath API key the connector sends). Returns the number of values replaced."""
    n = 0

    def walk(o):
        nonlocal n
        if isinstance(o, dict):
            if isinstance(o.get("name"), str) and o["name"].lower() in REDACT_HEADERS and "value" in o and o["value"] != "<redacted>":
                o["value"] = "<redacted>"; n += 1
            if isinstance(o.get("header"), dict):
                walk(o["header"])
            for k, v in o.items():
                if k in ("expression", "value", "message", "data") and isinstance(v, str):
                    continue
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(trace)
    # set-variable / set-header entries also echo the value as a string in "value"/"message"
    text_keys = ("value", "message")

    def scrub(o, parent_name=None):
        nonlocal n
        if isinstance(o, dict):
            name = o.get("name") if isinstance(o.get("name"), str) else parent_name
            for k in text_keys:
                if isinstance(o.get(k), str) and name and name.lower() in ("rdwrapikey", "x-rdwr-api-key") and o[k] != "<redacted>":
                    o[k] = "<redacted>"; n += 1
            for v in o.values():
                scrub(v, name)
        elif isinstance(o, list):
            for v in o:
                scrub(v, parent_name)
    scrub(trace)
    return n


def format_trace_summary(s: dict) -> str:
    call = "not made"
    if s["sideband_url"]:
        if s["sideband_error"]:
            call = f"{s['sideband_url']} -> FAILED: {s['sideband_error']}"
        else:
            st = s["sideband_status"]
            call = f"{s['sideband_url']} -> {st if st is not None else '?'}"
            if s["oop_request_status"]:
                call += f" ({s['oop_request_status']})"
    if not s["connector_ran"]:
        verdict = "-"
    elif s["diag"]:
        verdict = f"served uninspected (X-Rdwr-Diag = {s['diag']})"
    elif s["enforced"] and s["enforced"].startswith("custom_bot_block_status_"):
        verdict = f"block (custom Bot Manager status {s['verdict_status']} relayed to the client)"
    elif s["enforced"] and s["enforced"].startswith("redirect_issued_"):
        verdict = f"redirect ({s['verdict_status']} from SecurePath)"
    elif s["note"]:
        verdict = INFO_DIAGS[s["note"]]
    elif s["verdict_status"] == 200 and s["oop_request_status"] == "allowed":
        verdict = "allow"
    elif s["verdict_status"] in (403,):
        verdict = "block (403 from SecurePath)"
    elif s["verdict_status"] in (301, 302):
        verdict = f"redirect ({s['verdict_status']})"
    elif s["verdict_status"] == 200:
        verdict = "block (SecurePath 200 without an allow marker)"
    elif s["bypassed"]:
        verdict = "not inspected: a bypass rule matched (static extension, excluded method or inline trusted source) — expected for such requests"
    else:
        verdict = "-"
    lines = [
        "Trace summary",
        f"  trace file id:          {s['trace_id'] or '-'}",
        f"  API / operation:        {s['api'] or '-'} / {s['operation'] or '-'}",
        f"  connector ran:          {'yes (' + s['connector_form'] + ')' if s['connector_ran'] else 'NO'}",
        f"  policies before it:     {', '.join(s['before_connector']) if s['before_connector'] else 'none'}",
        f"  inspection call:        {call}",
        f"  verdict:                {verdict}",
        f"  response-phase log:     {s['response_log'] or '-'}",
        f"  origin answered:        {s['origin_status'] if s['origin_status'] is not None else '-'}",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Lint a SecurePath connector install on Azure API Management")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--file", help="policy document to check")
    mode.add_argument("--live", action="store_true", help="read every policy on a live instance")
    mode.add_argument("--trace", help="an API Management trace (JSON from listTrace) to read")
    mode.add_argument("--redact", help="replace credentials inside this trace file (in place) so it can be shared")
    ap.add_argument("--scope", choices=["global", "product", "api"], default="api", help="scope of --file")
    ap.add_argument("--label", default=None, help="label for --file findings")
    ap.add_argument("-g", "--resource-group")
    ap.add_argument("-n", "--apim")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    summary = None
    try:
        if a.redact:
            trace = load_trace(a.redact)
            n = redact_trace(trace)
            with open(a.redact, "w", encoding="utf-8") as f:
                json.dump(trace, f, indent=1)
            print(f"{a.redact}: {n} credential value(s) replaced with <redacted>")
            return 0
        if a.trace:
            trace = load_trace(a.trace)
            summary = summarize_trace(trace)
            findings = lint_trace(trace)
        elif a.file:
            with open(a.file, encoding="utf-8-sig") as f:
                text = f.read()
            findings = lint_document(text, a.scope, a.label or a.file)
            if not document_has_connector(text):
                findings.insert(0, Finding(
                    "L01", a.label or a.file, None, "no SecurePath connector in this document",
                    "add the four include-fragment lines (securepath-app-map, securepath-inbound, securepath-outbound, securepath-onerror) after <base /> (README Step 4, Form 2)"))
        else:
            if not (a.resource_group and a.apim):
                ap.error("--live needs -g RESOURCE_GROUP and -n APIM")
            findings = lint_instance(AzReader(a.resource_group, a.apim))
    except (OSError, RuntimeError, ValueError) as e:
        print(f"could not read: {e}", file=sys.stderr)
        return 2
    if a.json:
        payload = [f.__dict__ for f in findings]
        print(json.dumps({"summary": summary, "findings": payload} if summary else payload, indent=2))
    else:
        if summary:
            print(format_trace_summary(summary))
            print()
        for f in findings:
            print(f)
        print("clean" if not findings else f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
