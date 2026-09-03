#!/usr/bin/env python3
"""Radware SecurePath connector for Azure API Management: install lint.

Checks a policy document (--file) or a live instance (--live) for the ways an
install can be silently ineffective: the connector missing or installed twice,
an API policy without <base /> skipping a global connector, a request-ending
policy placed ahead of the connector, an empty set-variable left by a manual
merge, an incomplete fragment set, missing or malformed Named Values, an invalid
application map, and a missing backend entity on v2 tiers.

Text-based on purpose: API Management policy documents are not well-formed
XML (Named Value references and C# expressions sit inside attribute values).

Exit codes: 0 clean, 1 findings, 2 could not read.
"""
import argparse
import json
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
    "rdwr-app-map", "rdwr-true-host-header")
NEW_IN_140 = {"rdwr-app-map", "rdwr-true-host-header"}
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

def split_sections(text: str) -> Dict[str, Tuple[int, List[str]]]:
    """Section name -> (1-based line of its opening tag, the lines inside it)."""
    lines = text.splitlines()
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
    for i, ln in enumerate(text.splitlines(), start=1):
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
        return [a["name"] for a in self._get("/apis").get("value", [])]

    def api_policy(self, api_id):
        return self._policy(f"/apis/{api_id}")

    def products(self):
        return [p["name"] for p in self._get("/products").get("value", [])]

    def product_policy(self, product_id):
        return self._policy(f"/products/{product_id}")

    def named_values(self):
        out: Dict[str, Optional[str]] = {}
        for nv in self._get("/namedValues").get("value", []):
            name, props = nv["name"], nv.get("properties") or {}
            if props.get("secret"):
                raw = self._az(["rest", "--method", "POST", "--uri",
                                f"{self.base}/namedValues/{name}/listValue?api-version={API_VERSION}"])
                out[name] = self._parse(raw).get("value")
            else:
                out[name] = props.get("value")
        return out

    def backends(self):
        return [(b.get("properties") or {}).get("url", "")
                for b in self._get("/backends").get("value", [])]


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
        for f in lint_document(text, scope, label):
            if f.code == "L03" and not global_has:
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
    app_map_raw = nvs.get("rdwr-app-map")
    if app_map_raw is not None and app_map_raw.strip().lower() not in DISABLE_TOKENS:
        try:
            app_map = parse_app_map(app_map_raw)
            if not isinstance(app_map, dict):
                raise ValueError("top level must be an object")
            for key, entry in app_map.items():
                for field in ("app_id", "api_key", "endpoint"):
                    if not isinstance(entry, dict) or not entry.get(field):
                        findings.append(Finding("L10", "named-values", None, f"rdwr-app-map entry '{key}' lacks '{field}'",
                                                "each entry needs app_id, api_key and endpoint"))
                if isinstance(entry, dict):
                    bp = entry.get("base_path")
                    if bp is not None and not str(bp).startswith("/"):
                        findings.append(Finding("L10", "named-values", None, f"rdwr-app-map entry '{key}' base_path '{bp}' must start with /",
                                                "use the API's path prefix, for example /orders"))
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
    return findings


# ---------------------------------------------------------------- CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Lint a SecurePath connector install on Azure API Management")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--file", help="policy document to check")
    mode.add_argument("--live", action="store_true", help="read every policy on a live instance")
    ap.add_argument("--scope", choices=["global", "product", "api"], default="api", help="scope of --file")
    ap.add_argument("--label", default=None, help="label for --file findings")
    ap.add_argument("-g", "--resource-group")
    ap.add_argument("-n", "--apim")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.file:
            with open(a.file, encoding="utf-8-sig") as f:
                text = f.read()
            findings = lint_document(text, a.scope, a.label or a.file)
            if not document_has_connector(text):
                findings.insert(0, Finding(
                    "L01", a.label or a.file, None, "no SecurePath connector in this document",
                    "add the three include-fragment lines after <base /> (README Step 4)"))
        else:
            if not (a.resource_group and a.apim):
                ap.error("--live needs -g RESOURCE_GROUP and -n APIM")
            findings = lint_instance(AzReader(a.resource_group, a.apim))
    except (OSError, RuntimeError) as e:
        print(f"could not read: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        for f in findings:
            print(f)
        print("clean" if not findings else f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
