#!/usr/bin/env python3
"""Radware SecurePath connector for Azure API Management: application sync.

Keeps the connector's generated application map in step with the SecurePath
applications of your Radware Cloud account: the policy fragment
securepath-app-map (hostname, application id, inspection endpoint per
application), one secret Named Value per API key (rdwr-app-key-<id>) that the
fragment references, and, on Standard v2 / Premium v2, the backend entities for
the inspection endpoints. The hand-written rdwr-app-map Named Value is never
touched and takes precedence in the policy.

    plan    read the account, compare with the instance, print what would change
    apply   write the changes (map entries added or updated, backends created);
            --prune also removes map entries whose application is gone
    check   exit 1 when the instance differs from the account (for a scheduler)
    export  write the map as a Bicep parameter file for deploy/securepath-apim.bicep

    python3 tools/securepath-apim-sync.py plan  -g RG -n APIM --cloud-api-key KEY --cloud-context CTX
    python3 tools/securepath-apim-sync.py apply -g RG -n APIM --cloud-api-key KEY --cloud-context CTX [--prune]
    python3 tools/securepath-apim-sync.py check -g RG -n APIM --cloud-api-key KEY --cloud-context CTX
    python3 tools/securepath-apim-sync.py export --cloud-api-key KEY --cloud-context CTX --out appmap.parameters.json

--from-file apps.json reads the application list from a file (the JSON the Radware Cloud API
returns for /v1/gms/applications) instead of calling the API. Applications are keyed by their
domain (and by the API Protection hostname when one is set). Run it from any machine or
scheduler with the Azure CLI logged in; the same command run again only changes what differs.

Exit codes: 0 done / in sync, 1 drift (check) or nothing to write, 2 failure.
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("securepath_apim_lint", os.path.join(HERE, "securepath-apim-lint.py"))
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)

API_VERSION = lint.API_VERSION
CLOUD_API_BASE = "https://api.radwarecloud.app"
USER_AGENT = "SecurePath-APIM-connector/1.4.0"
FIELDS = ("app_id", "api_key", "endpoint", "port", "ssl")


# ---------------------------------------------------------------- Radware Cloud

def fetch_cloud_apps(api_key: str, context: str, timeout: float = 20.0):
    """GET /v1/gms/applications (every page). Raises RuntimeError on failure."""
    apps, page = [], 0
    while True:
        req = urllib.request.Request(f"{CLOUD_API_BASE}/v1/gms/applications?page={page}&size=200", method="GET",
                                     headers={"x-api-key": api_key, "context": context,
                                              "Accept": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Radware Cloud API answered HTTP {e.code} (check the API key and the context)") from e
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"Radware Cloud API unreachable: {e}") from e
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            raise RuntimeError("unexpected response shape from the Radware Cloud API")
        apps += data.get("content") or data.get("applications") or []
        total_pages = int(data.get("totalPages") or 1)
        page += 1
        if page >= total_pages:
            return apps


def project_cloud_apps(apps) -> dict:
    """Account applications -> {host: entry} for OUT_OF_PATH applications in PROTECTING state."""
    if isinstance(apps, dict):
        apps = apps.get("content") or apps.get("applications") or []
    out = {}
    for a in apps or []:
        if not isinstance(a, dict):
            continue
        if a.get("applicationAssetType") != "OUT_OF_PATH" or a.get("deploymentStatus") != "PROTECTING":
            continue
        waf = ((a.get("featuresData") or {}).get("wafFeatureData")) or {}
        domain = (((waf.get("mainDomain") or {}).get("mainDomain")) or "").strip().lower()
        cname = ""
        for rec in ((waf.get("oopDns") or {}).get("dnsRecords")) or []:
            if rec.get("type") == "CNAME" and rec.get("value"):
                cname = str(rec["value"]).strip().lower()
                break
        app_id, key = a.get("id") or "", a.get("oopApiKey") or ""
        if not (app_id and key and domain and cname):
            continue
        entry = {"app_id": app_id, "api_key": key, "endpoint": cname, "port": 443, "ssl": True}
        out[domain] = entry
        hn = ((a.get("apiProtection") or {}).get("hostname")) or {}
        if hn and not hn.get("useDefault", True) and hn.get("hostname"):
            out[str(hn["hostname"]).strip().lower()] = dict(entry)
    return out


# ---------------------------------------------------------------- map rendering and diff

FRAGMENT_ID = "securepath-app-map"
KEY_NV_PREFIX = "rdwr-app-key-"


def key_nv_name(app_id: str) -> str:
    """Secret Named Value that holds one application's API key (stable per application)."""
    return KEY_NV_PREFIX + "".join(ch for ch in app_id.lower() if ch.isalnum())[:64]


def render_fragment(app_map: dict) -> str:
    """The generated fragment: single-quoted JSON with each api_key replaced by a reference to
    its secret Named Value, so the fragment text never carries a key."""
    public = {}
    for host, e in app_map.items():
        entry = {k: v for k, v in e.items() if k != "api_key"}
        entry["api_key"] = "{{" + key_nv_name(e["app_id"]) + "}}"
        public[host] = entry
    body = render_map(public)
    return ("<fragment>\n"
            "    <!-- Generated by tools/securepath-apim-sync.py; do not edit by hand. Hand-written entries\n"
            "         belong in the rdwr-app-map Named Value, which takes precedence. -->\n"
            f"    <set-variable name=\"rdwrAppMapGenerated\" value=\"{body}\" />\n"
            "</fragment>\n")


def parse_fragment(text: str) -> dict:
    """The map inside a generated fragment (api_key values are the {{...}} references)."""
    import re
    m = re.search(r'name="rdwrAppMapGenerated" value="(.*?)" />', text or "", re.S)
    if not m:
        return {}
    raw = m.group(1).strip()
    if raw.lower() in lint.DISABLE_TOKENS:
        return {}
    parsed = lint.parse_app_map(raw)
    return parsed if isinstance(parsed, dict) else {}

def render_map(app_map: dict) -> str:
    """Single-quoted JSON, the only form a Named Value can carry."""
    text = json.dumps(app_map, separators=(", ", ": "), sort_keys=True)
    for ch in ("'", "&", "<"):
        if ch in text:
            raise ValueError(f"application map contains {ch!r}, which cannot be stored in a Named Value")
    return text.replace('"', "'")


def diff_maps(current: dict, desired: dict, current_keys: dict = None):
    """Compare the generated map on the instance with the account. Returns (added, changed,
    removed, unchanged) as dicts of key -> entry (changed: key -> (old, new)). current_keys maps
    key Named Value name -> value on the instance (None = unreadable); when given, a changed API
    key is detected through it. Keys that do not look like hostnames are never reported removed."""
    added, changed, removed, unchanged = {}, {}, {}, {}
    for k, e in desired.items():
        cur = current.get(k)
        if cur is None:
            added[k] = e
            continue
        differs = any(str(cur.get(f, "")) != str(e.get(f, "")) for f in ("app_id", "endpoint"))
        if not differs:
            if current_keys is not None:
                differs = current_keys.get(key_nv_name(e["app_id"])) != e["api_key"]
            elif str(cur.get("api_key", "")) not in ("{{" + key_nv_name(e["app_id"]) + "}}", e["api_key"]):
                differs = True
        if differs:
            changed[k] = (cur, e)
        else:
            unchanged[k] = cur
    for k, e in current.items():
        if k not in desired and "." in k:
            removed[k] = e
    return added, changed, removed, unchanged


def merge(current: dict, desired: dict, prune: bool) -> dict:
    out = {k: dict(v) for k, v in current.items()}
    for k, e in desired.items():
        merged = dict(out.get(k, {}))
        merged.update({f: e[f] for f in FIELDS if f in e})
        out[k] = merged
    for k, e in out.items():
        # entries read back from the fragment carry the reference; keep it renderable
        if str(e.get("api_key", "")).startswith("{{") and k in desired:
            e["api_key"] = desired[k]["api_key"]
    if prune:
        for k in list(out):
            if k not in desired and "." in k:
                del out[k]
    return out


# ---------------------------------------------------------------- Azure

class AzWriter:
    """az rest wrapper; injectable in tests."""

    def __init__(self, rg: str, apim: str, run=None):
        self.run = run or self._run
        sub = self.run(["account", "show", "--query", "id", "-o", "tsv"]).strip()
        if not sub:
            raise RuntimeError("az account show returned nothing; run az login")
        self.base = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
                     f"/providers/Microsoft.ApiManagement/service/{apim}")

    @staticmethod
    def _run(args):
        p = subprocess.run(["az"] + args, capture_output=True, text=True)
        if p.returncode != 0:
            if "404" in p.stderr or "NotFound" in p.stderr:
                return ""
            raise RuntimeError(p.stderr.strip() or f"az {' '.join(args)} failed")
        return p.stdout

    def get(self, path):
        raw = self.run(["rest", "--method", "GET", "--uri", f"{self.base}{path}?api-version={API_VERSION}", "-o", "json"])
        return json.loads(raw.lstrip("﻿")) if raw.strip() else {}

    def post(self, path):
        raw = self.run(["rest", "--method", "POST", "--uri", f"{self.base}{path}?api-version={API_VERSION}", "-o", "json"])
        return json.loads(raw.lstrip("﻿")) if raw.strip() else {}

    def put(self, path, body):
        self.run(["rest", "--method", "PUT", "--uri", f"{self.base}{path}?api-version={API_VERSION}",
                  "--headers", "Content-Type=application/json", "--body", json.dumps(body), "-o", "none"])

    def sku(self):
        return (self.get("").get("sku") or {}).get("name", "")

    def current_map(self) -> dict:
        """The generated map on the instance (from the securepath-app-map fragment)."""
        raw = self.run(["rest", "--method", "GET", "--uri",
                        f"{self.base}/policyFragments/{FRAGMENT_ID}?api-version={API_VERSION}&format=rawxml", "-o", "json"])
        raw = (raw or "").lstrip("\ufeff").strip()
        if not raw:
            return {}
        text = raw if raw.startswith("<") else (json.loads(raw).get("properties") or {}).get("value", "")
        try:
            return parse_fragment(text)
        except ValueError:
            raise RuntimeError(f"the {FRAGMENT_ID} fragment on the instance is not a generated map; re-register the default fragment first")

    def current_keys(self) -> dict:
        """Key Named Values on the instance: name -> secret value."""
        out = {}
        for nv in self.get("/namedValues").get("value", []):
            name = nv["name"]
            if not name.startswith(KEY_NV_PREFIX):
                continue
            raw = self.run(["rest", "--method", "POST", "--uri",
                            f"{self.base}/namedValues/{name}/listValue?api-version={API_VERSION}", "-o", "json"])
            out[name] = (json.loads(raw.lstrip("\ufeff")).get("value") if raw.strip() else None)
        return out

    def write_key(self, name, value):
        self.put(f"/namedValues/{name}", {"properties": {"displayName": name, "value": value, "secret": True}})

    def delete_key(self, name):
        self.run(["rest", "--method", "DELETE", "--uri", f"{self.base}/namedValues/{name}?api-version={API_VERSION}",
                  "--headers", "If-Match=*", "-o", "none"])

    def write_fragment(self, text):
        self.put(f"/policyFragments/{FRAGMENT_ID}", {"properties": {"format": "rawxml", "value": text,
                                                                     "description": "Radware SecurePath generated application map (written by tools/securepath-apim-sync.py)"}})

    def backend_hosts(self):
        out = {}
        for b in self.get("/backends").get("value", []):
            out[lint._host_of((b.get("properties") or {}).get("url", ""))] = b["name"]
        return out

    def create_backend(self, name, host):
        self.put(f"/backends/{name}", {"properties": {
            "url": f"https://{host}", "protocol": "http", "title": "SecurePath inspection endpoint",
            "tls": {"validateCertificateChain": False, "validateCertificateName": False}}})


# ---------------------------------------------------------------- commands

def plan(writer, desired, log=print):
    current = writer.current_map()
    keys = writer.current_keys()
    added, changed, removed, unchanged = diff_maps(current, desired, keys)
    log(f"{'action':<10}{'host':<36}{'application id':<40}endpoint")
    for k, e in sorted(added.items()):
        log(f"{'add':<10}{k:<36}{e['app_id']:<40}{e['endpoint']}")
    for k, (old, new) in sorted(changed.items()):
        log(f"{'update':<10}{k:<36}{new['app_id']:<40}{new['endpoint']}")
    for k, e in sorted(removed.items()):
        log(f"{'gone':<10}{k:<36}{e.get('app_id', ''):<40}{e.get('endpoint', '')}  (kept unless --prune)")
    for k, e in sorted(unchanged.items()):
        log(f"{'unchanged':<10}{k:<36}{e.get('app_id', ''):<40}{e.get('endpoint', '')}")
    missing_backends = []
    if writer.sku().lower().endswith("v2"):
        existing = writer.backend_hosts()
        for e in desired.values():
            if e["endpoint"] not in existing and e["endpoint"] not in missing_backends:
                missing_backends.append(e["endpoint"])
        for h in missing_backends:
            log(f"{'backend':<10}{h}  (will be created)")
    return current, keys, added, changed, removed, missing_backends


def apply(writer, desired, prune=False, log=print):
    current, keys, added, changed, removed, missing_backends = plan(writer, desired, log)
    if not (added or changed or missing_backends or (prune and removed)):
        log("in sync: nothing to write")
        return 0
    merged = merge(current, desired, prune)
    if added or changed or (prune and removed):
        # keys first (the fragment references them), then the fragment
        wanted = {key_nv_name(e["app_id"]): e["api_key"] for e in desired.values()}
        n_keys = 0
        for name, value in wanted.items():
            if keys.get(name) != value:
                writer.write_key(name, value)
                n_keys += 1
        writer.write_fragment(render_fragment(merged))
        log(f"{FRAGMENT_ID} written: {len(added)} added, {len(changed)} updated, {len(removed) if prune else 0} removed, {len(merged)} entries; {n_keys} key Named Value(s) written")
        if prune:
            still = {key_nv_name(e["app_id"]) for e in merged.values() if e.get("app_id")}
            for name in list(keys):
                if name not in still and name not in wanted:
                    writer.delete_key(name)
                    log(f"key Named Value removed: {name}")
    if missing_backends:
        existing = writer.backend_hosts()
        n = len(existing)
        for h in missing_backends:
            n += 1
            name = f"securepath-sideband-{n}"
            writer.create_backend(name, h)
            log(f"backend created: {name} -> https://{h}")
    return 0


def check(writer, desired, log=print):
    current, keys, added, changed, removed, missing_backends = plan(writer, desired, log)
    drift = bool(added or changed or removed or missing_backends)
    log("drift: yes" if drift else "in sync")
    return 1 if drift else 0


def export_parameters(desired, out_path, log=print):
    body = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {"appMap": {"value": desired}}}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(body, f, indent=2)
    log(f"wrote {out_path} ({len(desired)} entries); pass it with --parameters @{os.path.basename(out_path)} together with apimName, appId, apiKey and endpoint")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Keep the SecurePath application map in step with your Radware Cloud account")
    ap.add_argument("command", choices=["plan", "apply", "check", "export"])
    ap.add_argument("-g", "--resource-group")
    ap.add_argument("-n", "--apim")
    ap.add_argument("--cloud-api-key", help="Radware Cloud portal API key")
    ap.add_argument("--cloud-context", help="Application Protection ID (context header)")
    ap.add_argument("--from-file", help="read the application list from this JSON file instead of the Radware Cloud API")
    ap.add_argument("--prune", action="store_true", help="apply: remove map entries whose application is gone from the account")
    ap.add_argument("--include-provisioning", action="store_true", help="also include applications still provisioning")
    ap.add_argument("--out", default="securepath-appmap.parameters.json", help="export: parameter file to write")
    a = ap.parse_args(argv)
    try:
        if a.from_file:
            with open(a.from_file, encoding="utf-8") as f:
                raw = json.load(f)
        elif a.cloud_api_key and a.cloud_context:
            raw = fetch_cloud_apps(a.cloud_api_key, a.cloud_context)
        else:
            ap.error("give --cloud-api-key and --cloud-context, or --from-file")
        if a.include_provisioning:
            for app in raw:
                if isinstance(app, dict) and app.get("deploymentStatus") == "PROVISIONING":
                    app["deploymentStatus"] = "PROTECTING"
        desired = project_cloud_apps(raw)
        if not desired:
            print("no SecurePath application in PROTECTING state was returned for this key and context", file=sys.stderr)
            return 1
        if a.command == "export":
            return export_parameters(desired, a.out)
        if not (a.resource_group and a.apim):
            ap.error(f"{a.command} needs -g RESOURCE_GROUP and -n APIM")
        writer = AzWriter(a.resource_group, a.apim)
        if a.command == "plan":
            plan(writer, desired)
            return 0
        if a.command == "apply":
            return apply(writer, desired, a.prune)
        return check(writer, desired)
    except (RuntimeError, ValueError, OSError) as e:
        print(f"failed: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
