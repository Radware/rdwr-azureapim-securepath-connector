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
    render  write what apply would do as a reviewable change bundle (CHANGES.md, apply.sh,
            the fragment, the backend bodies, app-keys.env) and send nothing to Azure;
            --offline does not read the instance at all

    python3 tools/securepath-apim-sync.py plan   -g RG -n APIM --cloud-context CTX
    python3 tools/securepath-apim-sync.py apply  -g RG -n APIM --cloud-context CTX [--prune]
    python3 tools/securepath-apim-sync.py check  -g RG -n APIM --cloud-context CTX
    python3 tools/securepath-apim-sync.py export --cloud-context CTX --out appmap.parameters.json
    python3 tools/securepath-apim-sync.py render -g RG -n APIM --cloud-context CTX --out-dir bundle [--offline] [--prune]

The Radware Cloud portal API key is read from the RDWR_CLOUD_API_KEY environment variable,
from --cloud-api-key-file PATH, or from --cloud-api-key KEY (visible in shell history and
process listings: prefer the first two). The context can also come from RDWR_CLOUD_CONTEXT.

--from-file apps.json reads the application list from a file (the JSON the Radware Cloud API
returns for /v1/gms/applications) instead of calling the API. Applications are keyed by their
domain (and by the API Protection hostname when one is set). Run it from any machine or
scheduler with the Azure CLI logged in; the same command run again only changes what differs.

Exit codes: 0 done / in sync / bundle written, 1 drift (check) or no application in
PROTECTING state was returned, 2 failure.
"""
import argparse
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("securepath_apim_lint", os.path.join(HERE, "securepath-apim-lint.py"))
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)

API_VERSION = lint.API_VERSION
CLOUD_API_BASE = "https://api.radwarecloud.app"
USER_AGENT = "SecurePath-APIM-connector/1.5.0"
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
                have = current_keys.get(key_nv_name(e["app_id"]))
                differs = have is not None and have != e["api_key"]
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
        # the body may carry an API key: it goes through a mode-600 file, never the command line
        fd, tmp = tempfile.mkstemp(prefix="securepath-apim-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(body, f)
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            self.run(["rest", "--method", "PUT", "--uri", f"{self.base}{path}?api-version={API_VERSION}",
                      "--headers", "Content-Type=application/json", "--body", f"@{tmp}", "-o", "none"])
        finally:
            os.unlink(tmp)

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
        self.put(f"/backends/{name}", backend_body(host))

    def backend_name(self, n, host):
        # never a name that already exists: a PUT on it would overwrite another endpoint's backend
        taken = set(self.backend_hosts().values())
        while f"securepath-sideband-{n}" in taken:
            n += 1
        return f"securepath-sideband-{n}"

    def current_fragment_text(self) -> str:
        raw = self.run(["rest", "--method", "GET", "--uri",
                        f"{self.base}/policyFragments/{FRAGMENT_ID}?api-version={API_VERSION}&format=rawxml", "-o", "json"])
        raw = (raw or "").lstrip("\ufeff").strip()
        if not raw:
            return ""
        return raw if raw.startswith("<") else (json.loads(raw).get("properties") or {}).get("value", "")


def backend_body(host: str) -> dict:
    return {"properties": {
        "url": f"https://{host}", "protocol": "http", "title": "SecurePath inspection endpoint",
        "tls": {"validateCertificateChain": False, "validateCertificateName": False}}}


def _v2(sku) -> bool:
    """Backend entities are the trust mechanism on the v2 tiers; None = tier unknown (offline), assume yes."""
    return sku is None or str(sku).lower().endswith("v2")


class OfflineReader:
    """No Azure access: nothing is known about the instance, so a bundle rendered through it
    carries the whole desired state (every key, the full fragment, every backend)."""

    def sku(self):
        return None

    def current_map(self):
        return {}

    def current_keys(self):
        return {}

    def backend_hosts(self):
        return {}

    def current_fragment_text(self):
        return ""

    @staticmethod
    def backend_name(n, host):
        # not numbered: numbering needs the instance, and a clash would overwrite someone else's backend
        return "securepath-sideband-" + "".join(ch for ch in host.split(".")[0].lower() if ch.isalnum())[:16]


class RecordingWriter:
    """Records the writes apply() would perform, in order, instead of performing them. Reads go to
    the reader (an AzWriter for a difference against the instance, an OfflineReader for the whole
    desired state). What render writes into a bundle is therefore exactly what apply would do."""

    def __init__(self, reader):
        self.reader = reader
        self.ops = []

    def sku(self):
        return self.reader.sku()

    def current_map(self):
        return self.reader.current_map()

    def current_keys(self):
        return self.reader.current_keys()

    def backend_hosts(self):
        return self.reader.backend_hosts()

    def current_fragment_text(self):
        return self.reader.current_fragment_text()

    def backend_name(self, n, host):
        return self.reader.backend_name(n, host)

    def write_key(self, name, value):
        self.ops.append(("key", name, value))

    def delete_key(self, name):
        self.ops.append(("delete_key", name, None))

    def write_fragment(self, text):
        self.ops.append(("fragment", FRAGMENT_ID, text))

    def create_backend(self, name, host):
        self.ops.append(("backend", name, host))


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
    if _v2(writer.sku()):
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
            name = writer.backend_name(n, h)
            writer.create_backend(name, h)
            log(f"backend created: {name} -> https://{h}")
    return 0


def _env_name(nv_name: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in nv_name.upper())


def render_bundle(ops, plan_lines, out_dir, rg, apim, offline, prune, source, previous_fragment="", log=print):
    """Write a reviewable change bundle: CHANGES.md, apply.sh, the fragment, the key file, the
    backend bodies. Nothing is sent to Azure. Returns the list of files written."""
    import datetime
    import stat
    os.makedirs(out_dir, exist_ok=True)
    keys = [(n, v) for op, n, v in ops if op == "key"]
    deletes = [n for op, n, _ in ops if op == "delete_key"]
    fragments = [t for op, _, t in ops if op == "fragment"]
    backends = [(n, h) for op, n, h in ops if op == "backend"]
    written = []

    def emit(name, text, secret=False):
        path = os.path.join(out_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if secret:
            f = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8", newline="\n")
        else:
            f = open(path, "w", encoding="utf-8", newline="\n")
        with f:
            f.write(text)
        written.append(name)

    if fragments:
        emit("securepath-app-map.fragment.xml", fragments[-1])
    if previous_fragment and ops:
        emit("previous/securepath-app-map.fragment.xml", previous_fragment)
    if keys:
        emit("app-keys.env", "# SecurePath API keys, one per key Named Value. Secret: keep this file out of tickets and\n"
             "# version control; delete it after apply.sh has run.\n"
             + "".join(f"{_env_name(n)}='{v}'\n" for n, v in keys), secret=True)
    for n, h in backends:
        emit(f"backends/{n}.json", json.dumps(backend_body(h), indent=2) + "\n")

    when = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    mode = ("full desired state — the instance was not read, so every entry, key and backend is included "
            "and the generated map is replaced as a whole" if offline else
            "difference against the instance — only what differs is written; the generated map is "
            "replaced with the merged result")
    if ops:
        sh = [
            "#!/usr/bin/env bash",
            f"# SecurePath application map — apply bundle for {apim} ({rg}), generated {when} by",
            "# tools/securepath-apim-sync.py render. Review CHANGES.md first. Running it twice is safe: every write",
            "# is a PUT and removals tolerate an already-removed value. Needs: az logged in as API Management Service Contributor on the",
            "# instance, python3. Run from any directory: bash apply.sh",
            "set -e",
            f'RG="{rg}"',
            f'APIM="{apim}"',
            'DIR="$(cd "$(dirname "$0")" && pwd)"',
            'SUB=$(az account show --query id -o tsv)',
            '[ -n "$SUB" ] || { echo "az is not logged in: run az login" >&2; exit 2; }',
            'BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM"',
            f'V="api-version={API_VERSION}"',
            "",
        ]
        step = 1
        if keys:
            sh += [f"# {step}. {len(keys)} secret Named Value(s) holding API keys. The values come from app-keys.env, never from",
                   "#    this file, and reach az through a private temporary file, never the command line.",
                   'if [ -f "$DIR/app-keys.env" ]; then',
                   '  . "$DIR/app-keys.env"',
                   '  umask 077; TMP=$(mktemp -d); trap \'rm -rf "$TMP"\' EXIT']
            for n, _ in keys:
                sh.append(f'  KEY_NAME="{n}" KEY_VALUE="${_env_name(n)}" python3 -c \'import json,os;print(json.dumps({{"properties":{{"displayName":os.environ["KEY_NAME"],"value":os.environ["KEY_VALUE"],"secret":True}}}}))\' > "$TMP/{n}.json"')
                sh.append(f'  az rest --method PUT --uri "$BASE/namedValues/{n}?$V" --headers "Content-Type=application/json" --body @"$TMP/{n}.json" -o none')
                sh.append(f'  echo "named value written: {n}"')
            sh += ['else', '  echo "app-keys.env not found: skipping the key Named Values (already applied and the file deleted?)"', 'fi', ""]
            step += 1
        if fragments:
            sh += [f"# {step}. the generated application map fragment (replaces the current generated map; hand-written",
                   "#    entries live in the rdwr-app-map Named Value and are not touched)",
                   'python3 -c \'import json,sys;print(json.dumps({"properties":{"format":"rawxml","value":open(sys.argv[1],encoding="utf-8").read(),"description":"Radware SecurePath generated application map (written by tools/securepath-apim-sync.py)"}}))\' "$DIR/securepath-app-map.fragment.xml" > "$DIR/fragment-body.json"',
                   f'az rest --method PUT --uri "$BASE/policyFragments/{FRAGMENT_ID}?$V" --headers "Content-Type=application/json" --body @"$DIR/fragment-body.json" -o none',
                   f'echo "fragment written: {FRAGMENT_ID}"', ""]
            step += 1
        if backends:
            sh += [f"# {step}. {len(backends)} backend entit{'y' if len(backends) == 1 else 'ies'}: TLS trust for each inspection endpoint on Standard v2 / Premium v2.",
                   "#    Other tiers use CA certificates (README Step 1, Path A) and skip this step.",
                   'SKU=$(az apim show -g "$RG" -n "$APIM" --query sku.name -o tsv)',
                   'case "$SKU" in',
                   "  *V2|*v2)"]
            for n, h in backends:
                sh.append(f'    az rest --method PUT --uri "$BASE/backends/{n}?$V" --headers "Content-Type=application/json" --body @"$DIR/backends/{n}.json" -o none')
                sh.append(f'    echo "backend written: {n} -> https://{h}"')
            sh += ["    ;;", '  *) echo "tier $SKU: backend entities not needed (CA certificates, Step 1 Path A)" ;;', "esac", ""]
            step += 1
        if deletes:
            sh += [f"# {step}. {len(deletes)} key Named Value(s) whose application is gone (--prune); already-removed ones are skipped"]
            for n in deletes:
                sh.append(f'az rest --method DELETE --uri "$BASE/namedValues/{n}?$V" --headers "If-Match=*" -o none 2>/dev/null && echo "named value removed: {n}" || echo "named value already removed: {n}"')
            sh.append("")
        sh += ["echo \"done. Verify: python3 tools/securepath-apim-sync.py check -g '$RG' -n '$APIM' --cloud-api-key ... --cloud-context ...\"", ""]
        emit("apply.sh", "\n".join(sh))
        os.chmod(os.path.join(out_dir, "apply.sh"), 0o755)

    md = [f"# SecurePath application map — change bundle for `{apim}`", "",
          f"Generated {when} by `tools/securepath-apim-sync.py render`. Nothing has been sent to Azure.", "",
          f"- **Target:** API Management instance `{apim}`, resource group `{rg}`",
          f"- **Source:** {source}",
          f"- **Mode:** {mode}",
          f"- **Prune:** {'yes — entries whose application is gone are removed' if prune else 'no — entries whose application is gone are kept'}",
          "", "## Planned changes", "", "```"] + plan_lines + ["```", ""]
    if not ops:
        md += ["**In sync: nothing to write.** No `apply.sh` was generated.", ""]
    else:
        md += ["## What `apply.sh` does, in order", ""]
        step = 1
        if keys:
            md.append(f"{step}. Writes {len(keys)} secret Named Value(s), one per application API key, values read from `app-keys.env`: "
                      + ", ".join(f"`{n}`" for n, _ in keys)); step += 1
        if fragments:
            entries = len(parse_fragment(fragments[-1]))
            md.append(f"{step}. Replaces the generated map fragment `{FRAGMENT_ID}` with `securepath-app-map.fragment.xml` "
                      f"({entries} entr{'y' if entries == 1 else 'ies'}; API keys appear only as `{{{{named-value}}}}` references). "
                      "The connector picks a rewritten fragment up within seconds; no policy is re-saved."); step += 1
        if backends:
            md.append(f"{step}. Creates {len(backends)} backend entit{'y' if len(backends) == 1 else 'ies'} on Standard v2 / Premium v2 "
                      "(skipped on other tiers, which trust the endpoints through CA certificates): "
                      + ", ".join(f"`{n}` → `https://{h}`" for n, h in backends)); step += 1
        if deletes:
            md.append(f"{step}. Removes {len(deletes)} key Named Value(s) whose application is gone: " + ", ".join(f"`{n}`" for n in deletes)); step += 1
        md += ["", "## Files in this bundle", ""]
        for w in written:
            note = {"apply.sh": "the commands, in order — review, then run",
                    "securepath-app-map.fragment.xml": "the fragment as it will be stored (no secrets)",
                    "app-keys.env": "**secret** — the API keys; the only file that carries them",
                    "previous/securepath-app-map.fragment.xml": "the fragment as it is now, for rollback"}.get(
                w, "backend entity body" if w.startswith("backends/") else "")
            md.append(f"- `{w}` — {note}")
        md += ["", "## How to apply", "",
               "```bash", "bash apply.sh", "```", "",
               "Needs the Azure CLI logged in with **API Management Service Contributor** on the instance, and "
               "`python3`. Running it twice is safe: every write is a PUT and removals tolerate an already-removed value. "
               "API keys reach Azure through a private temporary file, never the command line.", "",
               "## How to verify", "", "```bash",
               f"python3 tools/securepath-apim-sync.py check -g {rg} -n {apim} --cloud-api-key ... --cloud-context ...",
               f"python3 tools/securepath-apim-lint.py --live -g {rg} -n {apim}",
               "```", "",
               "`check` prints `in sync` (exit 0) once the instance matches the account. Then trace one request "
               "for each application host with `tools/securepath-apim-trace.sh` (README Debugging).", ""]
        if previous_fragment:
            md += ["## Rollback", "",
                   "`previous/securepath-app-map.fragment.xml` is the generated map as it was before this change. "
                   "To put it back, run the fragment step of `apply.sh` (step 2) with that file instead.", ""]
        md += ["## Secrets", "",
               "`app-keys.env` holds the SecurePath API keys in clear text so that `apply.sh` and `CHANGES.md` do not. "
               "Keep it out of tickets, chat and version control, and delete it once `apply.sh` has run — the keys "
               "then live only in the secret Named Values.", ""]
    emit("CHANGES.md", "\n".join(md))
    for w in written:
        log(f"wrote {os.path.join(out_dir, w)}")
    return written


def render(reader, desired, out_dir, rg, apim, offline, prune, source, log=print):
    rec = RecordingWriter(reader)
    lines = []
    plan(rec, desired, log=lines.append)          # the review table, exactly as `plan` prints it
    apply(rec, desired, prune, log=lambda *_: None)  # records the writes; nothing is sent
    previous = "" if offline else (reader.current_fragment_text() or "")
    render_bundle(rec.ops, lines, out_dir, rg, apim, offline, prune, source, previous_fragment=previous, log=log)
    log("in sync: nothing to apply" if not rec.ops else f"bundle ready in {out_dir}: review CHANGES.md, then bash {os.path.join(out_dir, 'apply.sh')}")
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
    with os.fdopen(os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        json.dump(body, f, indent=2)
    log(f"wrote {out_path} ({len(desired)} entries, contains the applications' API keys — delete it after the deployment); "
        f"pass it with --parameters @{os.path.basename(out_path)} together with apimName, appId, apiKey and endpoint")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Keep the SecurePath application map in step with your Radware Cloud account")
    ap.add_argument("command", choices=["plan", "apply", "check", "export", "render"])
    ap.add_argument("-g", "--resource-group")
    ap.add_argument("-n", "--apim")
    ap.add_argument("--cloud-api-key", help="Radware Cloud portal API key (prefer RDWR_CLOUD_API_KEY or --cloud-api-key-file: this form is visible in shell history)")
    ap.add_argument("--cloud-api-key-file", help="file holding the Radware Cloud portal API key")
    ap.add_argument("--cloud-context", help="Application Protection ID (context header; or RDWR_CLOUD_CONTEXT)")
    ap.add_argument("--from-file", help="read the application list from this JSON file instead of the Radware Cloud API")
    ap.add_argument("--prune", action="store_true", help="apply: remove map entries whose application is gone from the account")
    ap.add_argument("--include-provisioning", action="store_true", help="also include applications still provisioning")
    ap.add_argument("--out", default="securepath-appmap.parameters.json", help="export: parameter file to write")
    ap.add_argument("--out-dir", default="securepath-apim-bundle", help="render: directory for the change bundle")
    ap.add_argument("--offline", action="store_true", help="render: do not read the instance; bundle the whole desired state")
    a = ap.parse_args(argv)
    try:
        cloud_key = a.cloud_api_key or os.environ.get("RDWR_CLOUD_API_KEY", "")
        if a.cloud_api_key_file:
            with open(a.cloud_api_key_file, encoding="utf-8") as f:
                cloud_key = f.read().strip()
        cloud_context = a.cloud_context or os.environ.get("RDWR_CLOUD_CONTEXT", "")
        a.cloud_context = cloud_context
        if a.from_file:
            with open(a.from_file, encoding="utf-8") as f:
                raw = json.load(f)
        elif cloud_key and cloud_context:
            raw = fetch_cloud_apps(cloud_key, cloud_context)
        else:
            ap.error("give the Radware Cloud API key (RDWR_CLOUD_API_KEY, --cloud-api-key-file or --cloud-api-key) and the context (RDWR_CLOUD_CONTEXT or --cloud-context), or --from-file")
        if isinstance(raw, dict):
            raw = raw.get("content") or raw.get("applications") or []
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
        if a.command == "render":
            source = f"file `{a.from_file}`" if a.from_file else f"Radware Cloud account (context `{a.cloud_context}`)"
            reader = OfflineReader() if a.offline else AzWriter(a.resource_group, a.apim)
            return render(reader, desired, a.out_dir, a.resource_group, a.apim, a.offline, a.prune, source)
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
