#!/usr/bin/env python3
"""Radware SecurePath connector for Azure API Management: application sync.

Reads the SecurePath applications of your Radware Cloud account and writes them
into the connector's application map (Named Value rdwr-app-map), keyed by each
application's domain, and on Standard v2 / Premium v2 creates the backend entity
that establishes trust for each inspection endpoint. Idempotent: run it again
whenever an application is added or changed.

    python3 tools/securepath-apim-sync.py -g RG -n APIM --cloud-api-key KEY --cloud-context CTX [--dry-run] [--print-map]

The same projection runs inside the policy when cloud sync is enabled there
(README "Protecting APIs that belong to different SecurePath applications").
This tool is for operators who prefer an explicit map, and it is the only way
to create the per-endpoint backend entities on v2 tiers automatically.

Exit codes: 0 done, 1 nothing to write (no protecting application), 2 failure.
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("securepath_apim_lint", os.path.join(HERE, "securepath-apim-lint.py"))
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)

API_VERSION = lint.API_VERSION
project_cloud_apps = lint.project_cloud_apps
fetch_cloud_apps = lint.fetch_cloud_apps


def render_map(app_map: dict) -> str:
    """Single-quoted JSON, the only form a Named Value can carry."""
    text = json.dumps(app_map, separators=(", ", ": "), sort_keys=True)
    for ch in ("'", "&", "<"):
        if ch in text:
            raise ValueError(f"application map contains {ch!r}, which cannot be stored in a Named Value")
    return text.replace('"', "'")


class AzWriter:
    """az rest wrapper; injectable in tests."""

    def __init__(self, rg: str, apim: str, run=None):
        self.run = run or self._run
        sub = self.run(["account", "show", "--query", "id", "-o", "tsv"]).strip()
        self.base = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
                     f"/providers/Microsoft.ApiManagement/service/{apim}")

    @staticmethod
    def _run(args):
        p = subprocess.run(["az"] + args, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.strip() or f"az {' '.join(args)} failed")
        return p.stdout

    def get(self, path):
        raw = self.run(["rest", "--method", "GET", "--uri", f"{self.base}{path}?api-version={API_VERSION}", "-o", "json"])
        return json.loads(raw.lstrip("﻿")) if raw.strip() else {}

    def put(self, path, body):
        self.run(["rest", "--method", "PUT", "--uri", f"{self.base}{path}?api-version={API_VERSION}",
                  "--headers", "Content-Type=application/json", "--body", json.dumps(body), "-o", "none"])

    def sku(self):
        return (self.get("").get("sku") or {}).get("name", "")

    def backend_hosts(self):
        out = {}
        for b in self.get("/backends").get("value", []):
            out[lint._host_of((b.get("properties") or {}).get("url", ""))] = b["name"]
        return out

    def write_map(self, rendered):
        self.put("/namedValues/rdwr-app-map", {"properties": {"displayName": "rdwr-app-map", "value": rendered, "secret": True}})

    def create_backend(self, name, host):
        self.put(f"/backends/{name}", {"properties": {
            "url": f"https://{host}", "protocol": "http", "title": "SecurePath inspection endpoint",
            "tls": {"validateCertificateChain": False, "validateCertificateName": False}}})


def sync(writer, apps_raw, dry_run=False, log=print):
    app_map = project_cloud_apps(apps_raw)
    if not app_map:
        log("no SecurePath application in PROTECTING state was returned for this key and context")
        return 1, app_map
    rendered = render_map(app_map)
    seen = set()
    log(f"{'host':<40}{'application id':<40}endpoint")
    for host, e in sorted(app_map.items()):
        log(f"{host:<40}{e['app_id']:<40}{e['endpoint']}")
    if dry_run:
        log("dry run: nothing written")
        return 0, app_map
    writer.write_map(rendered)
    log("rdwr-app-map written (secret)")
    if writer.sku().lower().endswith("v2"):
        existing = writer.backend_hosts()
        n = 0
        for e in app_map.values():
            host = e["endpoint"]
            if host in seen:
                continue
            seen.add(host)
            if host in existing:
                log(f"backend for {host}: exists ({existing[host]})")
                continue
            n += 1
            name = f"securepath-sideband-{len(existing) + n}"
            writer.create_backend(name, host)
            log(f"backend for {host}: created ({name})")
    else:
        log("v1 tier: no backend entities needed (the Radware CA is validated from the certificate store)")
    return 0, app_map


def main(argv=None):
    ap = argparse.ArgumentParser(description="Write the SecurePath application map and backend entities from the Radware Cloud API")
    ap.add_argument("-g", "--resource-group", required=True)
    ap.add_argument("-n", "--apim", required=True)
    ap.add_argument("--cloud-api-key", required=True, help="Radware Cloud portal API key")
    ap.add_argument("--cloud-context", required=True, help="Application Protection ID (context header)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--print-map", action="store_true", help="also print the single-quoted map value")
    a = ap.parse_args(argv)
    try:
        apps = fetch_cloud_apps(a.cloud_api_key, a.cloud_context)
        writer = AzWriter(a.resource_group, a.apim)
        rc, app_map = sync(writer, apps, a.dry_run)
    except (RuntimeError, ValueError) as e:
        print(f"failed: {e}", file=sys.stderr)
        return 2
    if a.print_map and app_map:
        print(render_map(app_map))
    return rc


if __name__ == "__main__":
    sys.exit(main())
