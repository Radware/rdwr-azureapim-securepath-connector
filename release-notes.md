# Release Notes — Radware SecurePath Connector for Azure API Management

### Named Values and version

Three new Named Values (23 in total): `rdwr-app-map`, `rdwr-true-host-header` and
`rdwr-custom-bot-block-statuses`. `x-rdwr-plugin-info` becomes `700-v1.4.0`.

### Upgrading from v1.3.x

1. Create the three new Named Values (README 3b) and set `plugin-version-info` to `700-v1.4.0`.
2. Register the four v1.4.0 fragments (README Step 4, Form 1, first block). Two are new
   (`securepath-app-map`, `securepath-onerror`); the other two replace the v1.3.4 ones in place.
3. If you installed v1.3.4 Form C (two fragments referenced from a policy), add the two missing
   include lines — `securepath-app-map` immediately before `securepath-inbound`, and
   `securepath-onerror` in `<on-error>` (README Form 2).
4. If you installed v1.3.4 Form A or B (a policy document), replace it with the fragment install
   (Form 1 or 2) or with `rdwr-azureapim-securepath-connector-v1.4.xml` (Form 3).
5. Run `python3 tools/securepath-apim-lint.py --live` (README 5e) and trace one request
   (README Debugging, Option A).

---

## v1.4.0 (2026-09-07)

### Several SecurePath applications on one instance

A request now selects its application by the API's resource name, by the client-facing
hostname, or by a default entry — from the new **application map** Named Value
(`rdwr-app-map`) — with per-entry base path, port, TLS and Bot Manager overrides. Without a
map, the three application values behave exactly as before.

### Keeping the map in step with the Radware Cloud account

A Named Value holds about 4,000 characters, roughly seventeen map entries. Larger estates use the
**generated map**: `tools/securepath-apim-sync.py apply` writes the policy fragment
`securepath-app-map` (hostname, application id, endpoint per application; hundreds fit) and one
secret Named Value per application key (`rdwr-app-key-<application id>`) that the fragment
references, so no key appears in policy text. The install registers an empty default fragment;
`rdwr-app-map` stays available for hand-written entries and overrides.

The tool reads the SecurePath applications of an account through the Radware Cloud API (or a
saved copy, `--from-file`) and compares them with the instance: `plan` shows what differs,
`apply` writes only that difference (keys before the fragment, then backends), `check` exits
non-zero on drift for a scheduler, `--prune` removes applications that are gone, `export` writes
a Bicep parameter file. The gateway itself never polls the Radware Cloud; selection stays on the
request path, reading the map.

### The client-facing hostname

`rdwr-true-host-header` names the request header that carries the hostname the client used when
Azure Front Door, a CDN or a proxy sits in front of the gateway (for example `X-Forwarded-Host`).
That hostname selects the application and is the `Host` reported to SecurePath.

### A configuration problem no longer fails requests

An incomplete configuration, an unmatched request with no default application, or an invalid
map used to be able to end a request with a 500. Such requests are now served without
inspection and marked with `X-Rdwr-Diag` (`config_incomplete`, `no_app_mapping`,
`app_map_invalid`) and a trace line, so the condition is visible without affecting traffic.

### Two behaviours aligned with the other SecurePath connectors

- A SecurePath response with a status the connector does not know (for example 401 or 418) is no
  longer relayed to the client. The request is served without a verdict, marked with
  `X-Rdwr-Diag: unexpected_status_<code>` and a trace line, which is what the other SecurePath
  connectors do — unless the status is listed in `rdwr-custom-bot-block-statuses` (below).
- The `uzmcr` header (the Bot Manager mobile flow) is honoured as an allow signal whether or not
  Bot Manager is enabled, and relayed to the client — with the Bot Manager cookies — only when
  `rdwr-bot-manager-enabled` is true, as the SecurePath specification requires.

### Requests rejected by your own policies now get a response-phase record

An on-error fragment, `fragments/securepath-onerror.fragment.xml`, sends the response-phase log from
the `on-error` section. Previously, when the connector allowed a request and a later policy in
the gateway rejected it (an expired token, a rate limit), API Management skipped the outbound
section and the record for that request had no response status. All four fragments —
`securepath-app-map`, `securepath-inbound`, `securepath-outbound`, `securepath-onerror` — are
referenced together, the app-map one immediately before the inbound one; the install forms and the
Bicep template do this for you.

### Fragments at All APIs scope are the default install

The connector installed at the All APIs scope runs before every API's own policy, so nothing has
to be ordered by hand and no existing policy is edited. `deploy/securepath-apim.bicep` installs
everything in one deployment. The whole-document form is now generated from the fragments
(`rdwr-azureapim-securepath-connector-v1.4.xml`); the v1.3 documents are no longer shipped.

### `tools/securepath-apim-lint.py`

Reads a policy document or a live instance and reports the conditions under which the connector
is installed but ineffective: missing or duplicated install, an API policy without `<base />`, a
request-ending policy placed ahead of the connector, an empty `set-variable` left by a manual
merge, missing or malformed Named Values, an invalid or mistyped application map, a missing
backend entity on v2 tiers, a fragment on the instance that differs from the shipped file (a
fragment registration is asynchronous and a rejected upload keeps the previous fragment), and an
invalid custom Bot Manager status list.

### Custom Bot Manager block responses are relayed

- New Named Value **`rdwr-custom-bot-block-statuses`** (default `##DISABLED##`; Bicep parameter
  `customBotBlockStatuses`). When Bot Manager is enabled and SecurePath answers with a status
  outside the standard verdicts that is listed here (`429`, `429,418`, or `*` for any), the connector
  relays that response to the client as a Bot Manager block: status, body, `Content-Type`,
  `Retry-After`, `Cache-Control`, `Expires`, `Pragma`, `WWW-Authenticate`, `Content-Language`,
  `Vary`, and the Bot Manager cookies; the response-phase log marks it `blocked`. A missing body is
  replaced by the connector's block page with that status. Standard verdicts are unaffected, a
  `5xx` is never relayed, an invalid list is ignored (and reported by the install check as `L13`),
  and an application-map entry may override the list with `bot_block_statuses`. Matches the
  NGINX connector's `rdwr_custom_bot_block_statuses`. README 3e.

### Robustness and hygiene

- A numeric or boolean Named Value the policy cannot read (`10s`, `yes`) no longer fails every
  request: the documented default is used and the trace names the value.
- A client-supplied `X-Rdwr-Diag` header is removed before the connector runs, so the signal your
  backend logs cannot be forged.
- `rdwr-true-client-ip-header` now defaults to `##DISABLED##`; when set, only the first address in
  the header is used and only if it is a valid IP address. `rdwr-inline-headers-enabled` no longer
  bypasses inspection on its own: a trusted-source list is required.
- All Bot Manager cookies SecurePath sends are relayed (up to six per response, previously three).
- The response-phase log of a blocked or redirected request reports the bytes actually sent to the
  client instead of zero, and origin response headers are reported only when the origin sent them.
- The response-phase log is sent once per request even when an outbound policy fails after it.
- Block responses use standard HTTP reason phrases (`Forbidden`, `Found`, `Too Many Requests`).
- An application-map entry that is not an object, or whose `port`, `ssl` or `bot_manager` has the
  wrong type, is treated as an invalid map (served uninspected, `X-Rdwr-Diag: app_map_invalid`)
  instead of failing the request; the install check names the entry.

### `securepath-apim-sync render`: a change bundle instead of a direct write

- For change-controlled environments, `render` writes what `apply` would do as files: `CHANGES.md`
  (the change document), `apply.sh` (the commands, in order, idempotent), the fragment as it will
  be stored, the backend entity bodies, and the API keys in a separate `app-keys.env`. Nothing is
  sent to Azure. `--offline` skips reading the instance so the tool needs no Azure login; the
  bundle then carries the whole desired state. Executed end to end on a Standard v2 instance.

### Debugging: trace one request from the command line, and read it

- **`tools/securepath-apim-trace.sh`** captures one API Management trace without the Portal —
  debug token for the API, one request through the URL your clients use (Front Door included),
  fetch by `Apim-Trace-Id`, save, redact the credentials inside it, read. Anything after the
  script name is passed to `curl`. `securepath-apim-lint.py --redact` does the redaction for a
  trace saved any other way.
- **`securepath-apim-lint.py --trace trace.json`** reads any trace (from the script, the Portal,
  or a colleague) and prints a readout: whether the connector ran, what ran before it, where the
  inspection call went and how it ended, the verdict, and why a request was served uninspected.
  Findings T01–T08 name the cause, the fix and the step of the README that covers it.
- The README Debugging section now leads with these, shows a healthy readout and the readout of the
  most common field failure (the `.v1` front-end host in `rdwr-app-ep-addr`, which the backend
  entity for the `.oop` host cannot cover), and adds a line-by-line table for reading a raw trace.
  Both readouts were produced on a Standard v2 instance against a live SecurePath application.

## v1.3.4 (2026-08-16)

**Documentation and packaging release. The policy XML is unchanged from v1.3.2** — there is nothing
to redeploy if the connector is already working. `x-rdwr-plugin-info` remains `700-v1.3.2`.

### Three install forms, so the connector fits an instance that is already in use

Previous versions offered one install: replace an API's policy document. On an API that already has
a policy, that discards it.

- **Form C — policy fragments (new, recommended).** Two reusable fragments,
  `fragments/securepath-inbound.fragment.xml` and `fragments/securepath-outbound.fragment.xml`, are
  registered once and referenced with two `include-fragment` lines from any scope. Existing policies
  are left intact. Updating the connector means replacing the fragments; every scope that references
  them picks up the change. A fragment cannot be deleted while it is still referenced.
- **Form B — policy document at All APIs scope (new).** Covers every API in one action, using
  `rdwr-azureapim-securepath-connector-v1.3-all-apis-scope.xml`. The standard file is rejected at
  this scope, because `<base />` is not permitted in the global context.
- **Form A — policy document at API scope.** Unchanged, and now carries an explicit warning that it
  replaces the API's existing policy.

### Validation

All three forms were exercised against a live SecurePath application on a Standard v2 instance,
with Bot Manager enabled, and were confirmed to **inspect traffic** — not merely to install.

| Check | Form A | Form B | Form C |
|---|:--:|:--:|:--:|
| Allow verdict returned to the client | ✓ | ✓ | ✓ |
| Bot Manager cookies from SecurePath reach the client | ✓ | ✓ | ✓ |
| Reserved header rejected with 403 | ✓ | ✓ | ✓ |

Bot Manager cookie propagation is the meaningful signal: the cookies originate at SecurePath, so
their arrival proves the inspection call completed; and they are captured during the request phase
and applied during the response phase, so their arrival under Form C also proves that state carries
across the two fragments. A baseline with no connector installed returned no such cookies, and all
three forms agreed exactly.

An API Management trace of the fragment form additionally confirms the response-phase log:

```
One way request was successfully send to https://<endpoint>.oop.radwarecloud.net/...
x-rdwr-oop-request-status = allowed
x-rdwr-oop-id             = 645d331c83b493192c22c9bf4b1ff6bf
x-rdwr-oop-log            = 2
```

with no suppressed errors in the trace. The fragment form was also confirmed to install and execute
at API, product and All APIs scope.

### Two pre-flight checks, added as a new Step 2

- **Named Value collisions.** `az apim nv create` **overwrites an existing Named Value without any
  error** — earlier revisions of this guide stated the opposite. Six of the twenty names the
  connector uses carry no `rdwr-` prefix and can already exist on a shared instance. Step 2a lists
  any collisions, with their current values, before anything is written.
- **Policies missing `<base />`.** If an API's own policy omits `<base />` from its inbound section,
  a policy installed at All APIs scope is **skipped for that API** — no error, no protection.
  Step 2b audits every API.

### Also

- **Required permissions** are now stated: **API Management Service Contributor**. API Management
  Service Operator is not sufficient — it grants only read access to the sub-resources involved.
- **Do not install at two scopes at once.** Measured on Standard v2, a connector present at both All
  APIs and API scope inspects every request twice: 2.58 s versus 0.90 s for the same request.
- Removal instructions now cover all three forms separately.

---

## v1.3.3 (2026-08-14)

**Documentation and packaging release. The policy XML is unchanged from v1.3.2** — there is nothing
to redeploy if the connector is already working. `x-rdwr-plugin-info` remains `700-v1.3.2`, because
it identifies the policy and the policy did not change.

### Deployment guidance for the v2 tiers

Standard v2 and Premium v2 have no service-level CA certificate store, so the certificate upload in
Step 1 cannot be performed on those tiers. Onboarding now documents a second path: create a
**backend entity** for the SecurePath endpoint. API Management applies it automatically to the
inspection call, so **no policy change is required**.

Previous revisions described the v2 tiers as equivalent to Developer / Basic / Standard / Premium.
They are not, and a deployment on a v2 tier without this step will serve traffic **uninspected**
with no error surfaced. The tier table, Step 1 and the troubleshooting section now reflect this.

### Onboarding guide rewritten

- **Every command block is self-contained.** Each begins with its own settings block, so any step
  can be run on its own, in any order, in a fresh shell — no reliance on variables set earlier.
- **Order is stated with reasons.** Each step explains why it must come where it does, including why
  Named Values must exist before the policy is applied.
- **Verification distinguishes three different things** — the policy being installed, the policy
  executing, and inspection actually happening. A `200` response proves none of them; the guide now
  says so and gives checks that do.
- **New debugging section** built around the API Management trace, including how to capture one and
  the exact strings to search for.
- **Application ID guidance.** The portal also shows a `.v1.radwarecloud.net` hostname that this
  connector does not use. Supplying it produces no error and results in uninspected traffic. Step 2c
  now checks for it.
- Shell variables renamed to match the Named Values they populate.

### Packaging

- **`certs/rdwr-root-ca.pem` and `certs/rdwr-intermediate-ca.pem` are now included in the release
  archive.** Both are required by Step 1 and were absent from the v1.3.0, v1.3.1 and v1.3.2
  archives.

---

## v1.3.2 (GA 2026-05-04)

### Bug Fixes

- **`x-rdwr-o2v-bytes-sent` now reports total wire bytes** (status line + headers + body), not body length alone. `x-rdwr-o2v-body-bytes-sent` continues to report body bytes only.

### Inspection call Plugin Info

- `x-rdwr-plugin-info` default updated to `700-v1.3.2`.

### Deployment

Same XML policy file (`rdwr-azureapim-securepath-connector-v1.3.xml`). No new Named Values required. Existing deployments can upgrade by replacing the policy XML in place via the Azure Portal (Design → Policies code editor) or via `az rest --method PUT` against `/apis/{api-id}/policies/policy?api-version=2024-05-01` with `format: rawxml` — see README §Step 3 for the full command.

---

## v1.3.1 (2026-03-31)

**Bug fix and analytics enhancement.** Adds connector disposition reporting in the response-phase log, enables response-phase logging on block and redirect verdicts, and corrects large-body forwarding behavior.

### Bug Fixes
- **Large request body forwarding.** When `Content-Length` exceeded `rdwr-body-max-size-bytes`, the policy previously forwarded the full body to SecurePath instead of skipping it. The policy now correctly sends an empty body in that case, preserving the configured size limit.

### Enhancements
- **Connector disposition header.** The response-phase log POST now includes `x-rdwr-o2h-rdwr-response`, with value:
  - `allowed` — the request reached the origin backend
  - `blocked` — the connector blocked or redirected the request
  
  This enables the Radware Cloud portal to report which requests actually reached origin.
- **Response-phase log on all verdict paths.** The response-phase log now fires on allow, block, and redirect verdicts (previously only on allow). This gives full analytics visibility for traffic that never reaches the origin.

### Inspection call Plugin Info
- `x-rdwr-plugin-info` default updated to `700-v1.3.1`.

### Deployment
Same XML policy file (`rdwr-azureapim-securepath-connector-v1.3.xml`). No new Named Values required. Existing deployments can upgrade by replacing the policy XML in place.

---

## v1.3.0 (2026-03-12)

**General availability.** Full SecurePath feature coverage at the API Management policy layer. Adds asynchronous response-phase logging via `send-one-way-request`, complete inspection call header assembly, and a customisable block page.

### Features
- **XML policy-based architecture.** No custom C# code; all SecurePath logic is implemented as Azure APIM XML policies.
- **Complete inspection call header assembly.** All mandatory `x-rdwr-*` headers (`x-rdwr-app-id`, `x-rdwr-api-key`, `x-rdwr-connector-ip`, `x-rdwr-true-client-ip`, `x-rdwr-host`, `x-rdwr-connector-port`, `x-rdwr-connector-scheme`, `x-rdwr-plugin-info`, `x-rdwr-connector-proto`, `x-rdwr-connector-stage`).
- **Verdict enforcement.** Allow, block (HTML and JSON), 301/302 redirect, challenge, true-bypass.
- **Bot Manager integration.** Bot Manager cookie and header propagation on all verdict paths.
- **Response-phase logging (v2).** Fire-and-forget log POST via `send-one-way-request`, correlated by `x-rdwr-oop-id`. Captures origin response metadata; body sample includes a base64-encoded body sample.
- **Reserved header security.** Strips spoofed `x-rdwr-*` headers from incoming client requests (returns 403).
- **Static resource bypass.** Configurable file extensions and HTTP methods skip inspection call entirely.
- **Fail-open by default.** Traffic flows to backend if SecurePath is unreachable.
- **Custom block page.** Configurable HTML/JSON block page rendered on block verdict, with transaction ID extraction.

### Platform Notes
- **No JavaScript injection.** Azure APIM XML policies cannot modify response bodies; the `inject_js` verdict is treated as `allow`. This is an APIM platform constraint, not a connector limitation. Practical impact is minimal for API gateway traffic (typically JSON/XML).
- **`x-rdwr-connector-scheme` always `https`.** Azure APIM forces HTTPS termination; the scheme value reflects this.
- **Partial body format.** APIM forwards a truncated body when oversize is detected; other Radware SecurePath connectors may instead send `Content-Length: 0`. Both are valid SecurePath inputs.

### Inspection call Plugin Info
- `x-rdwr-plugin-info` value: `700-v1.3.0`. Platform code `700` identifies this connector as the Azure API Management variant.

### Deployment
Deploy the XML policy file (`rdwr-azureapim-securepath-connector-v1.3.xml`) to your APIM instance via the Azure Portal (Design → Policies code editor) or via `az rest --method PUT` against the ARM REST API. Configure all required Named Values before applying the policy. See `README.md` for the complete onboarding walkthrough.

### Requirements
- Azure API Management instance (any tier: Developer, Basic, Standard, Premium, v2)
- A SecurePath application provisioned in the [Radware Cloud portal](https://portal.radwarecloud.com)
- Outbound HTTPS connectivity (port 443) from APIM to `*.oop.radwarecloud.net`

---

## v1.2.0 (2025-11-30)

Bot Manager cookie and header handling, reserved header security, static bypass, inspection call Host header override for Azure Web Apps backends.

---

## v1.1.0 (2025-09-15)

Body handling improvements, chunked request support.

---

## v1.0.0 (2025-05-01)

Initial release. Basic inspection call and verdict enforcement.

---

## Version History

| Version    | Date       | Status      | Highlights                                                       |
|------------|------------|-------------|------------------------------------------------------------------|
| **v1.4.0** | 2026-09-07 | **Current** | Several applications on one instance, generated map and sync tool, on-error log, custom Bot Manager block responses, install check, trace tool |
| v1.3.4     | 2026-08-16 | Superseded  | Three install forms, pre-flight checks (documentation and packaging; policy unchanged) |
| v1.3.3     | 2026-08-14 | Superseded  | Certificate files shipped in the package (documentation and packaging) |
| v1.3.2     | 2026-05-03 | Superseded  | `x-rdwr-o2v-bytes-sent` reports total wire bytes (status line + headers + body) |
| v1.3.1     | 2026-03-31 | Superseded  | Disposition header, response-phase log on block/redirect, body-truncation fix |
| v1.3.0     | 2026-03-12 | Superseded  | GA release, full feature coverage, response-phase logging        |
| v1.2.0     | 2025-11-30 | Superseded  | Bot Manager support, reserved header enforcement                 |
| v1.1.0     | 2025-09-15 | Superseded  | Body handling, chunked support                                   |
| v1.0.0     | 2025-05-01 | Superseded  | Initial release                                                  |
