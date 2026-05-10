# Release Notes — Radware SecurePath Connector for Azure API Management

---

## v1.3.2 (2026-05-03, docs refreshed 2026-05-08) — Current

**Bug fix in v1.3.2.** Corrects `x-rdwr-o2v-bytes-sent` reporting in the response-phase log to match NGINX `$bytes_sent` semantics.

### 2026-05-08 doc refresh — policy-upload command corrected (no policy XML change)

Partner feedback (Dennis Usle) revealed a third inaccurate CLI command shipped in the README. The policy XML itself is unchanged.

- **Policy upload — wrong CLI command.** Three sites in the README and one site in earlier release-notes documented `az apim api policy create-or-update` (and one site `az apim api policy update`) as the Azure CLI path for applying the SecurePath XML policy to an APIM API. **The `policy` subgroup does not exist** under `az apim api` — verified live against `az 2.77.0` (`az apim api -h` lists only `operation`, `release`, `revision`, `schema`, `versionset`) and against the canonical [`learn.microsoft.com/en-us/cli/azure/apim/api`](https://learn.microsoft.com/en-us/cli/azure/apim/api) reference. The customer's exact reported error — `'policy' is misspelled or not recognized by the system.` — was reproduced verbatim. Documentation now uses `az rest --method PUT` against the canonical [Api Policy - Create Or Update](https://learn.microsoft.com/en-us/rest/api/apimanagement/api-policy/create-or-update) ARM REST endpoint (`/apis/{api-id}/policies/policy?api-version=2024-05-01`). **Critical detail learned from live testing**: the request body's `properties.format` MUST be `rawxml`, not the default `xml` — the `xml` format rejects `{{named-value}}` references inside XML attribute values with `ValidationError: Name cannot begin with the '{' character`. PowerShell (`Set-AzApiManagementPolicy -Format "application/vnd.ms-azure-apim.policy.raw+xml"`) and Bicep (`Microsoft.ApiManagement/service/apis/policies` with `format: 'rawxml'`) alternatives are also documented. The end-to-end PUT was verified live against the QA APIM instance with the actual `rdwr-azureapim-securepath-connector-v1.3.xml` file: the PUT returned the canonical PolicyContract, the GET-after-PUT confirmed the policy is stored at `/apis/proxy-all/policies/policy`, and the gateway processes inbound requests through the policy as expected.

- **`<api-id>` clarification.** The customer also pasted the SecurePath endpoint hostname (`<app-id>.oop.radwarecloud.net`) into `--api-id`, since "the api id" is ambiguous. Docs now explicitly call out that `<api-id>` is the resource name of an APIM API in their instance (e.g. `proxy-all`, `orders-api`) — discoverable with `az apim api list -g $RG --service-name $APIM --query "[].name" -o tsv` — and is **not** the SecurePath endpoint hostname (which goes into the `rdwr-app-ep-addr` Named Value at Step 2).

### 2026-05-07 doc refresh — onboarding accuracy fixes (no policy XML change)

Customer feedback revealed two onboarding failures driven by inaccurate documentation; the policy XML itself is unchanged. Both are now corrected in the README and `certs/README.md`:

- **CA certificate upload — wrong CLI command.** The README and `certs/README.md` previously documented `az apim certificate create` and `az apim certificate-authority create` as the Azure CLI path for uploading the Radware CA chain. **Neither command exists** in the `az apim` CLI tree (verified against the canonical `learn.microsoft.com/en-us/cli/azure/apim` reference). Customers attempting this hit confusing errors and ultimately fell back to the Portal — which itself only accepts `.cer` files (PEM and CER are the same Base64 X.509 format; rename suffices, no conversion needed). Microsoft's canonical doc is [Add a Custom CA Certificate](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-ca-certificates), which describes Portal and PowerShell paths only and explicitly references uploading a `.cer` file. Documentation now leads with the Portal path (rename `.pem` → `.cer` first), notes the missing CLI support up front, lists PowerShell (`New-AzApiManagementSystemCertificate`) and ARM/Bicep alternatives for IaC pipelines, and flags the v2 / Consumption tier exclusion (Microsoft requires per-backend trust on those tiers).

- **Named Values — "default" framing was misleading + empty-string CLI trap.** The Step 2 table previously listed 15 Named Values as having "recommended defaults already wired in the policy XML," implying customers could skip them. The XML uses standard `{{name}}` substitution at policy-save time, so **every referenced Named Value must exist** — if any is missing, APIM rejects the policy upload with *"Named Value 'rdwr-...' not found"*. Worse: two of those 15 (`rdwr-api-base-path` and `rdwr-inline-trusted-sources`) had `(empty)` listed as their default, but `az apim nv create --value ""` silently fails (CLI rejects empty strings), so customers following the table verbatim ended up with two missing Named Values and a failed policy upload. The customer reported this exact symptom: *"weird there seem to be more in the named value list than i pasted, yet a couple are not there"* — the two missing ones were exactly the empty-default rows. Documentation now: (a) reframes the column as "Recommended value to set the Named Value to," with an explicit callout that the policy doesn't fall back if you skip the Named Value; (b) shows sentinel-disable values (`/` for `rdwr-api-base-path`; `##DISABLED##` for `rdwr-inline-trusted-sources` — both already recognised by the policy as disabled) instead of empty strings; (c) ships a complete bash loop for all 15 Tier-2 Named Values so customers don't have to hand-construct the CLI calls; (d) adds a verification step to confirm 18 Named Values exist before applying the policy.

The Quickstart section (lines 67–124) was also expanded with a new Step 2a covering the 15 Tier-2 Named Values — previously the Quickstart only created 3, which would have produced a failed policy upload at Step 3 for any customer following it literally.

### Bug Fixes

### Bug Fixes

- **`x-rdwr-o2v-bytes-sent` now reports total wire bytes** (status line + serialized response headers + body), not body length alone. Before this fix the field equalled `x-rdwr-o2v-body-bytes-sent`, which under-reported actual response size by the size of the response headers. The XML allow-path expression now sums `~20` bytes for the status line approximation, every response header serialized as `Name: Value\r\n`, the final empty-line CRLF (`2` bytes), and the body length. `x-rdwr-o2v-body-bytes-sent` continues to report body bytes only, matching NGINX `$body_bytes_sent`.

### Sideband Plugin Info

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
  
  This enables the SecurePath portal to report which requests actually reached origin.
- **Response-phase log on all verdict paths.** The response-phase log now fires on allow, block, and redirect verdicts (previously only on allow). This gives full analytics visibility for traffic that never reaches the origin.

### Sideband Plugin Info
- `x-rdwr-plugin-info` default updated to `700-v1.3.1`.

### Deployment
Same XML policy file (`rdwr-azureapim-securepath-connector-v1.3.xml`). No new Named Values required. Existing deployments can upgrade by replacing the policy XML in place.

---

## v1.3.0 (2026-03-12)

**General availability.** Full SecurePath feature coverage at the API Management policy layer. Adds asynchronous response-phase logging via `send-one-way-request`, complete sideband header assembly, and a customisable block page.

### Features
- **XML policy-based architecture.** No custom C# code; all SecurePath logic is implemented as Azure APIM XML policies.
- **Complete sideband header assembly.** All mandatory `x-rdwr-*` headers (`x-rdwr-app-id`, `x-rdwr-api-key`, `x-rdwr-connector-ip`, `x-rdwr-true-client-ip`, `x-rdwr-host`, `x-rdwr-connector-port`, `x-rdwr-connector-scheme`, `x-rdwr-plugin-info`, `x-rdwr-connector-proto`, `x-rdwr-connector-stage`).
- **Verdict enforcement.** Allow, block (HTML and JSON), 301/302 redirect, challenge, true-bypass.
- **Bot Manager integration.** Bot Manager cookie and header propagation on all verdict paths.
- **Response-phase logging (v2).** Fire-and-forget log POST via `send-one-way-request`, correlated by `x-rdwr-oop-id`. Captures origin response metadata; mode 3 includes a base64-encoded body sample.
- **Reserved header security.** Strips spoofed `x-rdwr-*` headers from incoming client requests (returns 403).
- **Static resource bypass.** Configurable file extensions and HTTP methods skip sideband entirely.
- **Fail-open by default.** Traffic flows to backend if SecurePath is unreachable.
- **Custom block page.** Configurable HTML/JSON block page rendered on block verdict, with transaction ID extraction.

### Platform Notes
- **No JavaScript injection.** Azure APIM XML policies cannot modify response bodies; the `inject_js` verdict is treated as `allow`. This is an APIM platform constraint, not a connector limitation. Practical impact is minimal for API gateway traffic (typically JSON/XML).
- **`x-rdwr-connector-scheme` always `https`.** Azure APIM forces HTTPS termination; the scheme value reflects this.
- **Partial body format.** APIM forwards a truncated body when oversize is detected; other Radware SecurePath connectors may instead send `Content-Length: 0`. Both are valid SecurePath inputs.

### Sideband Plugin Info
- `x-rdwr-plugin-info` value: `700-v1.3.0`. Platform code `700` identifies this connector as the Azure API Management variant.

### Deployment
Deploy the XML policy file (`rdwr-azureapim-securepath-connector-v1.3.xml`) to your APIM instance via the Azure Portal (Design → Policies code editor) or via `az rest --method PUT` against the ARM REST API. Configure all required Named Values before applying the policy. See `README.md` for the complete onboarding walkthrough.

### Requirements
- Azure API Management instance (any tier: Developer, Basic, Standard, Premium, v2)
- A SecurePath application provisioned in the [Radware Cloud portal](https://portal.radwarecloud.com)
- Outbound HTTPS connectivity (port 443) from APIM to `*.oop.radwarecloud.net`

---

## v1.2.0 (2025-11-30)

Bot Manager cookie and header handling, reserved header security, static bypass, sideband Host header override for Azure Web Apps backends.

---

## v1.1.0 (2025-09-15)

Body handling improvements, chunked request support.

---

## v1.0.0 (2025-05-01)

Initial release. Basic sideband and verdict enforcement.

---

## Version History

| Version    | Date       | Status      | Highlights                                                       |
|------------|------------|-------------|------------------------------------------------------------------|
| **v1.3.2** | 2026-05-03 | **Current** | `x-rdwr-o2v-bytes-sent` reports total wire bytes (status line + headers + body) |
| v1.3.1     | 2026-03-31 | Superseded  | Disposition header, v2 log on block/redirect, body-truncation fix |
| v1.3.0     | 2026-03-12 | Superseded  | GA release, full feature coverage, response-phase logging        |
| v1.2.0     | 2025-11-30 | Superseded  | Bot Manager support, reserved header enforcement                 |
| v1.1.0     | 2025-09-15 | Superseded  | Body handling, chunked support                                   |
| v1.0.0     | 2025-05-01 | Superseded  | Initial release                                                  |
