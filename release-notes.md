# Azure APIM SecurePath Connector Release Notes

## v1.3.0 (2026-03-12)

**Graduate from beta.** Full alignment with R&D NGINX v1.1.0 reference connector. v2 response-phase support via `send-one-way-request`. Complete sideband assembly with all `x-rdwr-*` headers. Custom block page support. Platform code `400-v1.3.0`.

### Features
- **XML policy-based architecture** — No custom C# code required; implements all SecurePath logic as Azure APIM XML policies
- **Complete sideband assembly** — All mandatory headers (`x-rdwr-app-id`, `x-rdwr-api-key`, `x-rdwr-connector-ip`, `x-rdwr-true-client-ip`, `x-rdwr-host`, `x-rdwr-connector-port`, `x-rdwr-connector-scheme`, `x-rdwr-plugin-info`, `x-rdwr-connector-proto`, `x-rdwr-connector-stage`)
- **Verdict enforcement** — Allow, block, redirect, challenge, inject_js, true_bypass
- **Bot Manager integration** — BM cookie/header extraction and propagation on all verdict paths
- **v2 response-phase** — Asynchronous log POST via `send-one-way-request` with correlation ID, origin response metadata capture (4 o2v headers, partial o2h headers)
- **Reserved header security** — Strips spoofed `x-rdwr-*` headers from client requests
- **Static bypass** — Configured paths skip sideband entirely
- **Fail-open** — Traffic allowed through when SecurePath is unreachable
- **Custom block page** — Returns configured HTML/JSON block page on block verdict

### Known Limitations
- **No JavaScript injection** — Azure APIM XML policies cannot modify response bodies. JS injection verdict returns allow instead. This is a platform limitation, not a bug.
- **`x-rdwr-connector-scheme` always HTTPS** — Azure forces HTTPS on ingress; the connector cannot originate HTTP to the origin server without additional configuration
- **Partial body size format difference** — APIM sends truncated body as-is; NGINX sends `content-length: 0` for bodies > max_size
- **v2 partial o2h headers** — Only a subset of the 21 reference headers are available in APIM response context (due to XML policy expression limitations)

### Known Variances (7 expected, registered in QA suite)
1. JS injection not attempted (platform limitation)
2. Block page source (local vs SP body)
3. `x-rdwr-connector-scheme` always `https`
4. `x-rdwr-partial-body` format difference
5. v2 o2h header count (partial set)
6. v2 response-phase header names (APIM naming conventions)
7. Sideband Content-Type on mode 2 (application/octet-stream variance)

### Testing & Validation
- **Parity suite**: 35/35 PASS (STRICT or EQUIVALENT)
- **Deep test suites**: sideband (23/23), origin (19/19) — 7 expected variances show as SKIP, not FAIL
- **Real SP validation**: WAF protection, API security blocks, bot manager detection — all working

### Deployment
Deploy the XML policy file (`rdwr-azureapim-securepath-connector-v1.3.xml`) to an Azure APIM instance via the Azure Portal or `az apim api operation policy create` CLI command.

### Requirements
- Azure API Management instance (any tier)
- SecurePath endpoint configuration (platform ID `400`)
- API key and app ID from SecurePath console

---

## v1.3.0-beta (2026-02-28)

Initial beta release. XML policy-based connector with sideband assembly, verdict enforcement, BM integration, and v2 response-phase support.

---

## Version History

| Version | Date | Status | Notes |
|---------|------|--------|-------|
| v1.3.0 | 2026-03-12 | **RELEASED** | Graduate from beta; full R&D alignment |
| v1.3.0-beta | 2026-02-28 | Deprecated | Initial beta |
| v1.2.0 | 2026-02-14 | Deprecated | Previous stable (pre-v2 response-phase) |
| v1.1.0 | 2025-11-30 | EOL | Early release |
| v1.0.0 | 2025-09-15 | EOL | Initial release |
