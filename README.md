# Radware SecurePath Connector for Azure API Management

**Version 1.3.2** — Production release, Azure API Management (any tier)

An Azure API Management (APIM) policy that integrates [Radware SecurePath](https://www.radware.com/products/securepath/) into your APIM gateway, providing real-time WAF and Bot Manager protection for your APIs without changing application code or backend infrastructure.

The connector is delivered as a single XML policy file. It runs entirely inside APIM's policy pipeline — no custom C# code, no Functions, no sidecars.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Capabilities](#capabilities)
3. [Prerequisites](#prerequisites)
4. [Onboarding Walkthrough](#onboarding-walkthrough)
5. [Configuration Reference](#configuration-reference)
6. [Do's and Don'ts](#dos-and-donts)
7. [Sideband Headers](#sideband-headers)
8. [Security Notes](#security-notes)
9. [Known Platform Constraints](#known-platform-constraints)
10. [Troubleshooting](#troubleshooting)
11. [Version History](#version-history)
12. [License](#license)

---

## How It Works

For every incoming API request, the policy:

1. **Intercepts** the request in APIM's inbound pipeline.
2. **Sends a sideband copy** to the SecurePath cloud service via APIM's `send-request` policy, with all required `x-rdwr-*` headers attached.
3. **Receives a verdict** (allow, block, redirect, or challenge).
4. **Enforces the verdict** before forwarding to the backend.

```
Client ──> Azure APIM ──> [SecurePath Policy] ──> Backend API
                                  │
                                  ├── send-request ──> SecurePath Cloud
                                  │                          │
                                  │<── Verdict ──────────────┘
                                  │
                            Enforce verdict:
                            allow    → forward to backend
                            block    → return 403 (HTML or JSON)
                            redirect → 302 to challenge page
```

In the **outbound** pipeline, the policy sends a fire-and-forget response-phase log back to SecurePath for analytics correlation. Latency overhead is near zero.

---

## Capabilities

### Application Protection
- Full sideband request assembly with all required `x-rdwr-*` headers
- Verdict enforcement: allow, block (HTML and JSON), 301 / 302 redirect
- Fail-open by default — traffic flows to backend if SecurePath is unreachable
- Reserved header security — rejects (403) any client request containing spoofed `x-rdwr-*` headers
- Static resource bypass — skip inspection for configured file extensions and HTTP methods
- Configurable request body forwarding with size limits and partial-body truncation
- Multipart form-data body support with separate size limit
- Chunked request body forwarding for configured content types
- Client IP detection via configurable header (e.g., `X-Forwarded-For`)
- API base path stripping for correct URI forwarding to SecurePath

### Bot Manager Support
- Bot Manager cookie propagation (`__uzma`, `__uzmb`, `__uzmc`, `__uzmd`, `__uzmf`, `uzmcr`) on all verdict paths
- `ShieldSquare-Response` header forwarding
- `uzmcr` header detection for mobile redirect exception handling
- Invalid API key detection with safe fail-open behaviour

> **Note on JavaScript injection.** APIM cannot perform JavaScript injection into response bodies — XML policies have no response-body modification capability. Practical impact is minimal because APIM is an API gateway: traffic is typically JSON or XML consumed by backend services, not HTML rendered in browsers. Bot Manager browser fingerprinting via injected JS is not relevant for API consumers.

### Response Logging and Analytics
- **Asynchronous response-phase log** posted to SecurePath via `send-one-way-request`, correlated with the inspection request via `x-rdwr-oop-id`. Adds near-zero client latency.
- **Disposition reporting** via the `x-rdwr-o2h-rdwr-response` header — value `allowed` (request reached origin) or `blocked` (connector blocked or redirected).
- **Logs fire on every verdict path** — allow, block, and redirect — giving full analytics visibility.
- Optional response body capture (mode 3, base64-encoded, size-capped).

---

## Prerequisites

- An **Azure API Management** instance. See "Tier and networking caveats" below for tier-specific behavior.
- A **SecurePath application** provisioned in the [Radware Cloud portal](https://portal.radwarecloud.com). You will need:
  - Application ID
  - API key
  - Endpoint hostname (typically `<app-id>.oop.radwarecloud.net`)
- **Outbound HTTPS connectivity** from your APIM instance to `*.oop.radwarecloud.net` on port 443.
- The Radware CA chain uploaded to APIM's CA certificate store (provided in `certs/`). SecurePath endpoints use a private Radware CA, not a public CA.
- Azure CLI **or** Azure Portal access with permission to manage APIM Named Values, policies, and CA certificates.

### Tier and networking caveats

| Topic | Notes |
|-------|-------|
| **Developer / Basic / Standard / Premium** | Fully supported. The XML policy compiles and runs identically on all four tiers. |
| **v2 (Standard v2 / Premium v2)** | Fully supported. The `send-request` and `send-one-way-request` policies behave the same way. |
| **Consumption tier** | Partial support. Consumption-tier APIM imposes [policy expression limits](https://learn.microsoft.com/en-us/azure/api-management/api-management-features) that the policy edges around (no large body buffering, smaller header set, no `set-status` after a forward). The policy degrades gracefully — sideband and verdict enforcement still work; some edge-case headers and the inline-bypass IP allow-list are skipped. **Test in Consumption** before committing to it; the certified test matrix uses Developer-tier APIM. |
| **Self-hosted gateway** | Supported. The Self-Hosted Gateway uses the same policy engine as cloud APIM, so the policy applies as-is. The `<send-one-way-request>` log POST runs from the self-hosted node, not from cloud APIM, so make sure that node has outbound 443 to `*.oop.radwarecloud.net` and the Radware CA in its trust store. |
| **Internal VNet (stv2 / Premium internal mode)** | Supported, but the APIM gateway must have outbound network access to `*.oop.radwarecloud.net`. If your subnet route-tables / firewall rules force-tunnel internet egress, you must explicitly allow the SecurePath endpoint FQDN. The `Microsoft.Web` service tag is **not** sufficient. |
| **Custom domains and mTLS to backend** | Independent of the connector. The policy operates on the APIM-side request/response pipeline; backend mTLS, custom domains, and gateway certificates do not interact with the SecurePath sideband. |

### Latency expectations

The sideband request adds approximately **20–80 ms** of synchronous overhead per request (median ~30 ms; p99 < 100 ms over public-internet egress to the closest SecurePath PoP). The default `rdwr-app-ep-timeout-seconds` is `10`, so a slow SecurePath PoP causes at most a 10-second stall before the policy **fails open** and forwards the request to the backend.

The response-phase log uses `<send-one-way-request>`, which is fire-and-forget — it adds no measurable client-visible latency on the response path.

---

## Onboarding Walkthrough

Follow these steps in order. The full workflow takes about 15 minutes for a standard deployment.

### Step 1 — Upload the Radware CA chain to APIM

The SecurePath endpoint (`*.oop.radwarecloud.net`) is signed by a private Radware CA. APIM must trust the chain before sideband calls will succeed.

1. Open the Azure Portal, navigate to your APIM instance.
2. Go to **Security → CA certificates** and click **+ Add**.
3. Upload `certs/rdwr-root-ca.pem` — name it `rdwr-root-r1`.
4. Click **+ Add** again and upload `certs/rdwr-intermediate-ca.pem` — name it `rdwr-ca-1a1`.

Both certificates are required. CLI and ARM/Bicep equivalents are documented in `certs/README.md`.

### Step 2 — Create Named Values

The policy reads all configuration from APIM [Named Values](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-properties). Create them via the Azure Portal, Azure CLI, or your IaC tool of choice.

**Required (no defaults — must be set per environment):**

| Named Value       | Example                              | Secret? | Description                                     |
|-------------------|--------------------------------------|:-------:|-------------------------------------------------|
| `rdwr-app-ep-addr`| `your-app-id.oop.radwarecloud.net`   |    —    | SecurePath endpoint hostname                    |
| `rdwr-app-id`     | `your-app-id`                        |    —    | Application ID from the Radware Cloud portal    |
| `rdwr-api-key`    | `your-api-key`                       |  **✓**  | API key from the Radware Cloud portal — **always** create with `--secret true` |

**Required (with recommended defaults):**

| Named Value                                | Default                                                | Secret? | Description                                                  |
|--------------------------------------------|--------------------------------------------------------|:-------:|--------------------------------------------------------------|
| `rdwr-app-ep-port`                         | `443`                                                  |    —    | SecurePath endpoint port                                     |
| `rdwr-app-ep-ssl`                          | `true`                                                 |    —    | Use HTTPS for sideband requests                              |
| `rdwr-app-ep-timeout-seconds`              | `10`                                                   |    —    | Sideband request timeout (seconds)                           |
| `rdwr-body-max-size-bytes`                 | `100000`                                               |    —    | Max request body forwarded to SecurePath                     |
| `rdwr-partial-body-size-bytes`             | `10240`                                                |    —    | Partial body size for oversized chunked requests             |
| `rdwr-multipart-max-size-bytes`            | `100000`                                               |    —    | Max multipart form-data body size                            |
| `rdwr-true-client-ip-header`               | `x-forwarded-for`                                      |    —    | Header containing the real client IP                         |
| `rdwr-api-base-path`                       | *(empty)*                                              |    —    | API base path to strip from sideband URI (e.g., `/api`)      |
| `rdwr-bot-manager-enabled`                 | `false`                                                |    —    | Enable Bot Manager cookie and header handling                |
| `plugin-version-info`                      | `700-v1.3.2`                                           |    —    | Plugin version string sent in `x-rdwr-plugin-info`           |
| `static-extensions-enabled`                | `true`                                                 |    —    | Enable static resource bypass                                |
| `static-list-of-methods-not-to-inspect`    | `GET,HEAD`                                             |    —    | HTTP methods eligible for static bypass                      |
| `static-list-of-bypassed-extensions`       | `png,jpg,css,js,gif,ico,svg,woff,woff2`                |    —    | File extensions to bypass                                    |
| `static-inspect-if-query-string-exists`    | `true`                                                 |    —    | Force inspection when a query string is present              |
| `chunked-request-allowed-content-types`    | `application/json,application/x-www-form-urlencoded`   |    —    | Content types eligible for chunked body forwarding           |
| `rdwr-inline-trusted-sources`              | *(empty)*                                              |    —    | Optional inline-bypass IP allow-list                         |
| `rdwr-inline-headers-enabled`              | `false`                                                |    —    | Optional inline-bypass header signature mode                 |

> Only `rdwr-api-key` should be created as a secret. The other Named Values are non-sensitive configuration and can be plain (this matters because secret Named Values cannot be referenced in trace output, which makes plain-Named-Value debugging easier).

#### Azure CLI examples

```bash
# Plain Named Value
az apim nv create --resource-group <rg> --service-name <apim> \
  --named-value-id rdwr-app-ep-addr \
  --display-name rdwr-app-ep-addr \
  --value "your-app-id.oop.radwarecloud.net"

# Secret Named Value — always use --secret true for the API key
az apim nv create --resource-group <rg> --service-name <apim> \
  --named-value-id rdwr-api-key \
  --display-name rdwr-api-key \
  --secret true \
  --value "your-api-key"
```

### Step 3 — Apply the Policy

Apply the XML policy at the **API level** (covers all operations) or per-operation as required.

**Via Azure Portal:**
1. Navigate to **APIM instance → APIs → [your API]**.
2. Select **All operations** (or a specific operation).
3. Open the **Policy code editor**.
4. Paste the contents of `rdwr-azureapim-securepath-connector-v1.3.xml`.
5. Click **Save**.

**Via Azure CLI:**
```bash
az apim api policy create-or-update \
  --resource-group <rg> \
  --service-name <apim> \
  --api-id <api-id> \
  --xml-policy @rdwr-azureapim-securepath-connector-v1.3.xml
```

### Step 4 — Verify

```bash
# Send a benign test request
curl -v https://<apim-name>.azure-api.net/<api-path>/ \
  -H "Ocp-Apim-Subscription-Key: <subscription-key>"
```

Expected: `HTTP 200` from the backend, indicating the request was inspected and allowed.

```bash
# Trigger a block — embed a typical SQL injection probe in the query string
curl -v "https://<apim-name>.azure-api.net/<api-path>/?id=1' OR '1'='1" \
  -H "Ocp-Apim-Subscription-Key: <subscription-key>"
```

Expected: `HTTP 403` with the SecurePath block page, confirming the connector is enforcing verdicts.

To inspect the sideband flow in detail, enable APIM Tracing for one request and look at the `send-request` step — it will show the outgoing `x-rdwr-*` headers and the SecurePath verdict response.

### Step 5 — Uninstall / rollback (when needed)

If you need to remove the policy (e.g., during incident response or to revert to a prior version), there are two safe paths:

**Path A — disable inspection without removing the policy.** Set `rdwr-app-ep-addr` to an unreachable value or set `rdwr-app-ep-timeout-seconds` to `0`. The policy fails open on connection error / timeout, so traffic flows to the backend without inspection. This is **non-destructive** and reversible by editing the Named Value back. Useful when you want to keep the policy in place for fast re-enablement after a SecurePath-side incident.

**Path B — fully remove the policy.** Replace the policy XML with the APIM default scope policy.

Via Azure Portal:
1. Navigate to **APIM instance → APIs → [your API] → All operations → Policy code editor**.
2. Replace the policy body with the default APIM scope policy:
   ```xml
   <policies>
       <inbound><base /></inbound>
       <backend><base /></backend>
       <outbound><base /></outbound>
       <on-error><base /></on-error>
   </policies>
   ```
3. Click **Save**. Inspection stops immediately on the next request.

Via Azure CLI:
```bash
# Replace the SecurePath policy XML with the default scope policy
cat <<'EOF' > /tmp/default-scope-policy.xml
<policies>
    <inbound><base /></inbound>
    <backend><base /></backend>
    <outbound><base /></outbound>
    <on-error><base /></on-error>
</policies>
EOF

az apim api policy create-or-update \
  --resource-group <rg> \
  --service-name <apim> \
  --api-id <api-id> \
  --xml-policy @/tmp/default-scope-policy.xml
```

To verify the rollback worked:
```bash
curl -v "https://<apim-name>.azure-api.net/<api-path>/?id=1' OR '1'='1" \
  -H "Ocp-Apim-Subscription-Key: <subscription-key>"
```
Expected: `HTTP 200` (or whatever the backend returns) instead of `HTTP 403` — the SQL-injection probe is no longer blocked, confirming the connector is no longer in the request path.

The Named Values created in Step 2 do not need to be deleted — they are inert without the policy. Leave them in place if you might re-enable inspection later, or `az apim nv delete` them if doing a permanent removal.

---

## Configuration Reference

### Body Handling

The policy decides how to forward request bodies based on `Content-Length` and content type:

| Condition                                                            | Behaviour                                                |
|---------------------------------------------------------------------|----------------------------------------------------------|
| Content-Length ≤ `rdwr-body-max-size-bytes`                          | Full body forwarded                                      |
| Content-Length > `rdwr-body-max-size-bytes`                          | Body **not** forwarded (`Content-Length: 0` sent)        |
| Chunked (no Content-Length) + matching content type                  | Body forwarded up to `rdwr-partial-body-size-bytes`      |
| Chunked + non-matching content type                                  | No body forwarded                                        |
| `multipart/form-data`                                                | Body forwarded up to `rdwr-multipart-max-size-bytes`     |
| Body truncated                                                       | `x-rdwr-partial-body: true` header added                 |

### API Base Path Stripping

APIM prepends a base path (e.g., `/api`) to all operations. SecurePath expects the original URI without this prefix. Set `rdwr-api-base-path` to your API's base path (e.g., `/api`) and the policy strips it from the sideband URI.

### Static Bypass

When `static-extensions-enabled` is `true`, requests are skipped if **all three** conditions are met:
1. The HTTP method is in `static-list-of-methods-not-to-inspect` (e.g., `GET`, `HEAD`).
2. The URI ends with an extension in `static-list-of-bypassed-extensions` (e.g., `.png`, `.css`).
3. No query string is present (unless `static-inspect-if-query-string-exists` is `false`).

### Bot Manager Cookie Handling

When `rdwr-bot-manager-enabled` is `true`:
- BM cookies from SecurePath responses (`__uzm*`, `uzmcr`) are propagated to the client via `Set-Cookie` headers.
- `ShieldSquare-Response` is forwarded.
- The `uzmcr` header overrides block verdicts to support mobile redirect handling.
- BM cookies propagate on **all** verdict paths (allow, block, redirect).

### Response Logging

The response-phase log fires automatically whenever SecurePath returns:
- `x-rdwr-oop-id` — correlation UUID
- `x-rdwr-oop-log` — log mode (`2` = headers only, `3` = headers + body)
- `x-rdwr-oop-log-body` — body capture limit (e.g., `2k`)

The log is sent via `send-one-way-request` (fire-and-forget) in the outbound pipeline.

**Captured response metadata includes:**
- `x-rdwr-o2v-status` — origin response status code
- `x-rdwr-o2h-content-type` — origin Content-Type header
- `x-rdwr-o2h-rdwr-response` — connector disposition (`allowed` / `blocked`)
- Base64-encoded response body sample (mode 3 only, configurable size)

---

## Do's and Don'ts

### Do
- ✅ **Store `rdwr-api-key` as a secret Named Value** (`--secret true` in the CLI). Secret Named Values are masked in policy exports and traces.
- ✅ **Upload both root and intermediate CA certificates** before enabling the policy. The intermediate alone will fail the TLS handshake.
- ✅ **Test in a non-production API first.** Apply the policy to a staging API, validate allow/block flows, then promote to production.
- ✅ **Set `rdwr-app-ep-timeout-seconds` to a value you can tolerate as worst-case latency.** The default of `10s` is safe; reduce it for latency-sensitive APIs.
- ✅ **Set `rdwr-api-base-path`** to match your APIM API's base path so SecurePath sees the correct URI.
- ✅ **Use APIM Tracing** for one-off troubleshooting. The trace shows the full sideband request and SecurePath response.
- ✅ **Monitor APIM `BackendDuration` and policy execution time** in Application Insights or Azure Monitor — sideband adds inspection latency proportional to network distance to the SecurePath region.
- ✅ **Update `plugin-version-info`** when you upgrade the policy XML so the SecurePath portal reports the correct connector version.

### Don't
- ❌ **Don't commit the API key to source control** — even in IaC files. Use Azure Key Vault references or pipeline secrets.
- ❌ **Don't apply this policy at the global / All-APIs level** unless you intend every API to be inspected. Apply at the API or operation level for finer control.
- ❌ **Don't combine this policy with another policy that modifies request bodies** before the sideband call. Body modifications upstream will be sent to SecurePath, which may produce unexpected verdicts.
- ❌ **Don't disable `ignore-error`** on the sideband `send-request`. It guarantees fail-open behaviour. Disabling it makes SecurePath unavailability customer-impacting.
- ❌ **Don't allow client-supplied `x-rdwr-*` headers** to reach this policy untouched from upstream proxies. The reserved-header check returns 403 by design — this is a security feature, not a bug.
- ❌ **Don't reduce `rdwr-app-ep-timeout-seconds` below `2`** unless you have measured your typical SecurePath round-trip latency. Aggressive timeouts cause spurious fail-open traffic.
- ❌ **Don't skip the CA certificate upload step.** TLS handshake failures will fail the sideband call and trigger fail-open on every request.
- ❌ **Don't edit the `<choose>` verdict logic** in the XML unless you understand the SecurePath verdict semantics. Verdict misclassification can cause bypass of legitimate blocks.

---

## Sideband Headers

The policy sends the following headers in every sideband request to SecurePath:

| Header                       | Description                                                                  |
|------------------------------|------------------------------------------------------------------------------|
| `x-rdwr-app-id`              | Application identifier                                                       |
| `x-rdwr-api-key`             | API key for authentication                                                   |
| `x-rdwr-connector-ip`        | Client IP, taken from `rdwr-true-client-ip-header` if present                |
| `x-rdwr-connector-port`      | Always `443` (Azure APIM ingress)                                            |
| `x-rdwr-connector-scheme`    | Always `https` (Azure forces HTTPS termination)                              |
| `x-rdwr-host`                | Original `Host` header from the client request                               |
| `x-rdwr-plugin-info`         | Connector platform and version (e.g., `700-v1.3.1`)                          |
| `x-rdwr-partial-body`        | `true` when the body was truncated due to size limits                        |
| `x-rdwr-connector-proto`     | `2` in the response-phase log                                                |
| `x-rdwr-connector-stage`     | `request` (sideband) or `log` (response-phase)                               |
| `x-rdwr-o2h-rdwr-response`   | `allowed` or `blocked` — connector disposition (response-phase log only)     |

---

## Security Notes

### Reserved Header Stripping
The policy returns `HTTP 403` for any incoming client request containing these headers (because they would otherwise allow a client to spoof inspection metadata):
- `x-rdwr-app-id`, `x-rdwr-api-key`, `x-rdwr-connector-ip`, `x-rdwr-partial-body`, `x-rdwr-cdn-ip`, `x-rdwr-ip`

### Fail-Open Behaviour
If the sideband request to SecurePath times out or fails, the policy allows the request to proceed to the backend. Set a strict `rdwr-app-ep-timeout-seconds` to control worst-case latency exposure.

### API Key Handling
Always store `rdwr-api-key` as a **secret** Named Value. Secret Named Values are masked in policy exports, traces, and the Azure Portal UI.

---

## Known Platform Constraints

| Constraint                                              | Impact                                                            | Mitigation                                                                         |
|---------------------------------------------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------|
| No response body modification                           | JavaScript injection verdicts cannot be enforced                  | Minimal — APIM serves API traffic (JSON/XML), not browser-rendered HTML            |
| `x-rdwr-connector-scheme` is always `https`             | Cosmetic only — Azure forces HTTPS                                | None needed                                                                        |
| No dedicated path proxying within a single XML policy   | BM browser-fingerprinting paths cannot be served from the policy  | Configure `/18f5.../` and `/c99a.../` as separate API operations pointing to SP    |
| `send-one-way-request` returns no response              | Response-phase log success cannot be checked from policy          | Monitor SecurePath portal for log ingestion correlation                            |
| APIM expression sandbox limits .NET APIs                | Some advanced parsing (e.g., regex) is unavailable                | None — the policy is written within sandbox limits                                 |

---

## Troubleshooting

### Requests return 403 unexpectedly
- Check whether the client (or an upstream proxy) is sending `x-rdwr-*` headers — the policy returns 403 by design when these are present.
- Verify the `rdwr-app-id` and `rdwr-api-key` Named Values match the values shown in the Radware Cloud portal.
- Enable APIM Tracing for one request and inspect the SecurePath sideband response body for the verdict reason.

### Sideband requests fail with TLS errors
- Confirm both `rdwr-root-ca.pem` and `rdwr-intermediate-ca.pem` are uploaded to the APIM CA store.
- If your network uses a TLS-inspecting proxy (e.g., Zscaler), upload that proxy's root CA to the APIM CA store as well.
- Verify outbound port 443 connectivity from the APIM VNet to `*.oop.radwarecloud.net`.

### Sideband requests time out
- Increase `rdwr-app-ep-timeout-seconds` (default `10`).
- Verify there are no NSG, firewall, or routing rules blocking egress from APIM to SecurePath.
- Check the SecurePath status page for service availability in your region.

### Named Values not resolving
- Named Values use double-brace syntax: `{{rdwr-app-id}}`.
- Confirm each Named Value exists and is not disabled.
- Secret Named Values are masked in the policy editor but resolve correctly at runtime.

### Body not forwarded to SecurePath
- Check `rdwr-body-max-size-bytes` — bodies larger than this are skipped (this is intentional).
- For chunked requests, ensure the `Content-Type` is in `chunked-request-allowed-content-types`.
- Set `rdwr-api-base-path` correctly so SecurePath sees the right URI path.

### Response-phase log not arriving in SecurePath portal
- Confirm `rdwr-bot-manager-enabled` and the response-logging Named Values are configured.
- Verify SecurePath returned `x-rdwr-oop-id` in the sideband response — without it, the log is not emitted.
- `send-one-way-request` is fire-and-forget; failures are not visible in APIM. Use SecurePath portal correlation as the source of truth.

---

## Version History

| Version    | Date       | Status      | Highlights                                                       |
|------------|------------|-------------|------------------------------------------------------------------|
| **v1.3.2** | 2026-05-03 | **Current** | `x-rdwr-o2v-bytes-sent` reports total wire bytes (not body alone) |
| v1.3.1     | 2026-03-31 | Superseded  | Disposition header, v2 log on block/redirect, body-truncation fix |
| v1.3.0     | 2026-03-12 | Superseded  | GA release, full feature parity, response-phase logging          |
| v1.2.0     | 2025-11-30 | Superseded  | Bot Manager support, reserved header enforcement                 |
| v1.1.0     | 2025-09-15 | Superseded  | Body handling, chunked request support                           |
| v1.0.0     | 2025-05-01 | Superseded  | Initial release                                                  |

For full release notes, see [`release-notes.md`](release-notes.md).

---

## Repository Structure

```
rdwr-azureapim-securepath-connector/
├── README.md                                         # This file
├── release-notes.md                                  # Detailed release notes
├── rdwr-azureapim-securepath-connector-v1.3.xml      # The policy XML
├── certs/                                            # Radware CA chain + upload guide
│   ├── README.md
│   ├── rdwr-root-ca.pem
│   ├── rdwr-intermediate-ca.pem
│   └── rdwr-ca-chain.pem
└── .gitignore
```

---

## License

Copyright © 2024–2026 Radware Ltd. All rights reserved.

Proprietary and confidential. Unauthorized copying, distribution, or use of this software is strictly prohibited.
