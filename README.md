# Radware SecurePath Connector for Azure API Management

The SecurePath connector adds Radware Cloud WAF and Bot Manager protection to Azure API Management (APIM). Every request your APIs serve is inspected by SecurePath before it reaches your backend, with allow / block / redirect verdicts enforced at the gateway. The connector is delivered as a **single XML policy file** that runs entirely inside APIM's policy pipeline — no custom C# code, no Functions, no sidecars, no separate compute.

| What you get | Where it shows up |
|--------------|-------------------|
| **WAF** — SQL-injection / XSS / RFI / file-upload / path traversal blocking, plus the rest of the SecurePath rule set | HTTP 403 to the client with SecurePath's block page (HTML) or structured block JSON |
| **Redirect / challenge** — risk-based redirects to a SecurePath-issued challenge URL | HTTP 301/302 to the client |
| **Bot Manager** — BM cookie propagation (`__uzma`, `__uzmf`, `uzmcr`, etc.) and `ShieldSquare-Response` forwarding on every verdict path | `Set-Cookie` and BM headers on the client response (allow, block, redirect alike) |
| **Response-phase analytics (v2)** — fire-and-forget log POST after every response, with disposition header (`allowed` / `blocked`) | Visible in the Radware Cloud "events" view; near-zero client-visible latency |
| **Reserved header security** — rejects (HTTP 403) any client request that contains spoofed `x-rdwr-*` headers | 403 returned at the gateway, request never forwarded |
| **Static-asset bypass** — configured methods + extensions skip inspection | Lower per-request cost on cacheable static traffic |
| **Fail-open by default** — if SecurePath is unreachable, traffic continues to your backend | Configurable via Named Values |

**Is this for you?** If you run Azure API Management (any tier — Developer, Basic, Standard, Premium, v2, with caveats for Consumption) and have (or want) a Radware Cloud SecurePath subscription. If your gateway is something else — Kong, NGINX, MuleSoft Flex Gateway, F5, HAProxy, Envoy — Radware ships a separate connector for each; this repo is APIM only.

> **What APIM does NOT do — JavaScript injection.** APIM XML policies cannot modify response bodies, so the Bot Manager browser-fingerprinting JS injection that other SecurePath connectors do is not available here. This is rarely an issue: APIM is an API gateway, so the traffic is typically JSON / XML / gRPC consumed by backend services, not HTML rendered in browsers. Bot Manager cookie propagation (the part that matters for non-browser clients) works in full.

---

## Architecture

```
        ┌──────────────────┐
        │  Client request  │  (Host: api.example.com, /v1/orders, ...)
        └────────┬─────────┘
                 │ HTTPS (Azure-terminated)
                 ▼
        ┌──────────────────────────────────────────┐
        │  Azure API Management gateway            │
        │                                          │
        │  ┌────────────────────────────────────┐  │
        │  │ <inbound> SecurePath policy        │  │      ┌────────────────┐
        │  │   • build sideband request         │  │      │  SecurePath    │
        │  │   • send-request to SP   ──────────┼──┼─────▶│  Cloud         │
        │  │   • parse verdict        ◀─────────┼──┼──────│  endpoint      │
        │  │   • allow / block / redirect       │  │      └────────────────┘
        │  └────────────────────────────────────┘  │              ▲
        │                                          │              │ async
        │  ┌────────────────────────────────────┐  │              │ log POST
        │  │ <outbound> response-phase log      │  │              │
        │  │   • send-one-way-request to SP ────┼──┼──────────────┘
        │  └────────────────────────────────────┘  │
        └─────────────────┬────────────────────────┘
                          │ allowed → forward
                          ▼
        ┌──────────────────────────────────────────┐
        │  Your backend (App Service, AKS, AWS,    │
        │  on-prem, function app, anything APIM    │
        │  can reach)                              │
        └──────────────────────────────────────────┘
```

For each client request, APIM:

1. Runs the SecurePath policy in the **inbound** pipeline.
2. The policy assembles the SecurePath sideband headers (`x-rdwr-app-id`, `x-rdwr-api-key`, `x-rdwr-connector-ip`, etc.) and dispatches an HTTPS sideband request to your SecurePath application's endpoint via APIM's `<send-request>` policy.
3. SecurePath returns a verdict (`allow`, `block`, `redirect`, or challenge).
4. The policy enforces the verdict — forward to backend, return 403 with a block page, or 302 to a challenge URL.
5. After the response is delivered to the client, the **outbound** pipeline fires an asynchronous v2 response-phase log POST to SecurePath via `<send-one-way-request>`. This is fire-and-forget and adds no client-visible latency.

The policy is **stateless**. All configuration lives in APIM Named Values, read fresh on every request. Multi-region APIM, multi-zone APIM, scale-out APIM — all work the same way.

---

## Quickstart (~15 minutes, end-to-end)

The fastest path from "we have an APIM instance" to "SecurePath is inspecting traffic." All commands assume Azure CLI; the Portal-equivalent steps are documented in the same section below.

> **You'll need:** an APIM instance you can edit, an active SecurePath application in the [Radware Cloud portal](https://portal.radwarecloud.com) (with the Application ID, API key, and `*.oop.radwarecloud.net` endpoint hostname handy), and Azure CLI signed in.

**1. Upload the Radware CA chain** so APIM can verify SecurePath's TLS cert. Both certs are required (root + intermediate):

```bash
az apim certificate create \
  --resource-group <rg> --service-name <apim> \
  --certificate-id rdwr-root-r1 \
  --certificate-path certs/rdwr-root-ca.pem

az apim certificate create \
  --resource-group <rg> --service-name <apim> \
  --certificate-id rdwr-ca-1a1 \
  --certificate-path certs/rdwr-intermediate-ca.pem
```

**2. Create the three required Named Values:**

```bash
RG=<your-resource-group>
APIM=<your-apim-instance>

az apim nv create -g $RG --service-name $APIM \
  --named-value-id rdwr-app-ep-addr  --display-name rdwr-app-ep-addr \
  --value "<your-app-id>.oop.radwarecloud.net"

az apim nv create -g $RG --service-name $APIM \
  --named-value-id rdwr-app-id       --display-name rdwr-app-id \
  --value "<your-app-id>"

az apim nv create -g $RG --service-name $APIM \
  --named-value-id rdwr-api-key      --display-name rdwr-api-key \
  --secret true \
  --value "<your-api-key>"
```

**3. Apply the policy** to the API you want to protect (typically all operations):

```bash
az apim api policy create-or-update \
  --resource-group $RG \
  --service-name $APIM \
  --api-id <your-api-id> \
  --xml-policy @rdwr-azureapim-securepath-connector-v1.3.xml
```

**4. Smoke-test:**

```bash
# Should pass — request reaches your backend
curl -i https://$APIM.azure-api.net/<api-path>/health \
  -H "Ocp-Apim-Subscription-Key: <key>"
# Expected: HTTP 200 from your backend.

# Should be blocked — SQL-injection probe in query string
curl -i "https://$APIM.azure-api.net/<api-path>/?id=1' OR '1'='1" \
  -H "Ocp-Apim-Subscription-Key: <key>"
# Expected: HTTP 403 with the SecurePath block page.
```

If both checks pass, the connector is working end-to-end. The deeper walkthrough — every Named Value, deployment-shape caveats, configuration details, troubleshooting, and uninstall procedure — lives in [Onboarding Walkthrough](#onboarding-walkthrough) below.

---

## Deployment shapes — does this work in MY APIM?

The same policy XML works across every APIM deployment shape. Where the shapes differ is in **what you need to do operationally** to give APIM outbound network reach to SecurePath:

| APIM shape | Status | What you need to do |
|------------|:------:|---------------------|
| **Developer / Basic / Standard / Premium** (the v1 family) | ✅ Fully supported | Standard onboarding — ensure outbound 443 to `*.oop.radwarecloud.net` works (it does by default unless you've added route-table restrictions). |
| **Standard v2 / Premium v2** | ✅ Fully supported | Same as v1. The v2 family uses an updated runtime but the same policy engine. |
| **Consumption tier** | ⚠️ Partial | Consumption-tier APIM imposes [policy-expression and execution limits](https://learn.microsoft.com/en-us/azure/api-management/api-management-features) — large-body buffering is limited and some advanced expressions are not available. The policy degrades gracefully (sideband and verdict enforcement still work; some edge-case headers and the inline-bypass IP allow-list are skipped). **Test in Consumption** before committing to it for production. |
| **Self-hosted gateway** | ✅ Supported | The Self-Hosted Gateway uses the same policy engine as cloud APIM. The `<send-one-way-request>` log POST runs from the self-hosted node — make sure that node has outbound 443 to `*.oop.radwarecloud.net` and the Radware CA in its trust store. |
| **Internal VNet (stv2 / Premium internal mode)** | ✅ Supported | The APIM gateway must have outbound network access to `*.oop.radwarecloud.net`. If your subnet route-tables / Azure Firewall / NSGs force-tunnel internet egress, explicitly allow the SecurePath endpoint FQDN. The `Microsoft.Web` service tag is **not** sufficient — SecurePath endpoints don't sit inside that tag's IP ranges. |
| **Custom domains and backend mTLS** | ✅ Independent | The connector operates on the APIM-side request/response pipeline. Backend mTLS, custom domains, and gateway certificates do not interact with the SecurePath sideband. |

### Latency expectations

The sideband request adds approximately **20–80 ms** of synchronous overhead per request (median ~30 ms; p99 < 100 ms over public-internet egress to the closest SecurePath PoP). The default `rdwr-app-ep-timeout-seconds` is `10`, so a slow PoP causes at most a 10-second stall before the policy **fails open** and forwards the request to the backend.

The response-phase log uses `<send-one-way-request>`, which is fire-and-forget — it adds no measurable client-visible latency on the response path.

---

## What's in this repo

| Path | Purpose |
|------|---------|
| `rdwr-azureapim-securepath-connector-v1.3.xml` | The policy XML you apply to your APIM API |
| `release-notes.md` | Per-version release notes — what changed, when |
| `certs/rdwr-root-ca.pem` | Radware Root CA — upload to APIM CA store |
| `certs/rdwr-intermediate-ca.pem` | Radware Intermediate CA — upload to APIM CA store |
| `certs/rdwr-ca-chain.pem` | Combined chain (informational; APIM needs them uploaded individually) |
| `certs/README.md` | CA upload guide for Portal / CLI / ARM-Bicep |

---

## Onboarding Walkthrough

The full step-by-step. Pick the path that matches your tooling.

### Step 1 — Upload the Radware CA chain to APIM

The SecurePath endpoint (`*.oop.radwarecloud.net`) is signed by a private Radware CA. APIM must trust the chain before sideband calls will succeed.

**Via Portal:**
1. Open the Azure Portal, navigate to your APIM instance.
2. Go to **Security → CA certificates** and click **+ Add**.
3. Upload `certs/rdwr-root-ca.pem` — name it `rdwr-root-r1`.
4. Click **+ Add** again and upload `certs/rdwr-intermediate-ca.pem` — name it `rdwr-ca-1a1`.

**Via Azure CLI:** see the Quickstart above.

Both certificates are required. ARM/Bicep equivalents are documented in `certs/README.md`.

### Step 2 — Create Named Values

The policy reads all configuration from APIM [Named Values](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-properties). Create them via the Azure Portal, Azure CLI, or your IaC tool of choice.

**Required (no defaults — must be set per environment):**

| Named Value       | Example                              | Secret? | Description                                     |
|-------------------|--------------------------------------|:-------:|-------------------------------------------------|
| `rdwr-app-ep-addr`| `your-app-id.oop.radwarecloud.net`   |    —    | SecurePath endpoint hostname                    |
| `rdwr-app-id`     | `your-app-id`                        |    —    | Application ID from the Radware Cloud portal    |
| `rdwr-api-key`    | `your-api-key`                       |  **✓**  | API key from the Radware Cloud portal — **always** create with `--secret true` |

**Required (with recommended defaults — already wired in the policy XML):**

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
- `x-rdwr-o2v-bytes-sent` — total wire bytes (status line + headers + body, matching NGINX `$bytes_sent` semantics; v1.3.2 fix)
- `x-rdwr-o2v-body-bytes-sent` — body bytes only (matching NGINX `$body_bytes_sent`)
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
| `x-rdwr-plugin-info`         | Connector platform and version (default `700-v1.3.2`)                        |
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

## Where to go next

| You want to | Read |
|-------------|------|
| Get something running | The [Quickstart](#quickstart-15-minutes-end-to-end) at the top |
| See every config knob | [Configuration Reference](#configuration-reference) |
| Understand tier / VNet / Consumption / self-hosted differences | [Deployment shapes](#deployment-shapes--does-this-work-in-my-apim) |
| Roll back or disable the connector | Step 5 — [Uninstall / rollback](#step-5--uninstall--rollback-when-needed) |
| Debug something that's not working | [Troubleshooting](#troubleshooting) |
| See what changed between versions | [release-notes.md](release-notes.md) |

For SecurePath-account questions (provisioning, billing, application configuration on the SecurePath side) contact your Radware account team. For connector bugs and feature requests, file an issue on this GitHub repo.

---

## Version History

| Version    | Date       | Status      | Highlights                                                       |
|------------|------------|-------------|------------------------------------------------------------------|
| **v1.3.2** | 2026-05-03 | **Current** | `x-rdwr-o2v-bytes-sent` reports total wire bytes (status line + headers + body) |
| v1.3.1     | 2026-03-31 | Superseded  | Disposition header, v2 log on block/redirect, body-truncation fix |
| v1.3.0     | 2026-03-12 | Superseded  | GA release, full SecurePath feature coverage, response-phase logging |
| v1.2.0     | 2025-11-30 | Superseded  | Bot Manager support, reserved header enforcement                 |
| v1.1.0     | 2025-09-15 | Superseded  | Body handling, chunked request support                           |
| v1.0.0     | 2025-05-01 | Superseded  | Initial release                                                  |

For full release notes, see [`release-notes.md`](release-notes.md).

---

## License

Copyright © 2024–2026 Radware Ltd. All rights reserved.

Proprietary and confidential. Unauthorized copying, distribution, or use of this software is strictly prohibited.
