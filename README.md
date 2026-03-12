# Radware SecurePath Connector for Azure API Management

An XML policy that integrates [Radware SecurePath](https://www.radware.com/products/securepath/) with [Azure API Management (APIM)](https://learn.microsoft.com/en-us/azure/api-management/), providing real-time WAF and Bot Manager protection for APIs.

## How It Works

For every incoming API request, the policy:

1. **Intercepts** the request in APIM's inbound pipeline
2. **Sends a sideband copy** to the SecurePath cloud service via `send-request` (with `x-rdwr-*` headers)
3. **Receives a verdict** (allow, block, redirect, or challenge)
4. **Enforces the verdict** before forwarding to the backend

```
Client ──> Azure APIM ──> [SecurePath Policy] ──> Backend API
                                  │
                                  ├── send-request ──> SecurePath Cloud
                                  │                        │
                                  │<── Verdict ────────────┘
                                  │
                            Enforce verdict:
                            allow → forward to backend
                            block → return 403 (HTML or JSON)
                            redirect → 302 to challenge page
```

In the **outbound** pipeline, the policy optionally sends a fire-and-forget response-phase log back to SecurePath for analytics correlation.

## Capabilities

### Application Protection
- Full sideband request assembly with all required `x-rdwr-*` headers
- Verdict enforcement: allow, block (HTML + JSON), 301/302 redirect
- Fail-open mode (default): traffic flows to backend if SecurePath is unreachable
- Reserved header security: rejects (403) client requests containing spoofed `x-rdwr-*` headers
- Static resource bypass: skip inspection for configured file extensions and HTTP methods
- Request body handling with configurable size limits and partial body forwarding
- Multipart form-data body support with separate size limit
- Chunked request body forwarding for configured content types
- Client IP detection via configurable header (e.g., `X-Forwarded-For`)
- API base path stripping for correct URI forwarding to SecurePath

### Bot Manager Support
- Bot Manager cookie propagation (`__uzma`, `__uzmb`, `__uzmc`, `__uzmd`, `__uzmf`, `uzmcr`) on all verdict paths
- `ShieldSquare-Response` header forwarding
- `uzmcr` header detection for mobile redirect exception handling
- Invalid API key detection (`wrong-api-key.oop.radwarecloud.com`) with fail-open

> **Note:** APIM cannot perform JavaScript injection into response bodies. This is an inherent platform limitation — XML policies have no response body modification capability. This has minimal practical impact because APIM is an API gateway; traffic is typically JSON/XML consumed by backend services, not HTML rendered in browsers. Bot Manager browser fingerprinting targets `</head>` in browser-rendered HTML, which is not relevant for API consumers.

### Response Logging and Analytics
- **Response Logging**: Fire-and-forget (`send-one-way-request`) POSTs origin response metadata back to SecurePath correlated via `x-rdwr-oop-id` — near-zero client latency
- Response body capture with configurable size limits (base64-encoded, mode 3)
- Always-on when SecurePath returns control headers (no configuration gate needed)

## Prerequisites

- **Azure API Management** instance (any tier: Developer, Basic, Standard, Premium, v2)
- **A Radware SecurePath application** configured in the [Radware Cloud portal](https://portal.radwarecloud.com)
- Outbound HTTPS connectivity from APIM to SecurePath (port 443)

## Project Structure

```
rdwr-azureapim-securepath-connector/
├── README.md                                          # This file
├── rdwr-azureapim-securepath-connector-v1.3.xml       # The policy XML
└── .gitignore
```

## Deployment

### Step 1: Create Named Values

The policy reads all configuration from APIM [Named Values](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-properties). Create these in your APIM instance:

**Required:**

| Named Value | Example | Description |
|-------------|---------|-------------|
| `rdwr-app-ep-addr` | `your-app-id.oop.radwarecloud.net` | SecurePath endpoint hostname |
| `rdwr-app-id` | `your-app-id` | Application ID from Radware Cloud portal |
| `rdwr-api-key` | `your-api-key` | API key from Radware Cloud portal |

**Required (with defaults):**

| Named Value | Default | Description |
|-------------|---------|-------------|
| `rdwr-app-ep-port` | `443` | SecurePath endpoint port |
| `rdwr-app-ep-ssl` | `true` | Use HTTPS for sideband requests |
| `rdwr-app-ep-timeout-seconds` | `10` | Sideband request timeout |
| `rdwr-body-max-size-bytes` | `100000` | Max request body sent to SecurePath |
| `rdwr-partial-body-size-bytes` | `10240` | Partial body size for oversized requests |
| `rdwr-multipart-max-size-bytes` | `100000` | Max multipart form-data body size |
| `rdwr-true-client-ip-header` | `x-forwarded-for` | Header containing the real client IP |
| `rdwr-api-base-path` | *(empty)* | API base path to strip from sideband URI (e.g., `/api`) |
| `rdwr-bot-manager-enabled` | `false` | Enable Bot Manager cookie/header handling |
| `plugin-version-info` | `700-v1.3.0` | Plugin version string for sideband |
| `static-extensions-enabled` | `true` | Enable static resource bypass |
| `static-list-of-methods-not-to-inspect` | `GET,HEAD` | HTTP methods for static bypass |
| `static-list-of-bypassed-extensions` | `png,jpg,css,js,gif,ico,svg,woff,woff2` | Extensions to bypass |
| `static-inspect-if-query-string-exists` | `true` | Force inspection when query string present |
| `chunked-request-allowed-content-types` | `application/json,application/x-www-form-urlencoded` | Content types for chunked body forwarding |

You can create these via the Azure Portal, Azure CLI, or Terraform:

```bash
# Azure CLI example
az apim nv create --resource-group <rg> --service-name <apim> \
  --named-value-id rdwr-app-ep-addr \
  --display-name rdwr-app-ep-addr \
  --value "your-app-id.oop.radwarecloud.net"

az apim nv create --resource-group <rg> --service-name <apim> \
  --named-value-id rdwr-app-id \
  --display-name rdwr-app-id \
  --value "your-app-id"

# Use --secret for sensitive values
az apim nv create --resource-group <rg> --service-name <apim> \
  --named-value-id rdwr-api-key \
  --display-name rdwr-api-key \
  --value "your-api-key" --secret true
```

### Step 2: Apply the Policy

Apply the XML policy at the **API level** (covers all operations) or per-operation:

**Via Azure Portal:**
1. Navigate to your APIM instance > APIs > your API
2. Click "All operations" (or a specific operation)
3. Open the "Policy code editor" (inbound + outbound)
4. Paste the contents of `rdwr-azureapim-securepath-connector-v1.3.xml`
5. Save

**Via Azure CLI:**
```bash
az apim api policy create-or-update \
  --resource-group <rg> \
  --service-name <apim> \
  --api-id <api-id> \
  --xml-policy @rdwr-azureapim-securepath-connector-v1.3.xml
```

### Step 3: Verify

```bash
# Send a test request
curl -v https://<apim-name>.azure-api.net/<api-path>/ \
  -H "Ocp-Apim-Subscription-Key: <your-subscription-key>"
```

Check the APIM trace logs or Application Insights for SecurePath sideband activity.

## Configuration Reference

### Body Handling

The policy handles request bodies based on Content-Length and content type:

| Condition | Behavior |
|-----------|----------|
| Content-Length <= `rdwr-body-max-size-bytes` | Full body forwarded to SecurePath |
| Content-Length > `rdwr-body-max-size-bytes` | Body NOT forwarded (`Content-Length: 0` sent) |
| Chunked (no Content-Length) + matching content type | Body forwarded up to `rdwr-partial-body-size-bytes` |
| Chunked + non-matching content type | No body forwarded |
| Multipart/form-data | Body forwarded up to `rdwr-multipart-max-size-bytes` |
| Body truncated | `x-rdwr-partial-body: true` header added |

### API Base Path Stripping

APIM prepends a base path (e.g., `/api`) to all operations. SecurePath expects the original URI without this prefix. Set `rdwr-api-base-path` to your API's base path (e.g., `/api`) and the policy strips it from the sideband URI.

### Static Bypass

When `static-extensions-enabled` is `true`, requests are skipped if:
1. HTTP method is in `static-list-of-methods-not-to-inspect` (e.g., GET, HEAD)
2. URI has an extension in `static-list-of-bypassed-extensions` (e.g., .png, .css)
3. No query string present (unless `static-inspect-if-query-string-exists` is `false`)

### Bot Manager Cookie Handling

When `rdwr-bot-manager-enabled` is `true`:
- BM cookies from SecurePath responses (`__uzm*`, `uzmcr`) are propagated to the client via `Set-Cookie`
- `ShieldSquare-Response` header is forwarded
- `uzmcr` header presence overrides block verdicts for mobile redirect handling
- BM cookies propagate on ALL verdict paths (allow, block, redirect) — matching NGINX behavior

### Response Logging

The response-phase log fires automatically when SecurePath returns:
- `x-rdwr-oop-id` — correlation UUID
- `x-rdwr-oop-log` — log mode (2 = headers only, 3 = headers + body)
- `x-rdwr-oop-log-body` — body capture limit (e.g., "2k")

The log is sent via `send-one-way-request` (fire-and-forget) in the outbound pipeline, adding near-zero client latency.

**Captured response metadata:**
- `x-rdwr-o2v-status` — origin response status code
- `x-rdwr-o2h-content-type` — origin Content-Type header
- Base64-encoded response body sample (mode 3 only, configurable limit)

## Sideband Headers

The policy sends these headers to SecurePath:

| Header | Description |
|--------|-------------|
| `x-rdwr-app-id` | Application identifier |
| `x-rdwr-api-key` | API key for authentication |
| `x-rdwr-connector-ip` | Client IP (from configured header) |
| `x-rdwr-connector-port` | Always `443` (Azure infrastructure) |
| `x-rdwr-connector-scheme` | Always `https` (Azure infrastructure forces HTTPS) |
| `x-rdwr-host` | Original Host header from the client request |
| `x-rdwr-plugin-info` | Connector version (e.g., `700-v1.3.0`) |
| `x-rdwr-partial-body` | `true` when body is truncated |
| `x-rdwr-connector-proto` | `2` in response-phase log |
| `x-rdwr-connector-stage` | `request` (sideband) or `log` (response phase) |

## Security

### Reserved Header Stripping
The policy rejects (403) any incoming client request containing these headers:
- `x-rdwr-app-id`, `x-rdwr-api-key`, `x-rdwr-connector-ip`, `x-rdwr-partial-body`, `x-rdwr-cdn-ip`, `x-rdwr-ip`

### Fail-Open Behavior
If the sideband request to SecurePath times out or fails, the policy allows the request to proceed to the backend (fail-open). This is the default behavior — set a strict timeout via `rdwr-app-ep-timeout-seconds` to control worst-case latency.

### API Key Security
Store `rdwr-api-key` as a **secret** Named Value in APIM to prevent exposure in policy exports and traces.

## Known Platform Limitations

| Limitation | Impact | Workaround |
|-----------|--------|------------|
| No response body modification | Cannot inject Bot Manager JavaScript | Minimal — APIM handles API traffic (JSON/XML), not browser HTML |
| `x-rdwr-connector-scheme` always `https` | Cosmetic — Azure forces HTTPS | None needed |
| No dedicated path proxying (`/18f5.../`, `/c99a.../`) | BM browser fingerprinting via dedicated paths unavailable | Add as separate API operations with backend pointing to SecurePath |

## Troubleshooting

**Requests return 403 unexpectedly:**
- Check if the client is sending `x-rdwr-*` headers (the policy blocks these)
- Verify Named Values `rdwr-app-id` and `rdwr-api-key` are correct
- Check APIM trace logs for SecurePath sideband response details

**Sideband request failing:**
- Verify outbound connectivity from APIM to SecurePath (port 443)
- Check `rdwr-app-ep-addr` Named Value is correct
- Increase `rdwr-app-ep-timeout-seconds` if seeing timeouts

**Named Value not resolving:**
- Named Values use double-brace syntax: `{{rdwr-app-id}}`
- Ensure the Named Value exists and is not disabled
- Secret Named Values won't show in policy editor but will resolve at runtime

**Body not forwarded to SecurePath:**
- Check `rdwr-body-max-size-bytes` — bodies larger than this are skipped
- For chunked requests, ensure the Content-Type is in `chunked-request-allowed-content-types`
- Check `rdwr-api-base-path` if SecurePath sees wrong URI paths

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.3.0 | 2026-03 | Response-phase logging via `send-one-way-request`, partial body size support, multipart body handling, API base path stripping, Bot Manager cookie propagation on all verdict paths, custom block page support, comprehensive Named Values configuration |
| 1.2.0 | 2025-11 | Bot Manager cookie/header handling, reserved header security, static bypass, sideband Host header override for Azure Web Apps |
| 1.1.0 | 2025-09 | Body handling improvements, chunked request support |
| 1.0.0 | 2025-05 | Initial release — basic sideband and verdict enforcement |

## License

Copyright (c) 2024-2026 Radware Ltd. All rights reserved.

Proprietary and confidential. Unauthorized copying, distribution, or use of this software is strictly prohibited.
