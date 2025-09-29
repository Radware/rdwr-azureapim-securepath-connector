# Azure APIM Policy for Radware SecurePath Integration

This document describes an Azure API Management (APIM) policy designed to integrate with a Radware SecurePath (Cloud WAAP) endpoint. The policy acts as a connector, sending incoming API requests to the Radware endpoint for security inspection before allowing them to proceed to the backend service.

**Current Version:** 1.1.0  

---

## Changelog (since 1.0.0)
- 1.1.0: Added optional Inline Bypass Mode for hybrid architectures (inline WAAP + APIM sideband).
- Added two optional Named Values:
  - `rdwr-inline-trusted-sources` (comma IP / CIDR list)
  - `rdwr-inline-headers-enabled` ("true"/"false")
- Added reserved header enforcement skip when inline bypass active.
- Added diagnostics variable `radwareDiag` documentation.
- Documentation of partial body, static bypass precedence, and security hardening.

---

## Purpose

The primary goal of this APIM policy is to integrate Radware's Cloud WAAP capabilities—including cutting-edge API security, discovery, and business logic attack protection, coupled with WAF protection and other advanced features—through Radware's SecurePath architecture. SecurePath allows for out-of-path integration, in this case, leveraging Azure API Management (APIM) as the enforcement point. This policy enables APIM to act as the connector, ensuring that API traffic is vetted by Radware before reaching backend services.

---

## Quick Start

1. **Create the required Named Values** listed in the tables below (Radware endpoint, credentials, request-body thresholds, bypass controls). Secrets such as `rdwr-api-key` should be stored as secret Named Values.
2. **Import the policy** from `rdwr-azureapim-securepath-connector.xml` into the *All operations* inbound pipeline of the APIM API that fronts your protected backend. The file is ready to paste into the policy editor.
3. **Configure backend routing per operation** (e.g., `<set-backend-service>` and `<rewrite-uri>` at the operation level) so that APIM forwards allowed requests to the correct upstream service.
4. **Verify connectivity** between APIM and the Radware SecurePath endpoint (outbound TCP 443/80 as appropriate) and confirm APIM trusts the Radware certificate chain.
5. **Exercise the API** using your preferred client (curl/Postman/APIM test console) to ensure:
   - Allowed requests reach the backend and return expected responses.
   - Blocked scenarios return Radware’s action response (403/redirect/etc.).
   - Optional bypass controls behave as intended (static assets, inline bypass).

The remainder of this document provides the detailed configuration reference for these steps.

---

## Features

- **Request Forwarding to Radware:**  
  Sends details of the original request (method, full original path & query, specific headers, and processed body) to the configured Radware SecurePath endpoint for deep inspection.

- **Client IP Handling:**
  - Defaults to using the immediate caller's IP address (`context.Request.IpAddress`).
  - Optionally allows specifying a request header (via the `rdwr-true-client-ip-header` Named Value) from which to extract the true client IP. This feature is activated if the Named Value is set to a valid header name; it's disabled if the Named Value is set to the placeholder string `##DISABLED##`.

- **Request Body Processing:**
  - Reads the request body for relevant content types and methods.
  - Respects a maximum body size (`rdwr-body-max-size-bytes`) for inspection.
  - Can send a partial body (`rdwr-partial-body-size-bytes`) to Radware if the original body exceeds the partial size but not the maximum size, setting the `X-Rdwr-Partial-Body` header.
  - Handles both `Content-Length` and `Transfer-Encoding: chunked` requests.

- **Static Content Bypass:**
  - Optionally bypasses Radware inspection for requests matching configured static file extensions and HTTP methods, unless a query string is present and configured to trigger inspection. The path used for this bypass check is relative to the APIM API's operation (e.g., `/items`).

- **Forbidden Header Check:**  
  Prevents client requests containing specific `x-rdwr-*` headers from proceeding.

- **Radware Response Handling:**
  - **Allowed Requests:** If Radware explicitly allows a request (e.g., HTTP 200 with `x-rdwr-oop-request-status: allowed` header), the request is forwarded to the backend service configured in APIM.
  - **Blocked/Action Taken by Radware:** If Radware returns any other status (e.g., 403) or does not explicitly allow the request, APIM will pass Radware's entire response (status, headers, and body) back to the original client.
  - **Redirects:** Handles 301/302 redirects from Radware, including a specific check for "wrong API key" redirects.
  - **Error Handling:** Provides basic error responses if APIM cannot communicate with the Radware endpoint (e.g., timeout, connection error).

- **Configuration via Named Values:**  
  All key parameters (Radware endpoint details, API keys, thresholds, feature flags) are managed via APIM Named Values for easy configuration without modifying the policy XML directly.

- **Reserved / Forbidden Header Enforcement (with Inline Bypass Awareness):**  
  Blocks requests that contain any of these headers (case-insensitive) unless inline bypass criteria were met earlier:
  `X-Rdwr-App-Id`, `X-Rdwr-Api-Key`, `X-Rdwr-Connector-Ip`, `X-Rdwr-Partial-Body`, `X-Rdwr-Cdn-Ip`, `X-Rdwr-Ip`.

- **Inline Bypass Mode (NEW):**  
  Allows traffic already inspected by an inline Radware WAAP (public edge) to safely bypass sideband inspection in APIM, avoiding double scanning while preserving protection for internal / direct traffic.

- **Fail-Open Strategy (Clarified):**  
  Only specific 200 responses with a non-`allowed` decision produce a 403. Almost all non-200 statuses from SecurePath (including 403, 5xx, 301/302) result in pass-through to the backend (availability bias).

---

## Radware Response Handling (Updated Logic Summary)

| SecurePath Response Pattern | Policy Action | Notes |
|-----------------------------|---------------|-------|
| 200 + `x-rdwr-oop-request-status: allowed` | Allow | Normal success |
| 200 + NOT allowed + `uzmcr` header present | Allow (fail-open) | Explicit pass-through override |
| 200 + NOT allowed + JSON body (`Content-Type: application/json...`) | 403 returned with that JSON body | Treated as explicit block |
| 200 + NOT allowed + Non-JSON | 403 with static HTML block page | Fallback block |
| 301 / 302 (any reason) | Allow (fail-open) | `radwareDiag=redirect_received_fallthrough` |
| Any other status (403, 4xx, 5xx, etc.) | Allow (fail-open) | `radwareDiag=non200_status_fallthrough` |
| Timeout / no response / network error | Allow (fail-open) | `radwareDiag=sideband_error_or_timeout` |

This differs from 1.0.0 documentation which implied non-200 blocks—now explicitly fail-open unless a block is conveyed via the 200 decision path.

---

## Inline Bypass Mode (Hybrid Deployment)  (NEW)

### When to Use
You run both:
1. Public ingress -> Inline Radware WAAP -> APIM -> Backend  
2. Internal / partner / east-west -> APIM -> Backend  

You want to avoid re-inspecting flow (1) while still inspecting flow (2).

### How It Works
The policy computes `isInlineBypass` before reserved header enforcement. If true, it sets `shouldBypassRadware=true`:
- Skips reserved header 403 enforcement for Radware headers legitimately injected inline.
- Skips the entire sideband (no body processing, no send-request call).
- Static bypass logic runs later but is irrelevant once `shouldBypassRadware` is already true.

### Decision Inputs
1. Presence (existence only) of a 5-header signature (case-insensitive):
   - `X-Rdwr-Ip`
   - `X-Rdwr-Port`
   - `X-Rdwr-Port-MM-Orig-FE-Port`
   - `X-Rdwr-Port-MM`
   - `X-Rdwr-App-Id`
2. Client socket IP matches any entry in `rdwr-inline-trusted-sources` (single IP or CIDR v4/v6).

### Configuration Matrix

| Headers Enabled? (`rdwr-inline-headers-enabled`) | IP List Configured? (`rdwr-inline-trusted-sources`) | Bypass Requires |
|--------------------------------------------------|-----------------------------------------------------|-----------------|
| Yes                                              | Yes                                                 | BOTH signature + IP match |
| Yes                                              | No (empty)                                          | Signature only |
| No                                               | Yes                                                 | IP match only |
| No                                               | No                                                  | Never bypass |

### Steps to Enable
1. Create NV: `rdwr-inline-trusted-sources` (e.g. `203.0.113.10, 198.51.100.0/24`).
2. Create NV: `rdwr-inline-headers-enabled` = `true`.
3. In policy: comment out the hardcoded:
   - `<set-variable name="trustedInlineSourcesCfg" value="" />`
   - `<set-variable name="inlineHeadersEnabledStr" value="false" />`
4. Uncomment the NV-based lines immediately below them.
5. Save & test:
   - Inline path request (with headers + trusted IP) => `shouldBypassRadware=true`.
   - Internal request (no headers or IP mismatch) => sideband executed.

### Security Considerations
- Header presence is not authenticated—never rely on headers alone if an attacker could inject them.
- Always prefer combining headers + IP list.
- Keep IP ranges minimal (only egress addresses of inline WAAP).
- Monitor bypass ratio; spikes may indicate spoof attempts.

---

## APIM Named Values Configuration

The following Named Values must be configured in your Azure API Management instance for this policy to function correctly. Users can manage these Named Values via the Azure Portal, ARM templates, Bicep, Azure CLI, or Azure PowerShell.

| Named Value Name                       | Example Value                                 | Description                                                                                                   | Secret |
|----------------------------------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------------|--------|
| `rdwr-app-ep-addr`                     | your-securepath.radwarecloud.net              | Hostname of the Radware SecurePath endpoint.                                                                  | No     |
| `rdwr-app-ep-port`                     | 443                                           | Port for the Radware SecurePath endpoint.                                                                     | No     |
| `rdwr-app-ep-ssl`                      | true                                          | Whether to use HTTPS to connect to Radware (`true` or `false`).                                               | No     |
| `rdwr-app-ep-timeout-seconds`          | 10                                            | Timeout in seconds for requests to the Radware endpoint.                                                      | No     |
| `rdwr-app-id`                          | your-radware-app-guid                         | Your Radware Application ID.                                                                                  | No     |
| `rdwr-api-key`                         | your-radware-api-key                          | Your Radware API Key.                                                                                         | Yes    |
| `rdwr-true-client-ip-header`           | X-Forwarded-For / ##DISABLED##                | Header for true client IP or literal `##DISABLED##`.                                                          | No     |
| `rdwr-body-max-size-bytes`             | 100000                                        | Max body size to read.                                                                                        | No     |
| `rdwr-partial-body-size-bytes`         | 10240                                         | Partial body threshold.                                                                                       | No     |
| `static-extensions-enabled`            | true                                          | Enable static bypass tier.                                                                                    | No     |
| `static-list-of-methods-not-to-inspect`| GET,HEAD                                      | Candidate methods for static bypass.                                                                          | No     |
| `static-list-of-bypassed-extensions`   | png,jpg,css,js                                 | Candidate extensions (no dots).                                                                               | No     |
| `static-inspect-if-query-string-exists`| true                                          | Force inspect despite static bypass when query present.                                                       | No     |
| `chunked-request-allowed-content-types`| application/json,text/plain                   | Allowed content types (exact match) for reading chunked bodies.                                               | No     |
| `plugin-version-info`                  | azure-apim-radware-v1.1.0                     | Free-form identifier included in the `X-Rdwr-Plugin-Info` header.                                             | No     |
| `rdwr-inline-trusted-sources` (NEW)    | 203.0.113.10, 198.51.100.0/24                 | Inline WAAP egress IP/CIDR allow list. Empty = not configured.                                                | No     |
| `rdwr-inline-headers-enabled` (NEW)    | true                                          | Enable evaluation of inline header signature.                                                                 | No     |

> IMPORTANT: If both new inline NVs are absent, policy behavior = legacy 1.0.0 (no inline bypass).

---

## Operational Diagnostics (NEW)

Trace variables of interest:
- `shouldBypassRadware` (final bypass flag)
- `isInlineBypass` (raw inline evaluation result)
- `radwareDiag` (empty on allow) values:
  - `sideband_error_or_timeout`
  - `redirect_received_fallthrough`
  - `non200_status_fallthrough`
- `setPartialBodyHeader` (true if partial truncation sent)
- `currentBodyLength`, `radwareReqBody` (when body read)

---

## Policy Implementation

1. **Save the Policy XML:**  
   Obtain the full policy XML (see [`rdwr-azureapim-securepath-connector.xml`](./rdwr-azureapim-securepath-connector.xml)) and save it to a file (e.g., `radware-securepath-connector-policy.xml`).

2. **Navigate to APIM:**  
   In the Azure Portal, go to your APIM instance → APIs.

3. **Select API Scope:**
   - Choose the specific API you wish to protect with this Radware integration.
   - Navigate to the "Design" tab for that API.
   - Select "All operations" from the "Frontend" list on the left.

4. **Apply Policy:**
   - In the "Processing policies" section in the middle, click the `</>` icon for "Inbound processing".
   - Delete any existing content in the policy editor.
   - Copy the entire content of your saved `radware-securepath-connector-policy.xml` file and paste it into the editor.
   - Click "Save".

5. **Configure Individual Operation Backends:**
   - This "All operations" policy handles the Radware security check. After this policy, if the request is allowed by Radware, APIM needs to know where to send it.
   - For each individual operation within your API (e.g., `GET /items`, `POST /items/{id}`):
     - Ensure its "Inbound processing" policy (or Backend settings in the UI for that operation) correctly defines the actual backend service URL and any necessary path rewriting. This typically involves using `<set-backend-service base-url="https://your-actual-backend-service.com"/>` and `<rewrite-uri template="/actual-backend-path"/>`.
     - The `<backend><base /></backend>` tag in the "All operations" policy tells APIM to then execute the backend routing defined at the specific operation level.

---

## Testing

- Use an API testing tool (e.g., Postman, curl).
- Send requests to your APIM endpoints (e.g., `https://<your-apim-host>/<your-api-suffix>/items`).
- **Required Header:** Include `Ocp-Apim-Subscription-Key` with a valid APIM subscription key.
- Test various scenarios:
  - Requests that should be allowed by Radware (verify they reach your backend and return expected data).
  - Requests that should be blocked by Radware (verify you receive Radware's block response, e.g., HTTP 403).
  - Requests that should trigger static content bypass (if enabled; verify Radware is not called).
  - POST/PUT requests with and without bodies, and with bodies of different sizes to test partial body logic.
  - If `rdwr-true-client-ip-header` is configured (not `##DISABLED##`), test with and without that header present in the request to verify client IP forwarding.
- Utilize the APIM "Trace" feature (in the "Test" tab of an operation) for detailed debugging of policy execution. This is invaluable for seeing variable values, the request sent to Radware, and the response received from Radware.
- Check logs in your Radware SecurePath dashboard for corresponding entries.
- Check logs in your backend application (e.g., Azure Function logs in Application Insights).

### Additional Inline Bypass Tests
1. Baseline (no NVs) -> Confirm sideband executes.
2. Enable only `rdwr-inline-headers-enabled=true` (no IP list):
   - Request with all 5 headers -> bypass.
   - Missing one header -> no bypass.
3. Enable only `rdwr-inline-trusted-sources`:
   - Match IP -> bypass.
   - Non-match -> inspect.
4. Enable both:
   - Headers + IP => bypass.
   - Headers only => inspect.
   - IP only => inspect.
5. Reserved header enforcement:
   - Inject `X-Rdwr-App-Id` from non-bypass source -> 403.
   - Same from bypass source -> allowed.

### Response Logic Verification
- Force SecurePath to return explicit block JSON (expect 403 JSON).
- Force non-200 (e.g., simulate 403) -> backend still reached (`radwareDiag=non200_status_fallthrough`).

---

## Troubleshooting

- **500 Internal Server Error from APIM:**  
  The most common source is the APIM policy itself. Use the APIM trace to identify the failing policy element or expression.
  - Verify all Named Values are correctly configured and accessible.
  - Check for syntax errors in C# expressions (`@(...)` or `@{...}`).
  - Ensure network connectivity between APIM and the Radware endpoint.
  - Confirm SSL/TLS handshake success (Radware's CA certificates must be trusted by APIM).

- **Radware Blocking Unexpectedly:**  
  Review Radware security policies and logs. Compare with the data APIM is sending to Radware (visible in APIM trace: URL, headers, body).

- **Incorrect Client IP Sent to Radware:**  
  Verify the `rdwr-true-client-ip-header` Named Value setting. If active, ensure the specified header is present in incoming requests. Check the `X-Rdwr-Connector-Ip` header in the request sent to Radware via APIM trace.

### Inline Bypass Specific
| Symptom | Cause | Action |
|---------|-------|--------|
| Expected bypass but inspected | Missing one header or IP not in list | Validate signature + IP list |
| Unexpected bypass | Headers spoofed & no IP list | Add / tighten `rdwr-inline-trusted-sources` |
| Reserved header 403 during inline test | Inline logic not triggered | Check `isInlineBypass` in trace |
| Many `sideband_error_or_timeout` | Endpoint latency / timeout too low | Adjust `rdwr-app-ep-timeout-seconds` |

---

## Limitations

- **SecurePath Bot Manager features are not implemented in this connector.**
  - The connector will not act upon a Bot Manager redirect.
  - It will not inject bot-related cookies to the user.
  - It will not inject the Bot Manager JavaScript, even if Bot Manager is active in the Cloud WAAP portal.
- Double inspection avoidance relies on accurate network source IP classification.

---

## Security Hardening (Supplemental)
- Prefer dual condition (headers + IP list) in production.
- Keep timeout low for resilience (availability bias).


---

## Upgrade (1.0.0 -> 1.1.0)
1. Deploy updated policy XML (already contains inline scaffolding with safe defaults).
2. Validate no behavior change (bypass variables still hardcoded empty/false).
3. Introduce `rdwr-inline-trusted-sources`.
4. Introduce `rdwr-inline-headers-enabled=true`.
5. Switch from hardcoded lines to NV references (uncomment / comment as directed).
6. Trace & confirm `shouldBypassRadware` only true for intended flows.

---
