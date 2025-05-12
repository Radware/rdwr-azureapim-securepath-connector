# Azure APIM Policy for Radware SecurePath Integration

This document describes an Azure API Management (APIM) policy designed to integrate with a Radware SecurePath (Cloud WAAP) endpoint. The policy acts as a connector, sending incoming API requests to the Radware endpoint for security inspection before allowing them to proceed to the backend service.

**Current Version:** 1.0.0 

---

## Purpose

The primary goal of this APIM policy is to integrate Radware's Cloud WAAP capabilities—including cutting-edge API security, discovery, and business logic attack protection, coupled with WAF protection and other advanced features—through Radware's SecurePath architecture. SecurePath allows for out-of-path integration, in this case, leveraging Azure API Management (APIM) as the enforcement point. This policy enables APIM to act as the connector, ensuring that API traffic is vetted by Radware before reaching backend services.

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

---

## Prerequisites

- An Azure API Management instance (Developer tier or higher is recommended for full feature support including static IP if needed for whitelisting by Radware. The Consumption tier does not support uploading custom CA certificates for backend validation).
- A Radware SecurePath (Cloud WAAP) endpoint properly configured with desired security policies (WAF, API Security, Bot Management, etc.).
- The necessary credentials and endpoint details from your Radware setup (endpoint address, port, App ID, API Key).
- Backend API services deployed and ready to be fronted by APIM.
- Appropriate CA certificates (Root and/or Intermediate) for your Radware SecurePath endpoint uploaded to the APIM instance's "CA certificates" store if Radware uses a private CA or a CA not in APIM's default trust store. This is critical for resolving SSL handshake errors if APIM does not inherently trust Radware's SSL certificate.

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
| `rdwr-true-client-ip-header`           | X-Forwarded-For<br>OR<br>##DISABLED##         | Header name to find the true client IP. Set to the specific string `##DISABLED##` to default to `context.Request.IpAddress`. | No     |
| `rdwr-body-max-size-bytes`             | 100000                                        | Maximum request body size (in bytes) to process and send to Radware.                                          | No     |
| `rdwr-partial-body-size-bytes`         | 10240                                         | If body exceeds this (but not max size), send only this many bytes (partial body).                            | No     |
| `static-extensions-enabled`             | true                                          | Enable or disable static content bypass (`true` or `false`).                                                  | No     |
| `static-list-of-methods-not-to-inspect`| GET,HEAD                                      | Comma-separated list of HTTP methods to consider for static bypass.                                           | No     |
| `static-list-of-bypassed-extensions`    | png,jpg,jpeg,gif,css,js,ico                   | Comma-separated list of file extensions to bypass if method matches.                                          | No     |
| `static-inspect-if-query-string-exists` | true                                          | If true, static bypass is overridden if a query string exists on the request (`true` or `false`).             | No     |
| `chunked-request-allowed-content-types` | application/json,application/x-www-form-urlencoded | Comma-separated list of Content-Types for which to read the body if the request is chunked.               | No     |
| `plugin-info`                          | azure-apim-radware-v1.0.0                     | Informational string for the plugin version/type.                                                             | No     |

> **Note:** For Named Values that are boolean flags (e.g., `rdwr-app-ep-ssl`, `static-extensions-enabled`), their values should be the strings `"true"` or `"false"` as they will be parsed by `bool.Parse()` in the policy.

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

---

