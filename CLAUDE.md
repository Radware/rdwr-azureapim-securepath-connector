# CLAUDE.md -- Azure APIM SecurePath Connector (rdwr-azureapim-securepath-connector)

## This Is a Customer-Facing Repository

This repo is published to `Radware/rdwr-azureapim-securepath-connector` on GitHub. Customers download it directly. Every file must be release-ready at all times.

### What MUST NOT be in this repo
- QA credentials, test app IDs, test API keys, internal DNS servers (e.g., `168.63.129.16`, `qa-key-01`, `qa-app-01`)
- Internal infrastructure references (`spqa0302b-*`, `azurewebsites.net`, `10.247.206.*`)
- QA-only code (e.g., `x-qa-correlation-id` passthrough, test harness hooks)
- Internal product names: use **SecurePath** (not CWAF, CWAAP, or CloudWAAP) in code, comments, and logs
- `.DS_Store` or other OS artifacts
- Internal version references (e.g., "R&D v1.1.0", "v1.2.1") -- use public version numbers only

### Default settings alignment (must match reference connectors)
| Named Value | Default | Notes |
|-------------|---------|-------|
| `rdwr-app-ep-timeout-seconds` | `10` | Seconds |
| `rdwr-bot-manager-enabled` | `false` | |
| `rdwr-body-max-size-bytes` | `100000` | ~100KB |
| `rdwr-partial-body-size-bytes` | `10240` | ~10KB |
| `static-extensions-enabled` | `true` | |
| `static-inspect-if-query-string-exists` | `true` | Query string overrides static bypass |
| `plugin-version-info` | `700-v1.3.2` | Platform ID 700 = Azure APIM |

## Naming & Terminology

- **SecurePath** = the connector/deployment architecture (what this repo implements)
- **Radware Cloud WAAP** = the cloud security service SecurePath connects to
- **SecurePath endpoint** = the `*.oop.radwarecloud.net` sideband destination
- In code/comments: say "SecurePath" or "SecurePath endpoint", not "SP", "CWAF", or "CWAAP"
- Repo title format: "Radware SecurePath Connector for Azure API Management"

## Architecture

The connector is a single XML policy file applied to APIM API operations. It uses:

- **Inbound pipeline**: sideband `send-request` to SecurePath, verdict enforcement
- **Outbound pipeline**: BM cookie propagation on allow path, response-phase `send-one-way-request` log POST

### Policy Structure (single XML file)

```
Inbound:
  1. Configuration (Named Values → context variables)
  2. Inline bypass check (IP allow-list + header signature)
  3. Reserved header enforcement (403 if spoofed x-rdwr-* present)
  4. Static bypass (extension + method + query string logic)
  5. Body gating (size limits, multipart, chunked, gzip passthrough)
  6. Client IP selection (configurable header or socket IP)
  7. Sideband URL construction (with API base path stripping)
  8. send-request to SecurePath (mode=copy with overrides, ignore-error=true)
  9. BM header/cookie extraction from SecurePath response
  10. Verdict handling (200/301/302/403/5xx, fail-open, custom block page)

Outbound:
  1. BM cookie propagation on allow path
  2. Response-phase log POST (mode 2/3, send-one-way-request)
```

### Key Design Decisions
- **`send-request mode="copy"`** clones the original request (method, headers, body), then policy overrides specific headers. Two branches: one for body-overridden requests, one for passthrough.
- **`ignore-error="true"`** on sideband request ensures fail-open behavior.
- **BM cookies are extracted in inbound** (before verdict) and applied in both inbound (block/redirect return-response) and outbound (allow path) to ensure propagation on all verdict paths.
- **Custom block page** is rendered in inbound with transaction ID extraction from SecurePath response body.
- **Response-phase log** uses `send-one-way-request` (fire-and-forget) for near-zero client latency.

## Azure APIM Platform Constraints

- **No response body modification** -- XML policies cannot modify origin response bodies, so JS injection is impossible. This is why `inject_js` verdict is not supported.
- **`x-rdwr-connector-scheme` always `https`** -- Azure forces HTTPS termination.
- **Named Values are the only configuration mechanism** -- no environment variables or config files. All settings must be pre-created as Named Values.
- **No dedicated path proxying** from within a single XML policy -- `/18f5.../` and `/c99a.../` paths must be configured as separate API operations.
- **`send-one-way-request`** does not return a response -- the v2 log POST result is not available for error checking.
- **APIM expression sandbox** limits available .NET APIs -- no LINQ `.Contains()` on older tiers, no `System.Text.RegularExpressions`, limited `System.Net` access.

## Version Strings to Update (on version bump)

- `README.md`: version header, plugin-version-info table entry, changelog section
- `rdwr-azureapim-securepath-connector-v1.3.xml`: default plugin-info fallback value (line with `"700-v1.3.2"`)
- Rename the XML file if the minor version changes (e.g., `v1.3.xml` to `v1.4.xml`)

## Certification (v1.3.2 -- Current)

- **Deep tests**: 60 PASS, 5 SKIP (expected platform limitations), 0 FAIL
- **Body handling**: Large body correctly sends empty body to SecurePath, partial body truncation verified, gzip passthrough verified
- **Host header**: Sideband HTTP Host carries original client Host (not SecurePath endpoint hostname)
- **Bot Manager**: Cookie propagation on all verdict paths (allow, block, redirect)
- **Response logging**: 4/4 o2v headers, 21/21 o2h headers, mode 3 body capture with base64 encoding
- **`x-rdwr-o2v-bytes-sent`**: v1.3.2 fix -- now reports total wire bytes (status line + headers + body), matching NGINX `$bytes_sent` semantics
- **Disposition header**: `x-rdwr-o2h-rdwr-response` reports `allowed`/`blocked` on all verdict paths (VD01-VD03: 3/3 PASS)
- **v2 on block**: Response-phase log fires on block and redirect verdicts (not just allow)
- **Known variances**: `x-rdwr-connector-scheme` always `https`, no JS injection, no dedicated path proxying

## Testing Environment

- **APIM instance**: Azure API Management (any tier)
- **Policy applied at**: API level (all operations) or per-operation
- **SecurePath app**: configured via Named Values
- **Subscription key**: required if APIM subscription validation is enabled

## Release-zip build recipe — IMPORTANT: certs/ MUST be force-included

`*.pem` and `*.cer` are gitignored (so working-tree CA bundles never accidentally land in commits), and the `certs/` directory only tracks `certs/README.md`. **`git archive` therefore EXCLUDES the cert PEM files.** Customers download the zip and find `certs/README.md` only — no `rdwr-root-ca.pem`, no `rdwr-intermediate-ca.pem`, no `rdwr-ca-chain.pem` — which silently breaks Step 1 of the onboarding flow (CA upload to APIM).

This was a pre-existing bug across v1.3.0, v1.3.1, and the original v1.3.2 release; caught in the 2026-05-08 customer-audit pass. Every release-zip build MUST copy the cert PEMs from the working tree into the staged tarball directory before zipping:

```bash
TMP=$(mktemp -d) && cd "$TMP"
git -C <repo> archive --format=tar --prefix='rdwr-azureapim-securepath-connector-v1.3.2/' HEAD | tar -x
rm -f rdwr-azureapim-securepath-connector-v1.3.2/CLAUDE.md          # engineering-only
cp <repo>/certs/rdwr-root-ca.pem         rdwr-azureapim-securepath-connector-v1.3.2/certs/   # GITIGNORED but customer-required
cp <repo>/certs/rdwr-intermediate-ca.pem rdwr-azureapim-securepath-connector-v1.3.2/certs/   # GITIGNORED but customer-required
cp <repo>/certs/rdwr-ca-chain.pem        rdwr-azureapim-securepath-connector-v1.3.2/certs/   # GITIGNORED but informational
zip -qr /tmp/rdwr-azureapim-securepath-connector-v1.3.2.zip rdwr-azureapim-securepath-connector-v1.3.2/
```

Verify the resulting zip contains all three PEM files plus `certs/README.md`:
```bash
unzip -l /tmp/rdwr-azureapim-securepath-connector-v1.3.2.zip | grep certs
# expect: certs/README.md, certs/rdwr-root-ca.pem, certs/rdwr-intermediate-ca.pem, certs/rdwr-ca-chain.pem
```
