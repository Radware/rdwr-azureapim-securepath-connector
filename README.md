# Radware SecurePath Connector for Azure API Management

This guide takes you from an existing API Management instance to SecurePath inspecting your API
traffic.

The connector is a single XML policy applied to an API Management API. On every request it makes
a short inspection call to your SecurePath application and enforces the verdict it returns. On the
response it sends an asynchronous log entry, which adds no client-visible latency.

---

## How to run this guide

**Every command block on this page is self-contained.** Each one begins with the same six settings
block. Fill those six values in once, keep them somewhere handy, and paste the same header at the
top of each block as you work through the steps. You can stop, close your terminal, come back
tomorrow, and any block will still run on its own.

There are no comments inside the command blocks, so they paste cleanly into macOS Terminal, Linux
and Azure Cloud Shell alike.

### Your six settings

| Variable | What it is | Where to get it |
|---|---|---|
| `RG` | Azure resource group holding your API Management instance | Azure portal |
| `APIM` | API Management instance name | Azure portal |
| `API_ID` | Resource name of the API you want to protect | `az apim api list`, in Step 0 |
| `APP_ID` | Your SecurePath **Application ID** | Radware Cloud portal |
| `API_KEY` | Your SecurePath **API key** | Radware Cloud portal |
| `APP_EP` | Your SecurePath **inspection endpoint** hostname | Radware Cloud portal |

### Worked example of the shapes

The values below are illustrative — they show the *shape* each value takes, not values you can
use:

| Variable | Example |
|---|---|
| `RG` | `waaap` |
| `APIM` | `securepath-apim` |
| `API_ID` | `orders-api` |
| `APP_ID` | `afa37f7d53ce4e76a4988c4955c2d7e5` |
| `API_KEY` | `f4b1c2d3-1111-2222-3333-abcdefabcdef` |
| `APP_EP` | `afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net` |

> **The mistake almost everyone makes once.** The Radware Cloud portal also shows a hostname ending
> `.v1.radwarecloud.net`. That is your application's front-end address and this connector does not
> use it. **If the value you are about to put in `APP_ID` contains a dot, it is not the Application
> ID** — the Application ID has no dots.
>
> A wrong Application ID produces no error at all. The connector keeps serving traffic, uninspected.
> Step 2c catches it.

### The order, and why it matters

| # | Step | Why it belongs here |
|---|------|---------------------|
| 0 | Confirm your tier and find your API | The tier decides which path you take in Step 1. The two paths are not interchangeable. |
| 1 | Establish TLS trust | Until this is in place, every inspection call fails and traffic is served **uninspected**. On some tiers it takes 15+ minutes to provision, so start it early. |
| 2 | Create the Named Values | The policy resolves them when it is saved. If one is missing, Step 3 is rejected outright. This is the most common reason Step 3 fails. |
| 3 | Apply the policy | Needs an existing API and all 20 Named Values already in place. |
| 4 | Verify | Only meaningful once Step 1 has finished provisioning. Running it earlier reports a false failure. |

**For the Azure CLI path** you need `jq`, and a shell opened in the directory containing the policy
XML. If you would rather not install `jq`, the Azure Portal path in Step 3 needs no local tooling.

---
---

# ▶ STEP 0 — Confirm your tier and find your API

**What this does:** tells you which Step 1 path to take, and gives you the `API_ID` value.

```bash
RG="your-resource-group"
APIM="your-apim-instance"

az apim show -g "$RG" -n "$APIM" --query "{name:name, tier:sku.name}" -o table
az apim api list -g "$RG" --service-name "$APIM" --query "[].{name:name,path:path}" -o table
```

The first table gives your tier. The second lists your APIs — the `name` column is your `API_ID`.

- Tier is **Developer, Basic, Standard or Premium** → Step 1, **Path A**
- Tier is **Standard v2 or Premium v2** → Step 1, **Path B**
- Tier is **Consumption** → not currently supported; contact Radware

---
---

# ▶ STEP 1 — Establish TLS trust for the inspection endpoint

**What this does:** lets API Management trust the certificate your SecurePath endpoint presents.
Until this is done, every inspection call fails silently and traffic is served uninspected.

The inspection endpoint uses a private Radware certificate authority, which API Management does not
trust by default.

## Path A — Developer, Basic, Standard, Premium

These tiers have a service-level CA certificate store. Azure CLI cannot upload to it, so use the
Portal, PowerShell or ARM/Bicep.

1. Rename `certs/rdwr-root-ca.pem` to `rdwr-root-ca.cer`, and `certs/rdwr-intermediate-ca.pem` to
   `rdwr-intermediate-ca.cer`. PEM and CER are the same Base64 X.509 format — the upload dialog
   filters on the extension, so renaming is enough.
2. Portal → your API Management instance → **Security → Certificates → CA certificates → + Add**.
3. Upload `rdwr-root-ca.cer`, store **Trusted Root Certification Authorities**.
4. **+ Add** again, upload `rdwr-intermediate-ca.cer`, store **Intermediate Certification
   Authorities**.

> **Two tabs look alike — only one works.** Under *Security → Certificates* there are separate
> **Certificates** and **CA certificates** tabs. The plain **Certificates** tab holds client
> certificates used to authenticate *to* a backend; putting the Radware CAs there has no effect on
> the inspection call. They must go in **CA certificates**.

Provisioning shows as *"CA certificate update in progress"* and takes **15 minutes or more**. Do
not run Step 4 until it finishes.

**Confirm they landed in the trust store:**

```bash
RG="your-resource-group"
APIM="your-apim-instance"

az apim show -g "$RG" -n "$APIM" --query "certificates[].{store:storeName,subject:certificate.subject}" -o table
```

Expect two rows, one `Root` and one `CertificateAuthority`. An empty result means they are **not**
in the trust store, whatever the Certificates blade shows you.

## Path B — Standard v2, Premium v2

The v2 tiers have no service-level CA certificate store, and the platform rejects any attempt to
add one. Trust is configured on a **backend entity** instead.

A backend entity records how API Management should talk to one particular URL. API Management
applies it automatically to any outbound call matching that URL, so **no policy change is needed**.

**Azure Portal:**

1. Portal → your API Management instance → **APIs → Backends → + Create new backend**.
2. **Backend hosting type**: *Custom URL*.
3. **Runtime URL**: `https://` followed by your `APP_EP` value.
4. Under **Advanced**, disable certificate chain validation and certificate name validation.
5. **Create.**

**Azure CLI:**

```bash
RG="your-resource-group"
APIM="your-apim-instance"
APP_EP="your-application-id.oop.radwarecloud.net"

SUB=$(az account show --query id -o tsv)
printf '{"properties":{"url":"https://%s","protocol":"http","title":"SecurePath inspection endpoint","tls":{"validateCertificateChain":false,"validateCertificateName":false}}}' "$APP_EP" > rdwr-backend.json &&
az rest --method PUT \
  --uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/backends/securepath-sideband?api-version=2024-05-01" \
  --headers "Content-Type=application/json" --body @rdwr-backend.json
```

**Confirm it exists:**

```bash
RG="your-resource-group"
APIM="your-apim-instance"

SUB=$(az account show --query id -o tsv)
az rest --method GET \
  --uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/backends/securepath-sideband?api-version=2024-05-01"
```

> **What this setting means.** On Developer, Basic, Standard and Premium tiers the Radware authority
> is installed into the gateway trust store (Path A) and the certificate is fully validated. The v2
> tiers provide no such trust store, so validation is disabled for this one endpoint instead.
>
> The call still uses TLS and remains encrypted in transit, and the setting applies **only** to the
> URL named in this backend entity — no other traffic through your gateway is affected. If full
> certificate validation is a requirement for your deployment, use a Developer, Basic, Standard or
> Premium tier instance, where Path A validates the chain.

---
---

# ▶ STEP 2 — Create the Named Values

**What this does:** creates the 20 settings the policy reads. All 20 must exist before Step 3, or
the policy upload is rejected.

## 2a — Your three application values

```bash
RG="your-resource-group"
APIM="your-apim-instance"
APP_ID="your-application-id"
API_KEY="your-api-key"
APP_EP="your-application-id.oop.radwarecloud.net"

az apim nv create -g "$RG" --service-name "$APIM" \
  --named-value-id rdwr-app-id --display-name rdwr-app-id --value "$APP_ID" &&
az apim nv create -g "$RG" --service-name "$APIM" \
  --named-value-id rdwr-app-ep-addr --display-name rdwr-app-ep-addr --value "$APP_EP" &&
az apim nv create -g "$RG" --service-name "$APIM" \
  --named-value-id rdwr-api-key --display-name rdwr-api-key --secret true --value "$API_KEY"
```

## 2b — The 17 configuration values

`RDWR_NV` below is a temporary **shell variable** used to build the list. It has nothing to do with
API Management Named Values, and clearing it affects nothing in Azure.

```bash
RG="your-resource-group"
APIM="your-apim-instance"

unset RDWR_NV
RDWR_NV=(
  "rdwr-app-ep-port=443"
  "rdwr-app-ep-ssl=true"
  "rdwr-app-ep-timeout-seconds=10"
  "rdwr-body-max-size-bytes=100000"
  "rdwr-partial-body-size-bytes=10240"
  "rdwr-multipart-max-size-bytes=100000"
  "rdwr-true-client-ip-header=x-forwarded-for"
  "rdwr-api-base-path=/"
  "rdwr-bot-manager-enabled=false"
  "plugin-version-info=700-v1.3.2"
  "static-extensions-enabled=true"
  "static-list-of-methods-not-to-inspect=GET,HEAD"
  "static-list-of-bypassed-extensions=png,jpg,css,js,gif,ico,svg,woff,woff2"
  "static-inspect-if-query-string-exists=true"
  "chunked-request-allowed-content-types=application/json,application/x-www-form-urlencoded"
  "rdwr-inline-trusted-sources=##DISABLED##"
  "rdwr-inline-headers-enabled=false"
)
for kv in "${RDWR_NV[@]}"; do
  name="${kv%%=*}"
  value="${kv#*=}"
  az apim nv create -g "$RG" --service-name "$APIM" \
    --named-value-id "$name" --display-name "$name" --value "$value" ||
    echo "FAILED: $name"
done
unset RDWR_NV
```

Set each to the value shown unless you have a specific reason to change it. These are values the
policy uses literally, not fallbacks applied if you skip them.

Set `rdwr-bot-manager-enabled` to `true` if Bot Manager is enabled on your SecurePath application.

Two values look like they should be empty and cannot be. The Azure CLI rejects an empty `--value`,
so both use a token the policy understands:

- **`rdwr-api-base-path`** — `/` means strip nothing. If your API sits under a base path that should
  not be sent for inspection, set it to that path instead.
- **`rdwr-inline-trusted-sources`** — `##DISABLED##` turns off the inline-bypass allow-list.

If a Named Value already exists from an earlier attempt, the create call reports that the id is in
use. Switch that one to `az apim nv update` with the value you want.

## 2c — Check before continuing

```bash
RG="your-resource-group"
APIM="your-apim-instance"

EXPECTED="rdwr-app-id rdwr-app-ep-addr rdwr-api-key rdwr-app-ep-port rdwr-app-ep-ssl rdwr-app-ep-timeout-seconds rdwr-body-max-size-bytes rdwr-partial-body-size-bytes rdwr-multipart-max-size-bytes rdwr-true-client-ip-header rdwr-api-base-path rdwr-bot-manager-enabled plugin-version-info static-extensions-enabled static-list-of-methods-not-to-inspect static-list-of-bypassed-extensions static-inspect-if-query-string-exists chunked-request-allowed-content-types rdwr-inline-trusted-sources rdwr-inline-headers-enabled"
HAVE=$(az apim nv list -g "$RG" --service-name "$APIM" --query "[].name" -o tsv)
for n in $EXPECTED; do
  echo "$HAVE" | grep -qx "$n" || echo "MISSING: $n"
done
ID=$(az apim nv show -g "$RG" --service-name "$APIM" --named-value-id rdwr-app-id --query value -o tsv)
EP=$(az apim nv show -g "$RG" --service-name "$APIM" --named-value-id rdwr-app-ep-addr --query value -o tsv)
case "$ID" in
  *.*) echo "WRONG: rdwr-app-id contains a dot. Use the bare Application ID, not a hostname." ;;
  *)   echo "OK: rdwr-app-id looks like an Application ID" ;;
esac
case "$EP" in
  *.oop.radwarecloud.net) echo "OK: rdwr-app-ep-addr looks like an inspection endpoint" ;;
  *) echo "WRONG: rdwr-app-ep-addr should end in .oop.radwarecloud.net" ;;
esac
```

Only `OK:` lines means you are ready for Step 3. Any `MISSING:` line will cause the policy upload to
be rejected.

> **Your other Named Values are none of our business.** This check looks only for the 20 names above
> and ignores everything else on your instance. If you see unrelated Named Values in the portal,
> leave them alone — the connector neither reads nor modifies them.

### Cleaning up after a partially completed paste

If a paste stopped halfway, it can leave behind an entry with an obviously wrong name — something
like `0`, `true` or `false`. Those are debris and can be removed.

**Look at it first.** Never delete a Named Value you have not inspected, in case it belongs to
another workload on the same instance:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
STRAY="0"

az apim nv show -g "$RG" --service-name "$APIM" --named-value-id "$STRAY"
```

Only if the value it prints is clearly paste debris, and the name is not one of the 20 above,
remove it:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
STRAY="0"

az apim nv delete -g "$RG" --service-name "$APIM" --named-value-id "$STRAY" --yes
```

---
---

# ▶ STEP 3 — Apply the policy

**What this does:** installs the connector. The policy is **one document** containing all four
processing sections — inbound, backend, outbound and on-error. Installing it covers both the
request path and the response path. There is no separate step for response-phase logging.

Apply it at the **API level** so it covers every operation of that API.

## Path A — Azure Portal

1. Portal → your API Management instance → **APIs** → select your API.
2. Select **All operations**.
3. In the **Inbound processing** box, select the **`</>`** icon to open the policy code editor. This
   editor shows the whole document, not only the inbound section.
4. Select all existing content and replace it with the full contents of
   `rdwr-azureapim-securepath-connector-v1.3.xml`.
5. **Save.**

If the save is rejected, the error names the missing Named Value or the offending line. Go back to
Step 2c.

## Path B — Azure CLI

Run this from the directory containing the policy XML.

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

SUB=$(az account show --query id -o tsv)
URI="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/apis/$API_ID/policies/policy?api-version=2024-05-01"

jq -Rs '{properties: {format: "rawxml", value: .}}' \
   rdwr-azureapim-securepath-connector-v1.3.xml > rdwr-policy-body.json &&
az rest --method PUT --uri "$URI" \
        --headers "Content-Type=application/json" \
        --body @rdwr-policy-body.json
```

`format` must be `rawxml`. The default rejects the Named Value references this policy uses inside
XML attributes.

A successful call returns the stored policy document. A failure returns a validation error with a
line and position.

## Path C — PowerShell

```powershell
$ctx = New-AzApiManagementContext -ResourceGroupName "your-resource-group" -ServiceName "your-apim-instance"
Set-AzApiManagementPolicy -Context $ctx -ApiId "your-api-resource-name" `
    -PolicyFilePath ".\rdwr-azureapim-securepath-connector-v1.3.xml" `
    -Format "application/vnd.ms-azure-apim.policy.raw+xml"
```

---
---

# ▶ STEP 4 — Verify

**What this does:** proves the connector is installed, executing, and actually inspecting — three
different things.

On Developer, Basic, Standard and Premium tiers, wait until Step 1 shows the certificates as
provisioned before running these.

## 4a — Confirm the policy is installed

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

SUB=$(az account show --query id -o tsv)
az rest --method GET \
  --uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/apis/$API_ID/policies/policy?api-version=2024-05-01&format=rawxml"
```

## 4b — Confirm the policy is executing

This needs no connectivity to Radware. First list your operations to get a real path:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

az apim api operation list -g "$RG" --service-name "$APIM" --api-id "$API_ID" \
  --query "[].{method:method,url:urlTemplate}" -o table
```

Then send a request carrying a reserved header, which the connector must reject:

```bash
APIM="your-apim-instance"

curl -s -o /dev/null -w "%{http_code}\n" \
  "https://$APIM.azure-api.net/your/real/operation/path" \
  -H "x-rdwr-app-id: spoofed"
```

**Expect 403.** Anything else means the policy is not applied to the API or operation you tested.

## 4c — Confirm inspection is actually happening

A `200` on normal traffic does **not** prove inspection. The connector keeps serving traffic if it
cannot reach the inspection service, so a healthy connector and an unreachable one look identical
from the client.

Three checks that do prove it:

1. **Radware Cloud events view** — send a request through the gateway and confirm it appears in your
   application's events. This is the definitive proof and works as an ongoing health signal.
2. **If Bot Manager is enabled**, look for `__uzm` cookies in the response. Those originate from
   SecurePath, so their presence confirms the inspection call completed:

```bash
APIM="your-apim-instance"

curl -s -o /dev/null -D - "https://$APIM.azure-api.net/your/real/operation/path" | grep -i "set-cookie"
```

3. **`X-Rdwr-Diag` at your backend** — when inspection does not complete, the connector adds this
   header to the request it forwards to your backend. Check your backend access log:

| Value | Meaning |
|---|---|
| *(header absent)* | Inspection completed normally |
| `sideband_error_or_timeout` | Could not reach or complete the inspection call — see Issue 1 |
| `sideband_error_failopen_5xx` | The inspection service returned an error |
| `wrong_api_key_redirect` | Credentials not recognised — see Issue 3 |

## 4d — About testing with an attack pattern

A common test sends an attack pattern and expects `403`. Treat a `200` carefully, because four
situations produce it:

- Your application is in **monitoring or report-only mode** — a `200` is correct, and the request
  should still appear in the events view.
- Your policy set did not flag that particular request.
- The credentials are not being recognised.
- The inspection call is not completing.

Only 4c distinguishes them.

---
---

# ▶ DEBUGGING

## Start here: capture a trace

Almost every question about this connector is answered by one API Management trace. The inspection
call is made with errors suppressed, by design, so that a problem on the inspection path never
breaks your traffic. That means failures do not surface anywhere except the trace.

1. Portal → your API Management instance → **APIs** → select your API.
2. Open the **Test** tab and select an operation.
3. Enable tracing for the call, then **Send**.
4. Open the **Trace** tab on the response and expand the **Inbound** section.
5. Find the `send-request` entry. That is the inspection call.

If the Trace tab is unavailable, tracing is not enabled for the subscription you are testing with.

## The one string to search for

In the trace, search for:

```
error ignored
```

Every suppressed failure appears in that shape:

```
... request to 'https://<your-endpoint>.oop.radwarecloud.net/...' resulted in error, error ignored: <reason>
```

**If that line is present, the request was not inspected.** It was forwarded to your backend anyway
and the client received a normal response. If it is absent, the inspection call completed.

## Issue 1 — Certificate rejected

In the trace:

```
The remote certificate was rejected by the provided RemoteCertificateValidationCallback.
```

Trust is not established. You will see no error code, no failed-request metric and no alert — the
API behaves normally while serving traffic uninspected.

| Your tier | Fix |
|---|---|
| Developer / Basic / Standard / Premium | Complete Step 1 Path A. Upload **both** certificates — the root alone is not sufficient. |
| Already uploaded both | Confirm provisioning finished. It shows *"CA certificate update in progress"* for 15+ minutes and the error persists until it completes. |
| Uploaded and provisioned, still failing | Confirm they are under **CA certificates**, not the general **Certificates** tab. Different stores. |
| Standard v2 / Premium v2 | Complete Step 1 Path B. The CA store does not exist on these tiers; the backend entity is the supported route. |

## Issue 2 — The attack test returns 200

See 4d, then check the trace for `error ignored`.

## Issue 3 — Everything works, nothing appears in the Radware portal

Usually the wrong `rdwr-app-id`. It is a bare identifier with no dots. Run the check in Step 2c.
Then check the trace for a redirect toward `wrong-api-key`, which is returned when the credentials
cannot be matched to an application.

## Issue 4 — Every request returns 500

A Named Value holds a value the policy cannot parse. These must be exact:

- `rdwr-app-ep-port`, `rdwr-app-ep-timeout-seconds`, and the three size values — plain integers
  only. Not `10s`, not `100kb`.
- `rdwr-app-ep-ssl`, `static-extensions-enabled`, `static-inspect-if-query-string-exists` — exactly
  `true` or `false`. Not `yes`, `on`, `1` or `0`.

The policy saves successfully with a bad value and fails at request time, so this appears right
after a Named Value edit rather than after a policy change.

## Issue 5 — The policy upload is rejected

*"Named Value not found"* means one of the 20 is missing. Run Step 2c, which names it.

If the upload failed with a validation error instead, confirm the request used `format: rawxml`.

## Issue 6 — 404 on your test request

The URL matched no API Management operation, so the policy never ran. Use a path from
`az apim api operation list`.

## Issue 7 — Unexpected 403 on traffic that should pass

The request carried a reserved header. The connector rejects any request presenting
`x-rdwr-app-id`, `x-rdwr-api-key`, `x-rdwr-connector-ip`, `x-rdwr-partial-body`, `x-rdwr-cdn-ip`,
`x-rdwr-ip`, or `x-rdwr-request-host-b60f5e78-5bc7-4441-aac8-20b1e7cddda5`, because a client sending
them is attempting to impersonate the connector.

If an upstream proxy or CDN adds any of these, strip them before the request reaches API Management.

## Issue 8 — Requests are slow

Each request waits for the inspection call, bounded by `rdwr-app-ep-timeout-seconds` (default `10`).
If the endpoint is unreachable, every request waits out that timeout before being forwarded. Check
the trace for `error ignored`.

## Issue 9 — Nothing happened when you pasted a command block

Your shell stopped partway through, most likely on a syntax error, and the remaining commands never
ran. Re-run the block, then run Step 2c to see what was actually created. If you are pasting into a
shell other than bash, paste one command at a time.

---
---

# ▶ REMOVING THE CONNECTOR

Replace the API policy with the default, which restores normal routing immediately:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

SUB=$(az account show --query id -o tsv)
URI="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/apis/$API_ID/policies/policy?api-version=2024-05-01"

printf '{"properties":{"format":"rawxml","value":"<policies><inbound><base /></inbound><backend><base /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>"}}' > rdwr-default-policy.json &&
az rest --method PUT --uri "$URI" --headers "Content-Type=application/json" --body @rdwr-default-policy.json
```

The 20 Named Values and the backend entity are inert once the policy is removed. Remove them at your
convenience — they are all prefixed `rdwr-`, `static-`, `chunked-` or named `plugin-version-info`,
and the backend entity is named `securepath-sideband`.

---
---

# ▶ SUPPORT

When contacting Radware, include:

1. The trace for one failing request, with the **Inbound** section expanded.
2. The output of the Step 2c check.
3. Your tier — `az apim show -g "$RG" -n "$APIM" --query sku.name -o tsv`
4. Whether the request appears in the Radware Cloud events view.
