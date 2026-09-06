# Radware SecurePath Connector for Azure API Management

**Connector v1.4.0** (`x-rdwr-plugin-info` 700-v1.4.0), released 2026-09-07. Changes since v1.3.4
are in `release-notes.md`; existing installs, see "Upgrading from v1.3.x" there.

This guide takes you from an existing API Management instance to SecurePath inspecting your API
traffic.

The connector is an API Management policy. On every request it makes a short inspection call to
your SecurePath application and enforces the verdict it returns. On the response it sends an
asynchronous log entry, which adds no client-visible latency.

It can be installed as a whole policy document or as reusable policy fragments, at the scope of a
single API, a product, or every API on the instance. If you already have policies in place, the
fragment form leaves them untouched — see **Choosing an install form** below.

---

## How to run this guide

**Every command block on this page is self-contained.** Each one begins with the settings it
needs, set to placeholder text such as `RG="your-resource-group"`. Replace those placeholders
inside the block with your values, then paste the whole block. The values come from the same
six settings, so fill them in once and keep them somewhere handy. You can stop, close your
terminal, come back tomorrow, and any block will still run on its own.

Two of the six are secrets. Type `API_KEY` (and, in 3d, the application map) with your shell's
history switched off for that line — `read -rs API_KEY` then Enter, or a leading space when
`HISTCONTROL=ignorespace` is set — and `unset API_KEY` when you are done. The Named Value that
receives it is marked secret and never shown again.

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
> use it — not as `APP_ID`, and not as `APP_EP`. **If the value you are about to put in `APP_ID`
> contains a dot, it is not the Application ID** — the Application ID has no dots. **If the value
> you are about to put in `APP_EP` ends in `.v1.radwarecloud.net`, it is the wrong host** — the
> inspection endpoint always ends in `.oop.radwarecloud.net`.
>
> Neither mistake produces an error. The connector keeps serving traffic, uninspected, and the trace
> shows the inspection call rejected on its certificate. Step 3c and the install check (5e) catch
> both.

### The order, and why it matters

| # | Step | Why it belongs here |
|---|------|---------------------|
| 0 | Confirm your tier and find your API | The tier decides which path you take in Step 1. The two paths are not interchangeable. |
| 1 | Establish TLS trust | Until this is in place, every inspection call fails and traffic is served **uninspected**. On some tiers it takes 15+ minutes to provision, so start it early. |
| 2 | Pre-flight checks | Two things can silently damage an existing configuration or silently disable protection. Both are checked before anything is created. |
| 3 | Create the Named Values | The policy resolves them when it is saved. If one is missing, Step 4 is rejected outright. |
| 4 | Install the connector | Needs an existing API and all 23 Named Values already in place. Choose an install form — see below. |
| 5 | Verify | Only meaningful once Step 1 has finished provisioning. Running it earlier reports a false failure. |

### Permissions you need

Installing the connector writes Named Values, a policy, and (on the v2 tiers) a backend entity.
The built-in role that covers all of them is **API Management Service Contributor**, whose
`Microsoft.ApiManagement/service/*` permission includes every sub-resource involved.

| Role | Enough? |
|---|---|
| **API Management Service Contributor** | **Yes** |
| API Management Service Operator | No — it grants `service/*/read` on sub-resources, so it can update the service itself but cannot write Named Values, policies or fragments |
| API Management Service Reader | No — read only |

### Choosing an install form

**Default: policy fragments at All APIs scope.** The connector is four reusable policy
fragments (the application map, inbound, outbound and on-error). Referenced from the All APIs scope, they run before every API's own policy: API
Management evaluates the All APIs policy first and hands over to the API's policy at its
`<base />` element. So the connector sees every request, including the ones your own
`validate-jwt`, `ip-filter` or `rate-limit` policies go on to reject. Nothing in your existing
policies is edited. `deploy/` installs this form in one command; Step 4 shows the CLI and
Portal equivalents.

Two things follow from that, and both are checked for you by `tools/securepath-apim-lint.py`:

- every API and product policy must keep `<base />` as the first element of its `inbound`,
  `outbound` and `on-error` sections. An API policy without it silently skips the connector;
- install at one scope only. The connector at two scopes inspects every request twice.

| Form | Covers | Existing policies | Use when |
|---|---|---|---|
| **1 — Fragments at All APIs scope** *(default)* | every API | untouched | almost always |
| **2 — Fragments inside one API or product policy** | that API or product | untouched; you add four lines | you must limit the connector to some APIs and cannot use a product |
| **3 — Policy document at API scope** | one API | **replaced** | the API has no policy of its own and never will |

If the instance serves several SecurePath applications, see 3d, "Protecting APIs that belong to
different SecurePath applications".

**For the Azure CLI path** you need `jq`, and a shell opened in the directory containing the policy
XML. If you would rather not install `jq`, the Azure Portal paths need no local tooling.

### Files in this package

| File | What it is |
|---|---|
| `fragments/securepath-app-map.fragment.xml`, `-inbound`, `-outbound`, `-onerror` | the connector, as four policy fragments (Forms 1 and 2) |
| `rdwr-azureapim-securepath-connector-v1.4.xml` | the same connector as one policy document, generated from the fragments (Form 3) |
| `deploy/securepath-apim.bicep`, `deploy/README.md` | one-command install of Form 1 |
| `tools/securepath-apim-lint.py`, `securepath-apim-sync.py`, `securepath-apim-trace.sh`, `tools/README.md` | the install check, the application sync, the trace tool |
| `certs/rdwr-root-ca.pem`, `certs/rdwr-intermediate-ca.pem`, `certs/rdwr-ca-chain.pem`, `certs/README.md` | the Radware certificate authority, for Step 1 Path A |
| `release-notes.md` | what changed, and how to upgrade from v1.3.x |

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
Portal (below), or PowerShell or ARM/Bicep (`certs/README.md`).

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

> **What this setting gives up, plainly.** On Developer, Basic, Standard and Premium tiers the
> Radware authority is installed into the gateway trust store (Path A) and the endpoint's
> certificate is fully validated. The v2 tiers have no such store, so for this one URL the gateway
> does not verify the certificate: the connection is still encrypted, but the endpoint's identity is
> not authenticated by the gateway. What travels on it is the inspection call — the request's
> headers and body sample and your SecurePath API key — so the exposure is to an attacker who can
> already intercept the gateway's outbound traffic to `*.oop.radwarecloud.net`. The setting applies
> only to the URL named in the backend entity; no other traffic through your gateway is affected.
> If full certificate validation is a requirement, use a Developer, Basic, Standard or Premium
> tier instance, where Path A validates the chain.

---
---

# ▶ STEP 2 — Pre-flight checks

**What this does:** catches the two conditions that silently damage an existing configuration or
silently disable protection. Run both before creating anything.

## 2a — Named Value collisions

Named Values share one namespace across the whole instance, and **`az apim nv create` overwrites an
existing name without warning or error**. Six of the 22 names the connector uses carry no
`rdwr-` prefix and are generic enough to already exist:

`plugin-version-info`, `static-extensions-enabled`, `static-list-of-methods-not-to-inspect`,
`static-list-of-bypassed-extensions`, `static-inspect-if-query-string-exists`,
`chunked-request-allowed-content-types`

This lists any that already exist, with their current values, **before** anything is written:

```bash
RG="your-resource-group"
APIM="your-apim-instance"

RDWR_NAMES="rdwr-app-id rdwr-app-ep-addr rdwr-api-key rdwr-app-ep-port rdwr-app-ep-ssl rdwr-app-ep-timeout-seconds rdwr-body-max-size-bytes rdwr-partial-body-size-bytes rdwr-multipart-max-size-bytes rdwr-true-client-ip-header rdwr-api-base-path rdwr-bot-manager-enabled plugin-version-info static-extensions-enabled static-list-of-methods-not-to-inspect static-list-of-bypassed-extensions static-inspect-if-query-string-exists chunked-request-allowed-content-types rdwr-inline-trusted-sources rdwr-inline-headers-enabled rdwr-app-map rdwr-true-host-header rdwr-custom-bot-block-statuses"
EXISTING=$(az apim nv list -g "$RG" --service-name "$APIM" --query "[].name" -o tsv)
FOUND=0
for n in $RDWR_NAMES; do
  if echo "$EXISTING" | grep -qx "$n"; then
    V=$(az apim nv show -g "$RG" --service-name "$APIM" --named-value-id "$n" --query value -o tsv 2>/dev/null)
    echo "COLLISION: $n currently holds: ${V:-secret}"
    FOUND=$((FOUND+1))
  fi
done
echo "collisions: $FOUND"
```

`collisions: 0` means Step 3 is safe to run. Anything else belongs to another workload or to a
previous install — decide what that value is for before you overwrite it.

## 2b — Policies missing `<base />`

Needed for the default install (fragments at All APIs scope). `tools/securepath-apim-lint.py --live`
performs this check as finding L03 for API and product policies and for all three sections; the
block below is the inbound part of it for API policies, in plain shell.

API Management chains policy scopes together with the `<base />` element. If an API's own policy
omits `<base />` from its `<inbound>` section, **the All APIs policy is skipped for that API** —
the connector never runs there, and nothing reports it.

```bash
RG="your-resource-group"
APIM="your-apim-instance"

SUB=$(az account show --query id -o tsv)
MISSING=0
for API in $(az apim api list -g "$RG" --service-name "$APIM" --query "[].name" -o tsv); do
  POL=$(az rest --method GET --uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/apis/$API/policies/policy?api-version=2024-05-01&format=rawxml" 2>/dev/null)
  if [ -z "$POL" ]; then
    echo "OK       $API has no policy of its own, inherits All APIs"
  elif echo "$POL" | tr -d ' \t\r\n' | grep -q '<inbound><base/>'; then
    echo "OK       $API inbound starts with base"
  else
    echo "SKIPPED  $API inbound has no base, the connector will NOT run for this API"
    MISSING=$((MISSING+1))
  fi
done
echo "apis that would skip the connector: $MISSING"
```

Any `SKIPPED` line must be fixed by adding `<base />` as the first element of that API's
`<inbound>` section, or that API stays unprotected.

---
---

# ▶ STEP 3 — Create the Named Values

**What this does:** creates the 23 settings the policy reads — the 3 application values in 3a and
the 20 configuration values in 3b. All 23 must exist before Step 4, or the install is rejected.

## 3a — Your three application values

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

## 3b — The 20 configuration values

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
  "rdwr-true-client-ip-header=##DISABLED##"
  "rdwr-api-base-path=/"
  "rdwr-bot-manager-enabled=false"
  "plugin-version-info=700-v1.4.0"
  "static-extensions-enabled=true"
  "static-list-of-methods-not-to-inspect=GET,HEAD"
  "static-list-of-bypassed-extensions=png,jpg,css,js,gif,ico,svg,woff,woff2"
  "static-inspect-if-query-string-exists=true"
  "chunked-request-allowed-content-types=application/json,application/x-www-form-urlencoded"
  "rdwr-inline-trusted-sources=##DISABLED##"
  "rdwr-inline-headers-enabled=false"
  "rdwr-app-map=##DISABLED##"
  "rdwr-true-host-header=##DISABLED##"
  "rdwr-custom-bot-block-statuses=##DISABLED##"
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
If Bot Manager answers bots with a custom status (a `429` with a "slow down" page, say), list that
status in `rdwr-custom-bot-block-statuses` so the connector relays it — see 3e.

Five values look like they should be empty and cannot be. The Azure CLI rejects an empty `--value`,
so they use a token the policy understands: `/` for `rdwr-api-base-path` (strip nothing; set it to
your API's prefix if that prefix must not reach SecurePath) and `##DISABLED##` for the four
below, which means "off":

- **`rdwr-true-client-ip-header`** — the request header that carries the real client IP when a
  proxy you control (Front Door, Application Gateway, a CDN) fronts the gateway, for example
  `X-Forwarded-For`. The connector takes the first address in it, and only if it is a valid IP
  address. Set it **only** when that proxy is the sole path to the gateway: a client that can reach
  the gateway directly can write that header and choose the IP SecurePath sees.
- **`rdwr-true-host-header`** — the header carrying the client-facing hostname behind Front Door
  or a CDN (3d). Same rule: only when the proxy is the sole path to the gateway.
- **`rdwr-inline-trusted-sources`** — the allow-list of source IPs that may bypass inspection
  (traffic already inspected upstream). `rdwr-inline-headers-enabled=true` additionally requires
  the bypass signature headers on such requests; it never works alone — headers can be forged,
  so without the IP list there is no bypass.
- **`rdwr-app-map`** and **`rdwr-custom-bot-block-statuses`** — explained in 3d and 3e.

Re-running this block over an earlier attempt simply overwrites each value; no error is reported
(which is why Step 2a runs first). A `FAILED:` line appears only for a genuine API error.

## 3c — Verify the Named Values

```bash
RG="your-resource-group"
APIM="your-apim-instance"

EXPECTED="rdwr-app-id rdwr-app-ep-addr rdwr-api-key rdwr-app-ep-port rdwr-app-ep-ssl rdwr-app-ep-timeout-seconds rdwr-body-max-size-bytes rdwr-partial-body-size-bytes rdwr-multipart-max-size-bytes rdwr-true-client-ip-header rdwr-api-base-path rdwr-bot-manager-enabled plugin-version-info static-extensions-enabled static-list-of-methods-not-to-inspect static-list-of-bypassed-extensions static-inspect-if-query-string-exists chunked-request-allowed-content-types rdwr-inline-trusted-sources rdwr-inline-headers-enabled rdwr-app-map rdwr-true-host-header rdwr-custom-bot-block-statuses"
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

Only `OK:` lines means you are ready for Step 4. Any `MISSING:` line will cause the policy upload to
be rejected.

> **Your other Named Values are none of our business.** This check looks only for the 22 names above
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

Only if the value it prints is clearly paste debris, and the name is not one of the 22 above,
remove it:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
STRAY="0"

az apim nv delete -g "$RG" --service-name "$APIM" --named-value-id "$STRAY" --yes
```

## 3d — Protecting APIs that belong to different SecurePath applications

The three values in 3a are the **default application**: every request the connector inspects
uses them unless something below says otherwise. One instance that fronts several SecurePath
applications adds one more Named Value, the **application map**. It is optional and costs
nothing when absent; `tools/securepath-apim-sync.py` keeps it in step with your account.

### Which application a request belongs to

For each request the connector looks up, in this order:

1. the API's resource name (`API_ID`, the `name` column of Step 0);
2. the **client-facing hostname**;
3. the entry named `*`.

The first match wins. No match means the default application from 3a. If you set `rdwr-app-id`
to `##DISABLED##` there is no default: an unmatched request is **served without inspection**,
and the connector says so — it adds `X-Rdwr-Diag: no_app_mapping` to the request it forwards to
your backend and writes a trace line — so an unprotected API is visible, never silent.

**The client-facing hostname.** By default this is the host the gateway received. When Azure
Front Door, a CDN or any proxy sits in front of the gateway, the gateway receives *its own*
hostname and the hostname the client used arrives in a header — `X-Forwarded-Host` for Front
Door. Set `rdwr-true-host-header` to that header name. The connector then uses it both to select
the application and as the `Host` it reports to SecurePath, so events show the domain your users
see (the same idea as `rdwr-true-client-ip-header`). Leave it `##DISABLED##` when clients reach
the gateway directly — and enable it only when the proxy is the sole path to the gateway (Front
Door with a `check-header` on `X-Azure-FDID`, an `ip-filter` for the proxy's ranges, or a private
gateway). Otherwise a client can set that header itself and pick which application inspects it.

### The application map

`rdwr-app-map` holds one JSON object. **Use single quotes, and do not use `&` or `<`**: the
Named Value is inserted into the policy text, where a double quote is not allowed:

```
{'orders-api': {'app_id': 'afa37f7d53ce4e76a4988c4955c2d7e5', 'api_key': 'f4b1c2d3-1111-2222-3333-abcdefabcdef', 'endpoint': 'afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net', 'base_path': '/orders'},
 'shop.example.com': {'app_id': '0b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f', 'api_key': 'aaaa1111-2222-3333-4444-555566667777', 'endpoint': '0b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f.oop.radwarecloud.net'},
 '*': {'app_id': '9f8e7d6c5b4a39281706f5e4d3c2b1a0', 'api_key': 'bbbb1111-2222-3333-4444-555566667777', 'endpoint': '9f8e7d6c5b4a39281706f5e4d3c2b1a0.oop.radwarecloud.net'}}
```

Each entry needs `app_id`, `api_key` and `endpoint`. Optional per entry: `base_path` (the path
prefix to strip before inspection, for an API that lives under a prefix SecurePath does not
know; overrides `rdwr-api-base-path`), `port`, `ssl`, `bot_manager` and `bot_block_statuses`
(override the instance values; `bot_block_statuses` is explained in 3e). Mark the Named Value
**secret**.

```bash
RG="your-resource-group"
APIM="your-apim-instance"
MAP="{'orders-api': {'app_id': 'first-application-id', 'api_key': 'first-api-key', 'endpoint': 'first-application-id.oop.radwarecloud.net'}, 'shop.example.com': {'app_id': 'second-application-id', 'api_key': 'second-api-key', 'endpoint': 'second-application-id.oop.radwarecloud.net'}}"

az apim nv update -g "$RG" --service-name "$APIM" --named-value-id rdwr-app-map --secret true --value "$MAP"
```

On Standard v2 and Premium v2 every distinct `endpoint` needs its own backend entity: run the
Path B block of Step 1 once per endpoint, each time with that endpoint in `APP_EP` **and a
different id at the end of the URL** — `securepath-sideband-2`, `-3`, and so on — because the
block's `securepath-sideband` id is the default application's entity and would be overwritten.
The id is free; the match is on the URL. `deploy/securepath-apim.bicep` creates them from the
`appMap` parameter. `tools/securepath-apim-lint.py --live` reports an endpoint without one as L09.

With Form 3 (a whole policy document) the generated map below is not available — the document
cannot reference the `securepath-app-map` fragment — so use `rdwr-app-map` there.

### Keeping up with your Radware Cloud account: the generated map

Hand-editing `rdwr-app-map` is fine for a handful of applications; a Named Value holds about
4,000 characters, roughly seventeen entries. For anything larger, or to stop maintaining it by
hand at all, let `tools/securepath-apim-sync.py` write the **generated map**. It reads the
SecurePath applications of your account through the Radware Cloud API and writes:

- the policy fragment `securepath-app-map` — hostname, application id and inspection endpoint
  per application (a fragment holds hundreds of entries);
- one **secret** Named Value per application, `rdwr-app-key-<application id>`, holding that
  application's API key — the fragment references it, so no key is ever written into policy
  text, exactly like `rdwr-api-key`;
- on Standard v2 / Premium v2, the backend entity each inspection endpoint needs.

Your `rdwr-app-map` entries are never touched and take precedence over generated ones.

The tool needs two values from the Radware Cloud portal, in addition to your six settings:

| Variable | What it is | Where to get it |
|---|---|---|
| `RDWR_CLOUD_API_KEY` | a Radware Cloud portal **API key** (an account-wide credential: it can read every application's SecurePath key) | Radware Cloud portal → **Accounts → API Keys**; shown once at creation |
| `RDWR_CLOUD_CONTEXT` | your **Application Protection ID** | Radware Cloud portal → **Accounts → API Keys → Account ID Details** |

The tool reads them from those environment variables (or from `--cloud-api-key-file` for the
key), so the key never lands on a command line. In a pipeline, feed them from its secret store.

```bash
RG="your-resource-group"
APIM="your-apim-instance"
export RDWR_CLOUD_CONTEXT="your-application-protection-id"
read -rs RDWR_CLOUD_API_KEY && export RDWR_CLOUD_API_KEY

python3 tools/securepath-apim-sync.py plan -g "$RG" -n "$APIM"
```

`plan` prints one line per application: `add`, `update`, `unchanged`, or `gone` (an entry whose
application no longer exists in the account; kept unless you ask otherwise), plus the backend
entities it would create. Nothing is written. Then:

```bash
RG="your-resource-group"
APIM="your-apim-instance"

python3 tools/securepath-apim-sync.py apply -g "$RG" -n "$APIM"
```

(`RDWR_CLOUD_API_KEY` and `RDWR_CLOUD_CONTEXT` still exported from the `plan` block.)
**If you would rather not let a tool write to Azure.** `render` produces the same change as
files you can review and hand to whoever applies it: a `CHANGES.md` change document, an
`apply.sh` with the commands in order, the fragment as it will be stored, one JSON body per backend
entity, and the API keys in a separate `app-keys.env` so that nothing else in the bundle carries
a secret. Add `--offline` to skip reading the instance, so the tool needs no Azure login at all —
the bundle then carries the whole desired state rather than the difference.

```bash
RG="your-resource-group"
APIM="your-apim-instance"

python3 tools/securepath-apim-sync.py render -g "$RG" -n "$APIM" --out-dir securepath-apim-bundle
```

Then review `securepath-apim-bundle/CHANGES.md` and run `bash securepath-apim-bundle/apply.sh`
with an account that holds API Management Service Contributor. `check` confirms the instance
matches afterwards.

Run `apply` again after onboarding an application or rotating a key; it changes only the
difference. Add `--prune` to also drop entries (and their key Named Values) whose application
is gone — not when several accounts feed one instance, because the other account's entries
look gone. `check` exits 1 when the instance differs from the account, so a scheduler can
alert; `export --out appmap.parameters.json` writes the map as a parameter file for
`deploy/securepath-apim.bicep` — for a handful of applications only, since the `rdwr-app-map`
Named Value it feeds holds about fifteen entries, and the file carries the API keys in clear, so
delete it after the deployment; `--from-file apps.json` uses a saved copy of the account's
application list instead of calling the API.

**Automation.** Run `check` or `apply` from any scheduler you already have: a pipeline in
GitHub Actions or Azure DevOps, a cron host, a Logic App calling a runbook. Nothing in the
gateway polls the Radware Cloud; application selection happens on the request path, reading
the map, and stays deterministic whatever the state of the Radware Cloud API. If the
synchronisation has to live inside Azure without a pipeline, a timer-triggered Azure Function
or a Container Apps job running the same command is the shape to use; talk to Radware before
setting one up.

**What a first `apply` costs at scale.** One Azure call per application key and per backend
entity: a few seconds per application, so a couple of minutes for a hundred. Later runs write
only the difference. Per request, the gateway parses the map once; that stays well under a
millisecond at a hundred entries.

## 3e — Custom Bot Manager block responses

Bot Manager can be configured, in the Radware Cloud portal, to answer a bot with a response of
your own: a status code such as `429` and a page or JSON body of your choosing. SecurePath then
returns that status to the connector instead of the standard `403`.

The connector always handles the standard verdicts (`200`, `301`, `302`, `403`). Any other status is
**not a verdict it knows**, and by default the request is served without one — the connector fails
open and says so (`X-Rdwr-Diag: unexpected_status_429` at your backend, an error in the trace).
Listing the status here turns it into a block that the connector relays:

```bash
RG="your-resource-group"
APIM="your-apim-instance"

az apim nv update -g "$RG" --service-name "$APIM" --named-value-id rdwr-custom-bot-block-statuses --value "429"
```

| Value | Meaning |
|---|---|
| `##DISABLED##` *(default)* | Off. Statuses outside the standard verdicts fail open. |
| `429` or `429,418` | Relay these statuses as a Bot Manager block. |
| `*` | Relay **every** status outside the standard verdicts. Use with care: it also catches an unexpected `4xx` that has nothing to do with a Bot Manager decision. A `5xx` is never relayed, even with `*`. |

**What the client receives when a listed status arrives:** SecurePath's status code, its body byte
for byte, its `Content-Type`, and its `Retry-After`, `Cache-Control`, `Expires`, `Pragma`,
`WWW-Authenticate`, `Content-Language` and `Vary` headers, plus the Bot Manager cookies. If
SecurePath sent the status without a body, the connector's own block page is served with that
status. The response-phase log marks the request `blocked`, so it appears as such in the portal.

**The rules, so nothing surprises you:**

- The setting is used only when `rdwr-bot-manager-enabled` is `true`; otherwise it is ignored.
- `200`, `301`, `302` and `403` in the list have no effect: they are standard verdicts and are
  handled before the list is consulted.
- A `5xx` from SecurePath is an endpoint problem, never a Bot Manager decision. It always fails open.
- A value that is not a list of status codes (a typo, say) disables the setting for that request;
  the request then fails open like any unlisted status. The install check (5e) reports all four
  situations as `L13`.
- With several applications on one instance (3d), an application-map entry may carry its own
  `bot_block_statuses`; it overrides this Named Value for that application.

To see it work, trace one request (Debugging, Option A): the readout's verdict line reads
`block (custom Bot Manager status 429 relayed to the client)`.

---
---

# ▶ STEP 4 — Install the connector

**What this does:** installs the connector. Whichever form you choose, it covers the request
path, the response path and requests rejected by your own policies. There is no separate step
for response-phase logging.

Pick **one** form and install at **one** scope.

---

## Form 1 — Fragments at All APIs scope *(default)*

**Bicep, one command.** See `deploy/README.md`. It creates the backend entity (Step 1 Path B),
the Named Values and all four fragments, and sets the All APIs policy, so Steps 1 (Path B) and 3
can be skipped when you use it; its `what-if` replaces Step 2a.

**Azure CLI, in two blocks.** Run from the directory containing the `fragments/` folder, after
Step 3. The first block registers the four fragments; Form 2 uses it too.

```bash
RG="your-resource-group"
APIM="your-apim-instance"

SUB=$(az account show --query id -o tsv)
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM"
RDWR_OK=1
for F in app-map inbound outbound onerror; do
  jq -Rs "{properties:{format:\"rawxml\",description:\"Radware SecurePath $F\",value:.}}" \
     fragments/securepath-$F.fragment.xml > rdwr-frag-$F.json &&
  az rest --method PUT --uri "$BASE/policyFragments/securepath-$F?api-version=2024-05-01" \
          --headers "Content-Type=application/json" --body @rdwr-frag-$F.json -o none > /dev/null &&
  echo "registered securepath-$F" || { echo "FAILED: securepath-$F (usually a missing Named Value, Step 3c)"; RDWR_OK=0; break; }
done
[ "$RDWR_OK" = 1 ] && echo "all four fragments registered"
```

The second block references them from the All APIs scope:

```bash
RG="your-resource-group"
APIM="your-apim-instance"

SUB=$(az account show --query id -o tsv)
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM"
printf '{"properties":{"format":"rawxml","value":"<policies><inbound><include-fragment fragment-id=\\"securepath-app-map\\" /><include-fragment fragment-id=\\"securepath-inbound\\" /></inbound><backend><forward-request /></backend><outbound><include-fragment fragment-id=\\"securepath-outbound\\" /></outbound><on-error><include-fragment fragment-id=\\"securepath-onerror\\" /></on-error></policies>"}}' > rdwr-global-policy.json &&
az rest --method PUT --uri "$BASE/policies/policy?api-version=2024-05-01" \
        --headers "Content-Type=application/json" --body @rdwr-global-policy.json -o none > /dev/null &&
echo "installed at All APIs scope"
```

A fragment registration is **asynchronous**: the command returns as soon as the upload is
accepted, and validation finishes a few seconds later. If a fragment is ever rejected at that
stage, the previous version stays in place and nothing on the command line says so. The install
check in 5e compares the fragments on the instance with the files in this package and reports
any difference as `L14`, so run it after every registration.

**Azure Portal.** APIs → **Policy fragments** → **+ Create**, four times, pasting each file from
`fragments/`. Name each one after its file without the `.fragment.xml` suffix — exactly
`securepath-app-map`, `securepath-inbound`, `securepath-outbound`, `securepath-onerror` — because
the include lines below reference those names. Then APIs → **All APIs** → **Policies**, open the
code editor and replace the document with:

```xml
<policies>
  <inbound>
    <include-fragment fragment-id="securepath-app-map" />
    <include-fragment fragment-id="securepath-inbound" />
  </inbound>
  <backend>
    <forward-request />
  </backend>
  <outbound>
    <include-fragment fragment-id="securepath-outbound" />
  </outbound>
  <on-error>
    <include-fragment fragment-id="securepath-onerror" />
  </on-error>
</policies>
```

There is no `<base />` at this scope: the All APIs policy has no parent to inherit from. If the
instance already has an All APIs policy of its own, keep its content and add the four include
lines to it instead (the app-map and inbound lines first in `<inbound>`), as in Form 2.

Updating the connector later means replacing the fragments; every scope that references them
picks up the change. `securepath-app-map` is the one fragment the sync tool rewrites (Step 3d);
a connector update leaves it as it is. A fragment cannot be deleted while a policy still references it; API
Management refuses and names the referencing policy.

---

## Form 2 — Fragments inside an existing API or product policy

Register the fragments with the **first** block of Form 1 (or the Portal steps) — not the second,
which would install the connector at All APIs scope. Then open the policy for the API or product
and add the four `include-fragment` lines **immediately after `<base />`, before any policy of
your own**:

```xml
<policies>
  <inbound>
    <base />
    <include-fragment fragment-id="securepath-app-map" />
    <include-fragment fragment-id="securepath-inbound" />
    <!-- your existing inbound policies stay here, after the connector -->
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
    <include-fragment fragment-id="securepath-outbound" />
    <!-- your existing outbound policies -->
  </outbound>
  <on-error>
    <base />
    <include-fragment fragment-id="securepath-onerror" />
    <!-- your existing on-error policies -->
  </on-error>
</policies>
```

**The position matters.** A `validate-jwt`, `check-header`, `ip-filter`, `rate-limit`, `quota`
or `return-response` placed above the connector ends the request before the connector runs, and
SecurePath never sees the requests those policies reject, which are usually the ones you most
want it to see. `tools/securepath-apim-lint.py --file your-policy.xml` reports this as L04
before you upload.

To edit from the CLI, fetch the current policy, edit it, and upload it with `format` set to
`rawxml`. For an API (for a product, replace `apis/$API_ID` with `products/your-product-id`):

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

SUB=$(az account show --query id -o tsv)
URI="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/apis/$API_ID/policies/policy?api-version=2024-05-01"
az rest --method GET --uri "$URI&format=rawxml" -o json | sed '1s/^\xEF\xBB\xBF//' > rdwr-my-policy.xml
python3 tools/securepath-apim-lint.py --file rdwr-my-policy.xml
```

Edit `rdwr-my-policy.xml` (an empty file or a 404 means the API has no policy yet: start from
the document above), run the check again, then upload it:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

SUB=$(az account show --query id -o tsv)
URI="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/apis/$API_ID/policies/policy?api-version=2024-05-01"
jq -Rs '{properties: {format: "rawxml", value: .}}' rdwr-my-policy.xml > rdwr-my-policy.json &&
az rest --method PUT --uri "$URI" --headers "Content-Type=application/json" --body @rdwr-my-policy.json -o none > /dev/null &&
echo "policy updated"
```

---

## Form 3 — Policy document at API scope

Covers one API. **This replaces that API's entire policy document**, so only use it where the API
has no policy of its own. If the API already has a policy, use Form 2 instead.

**Azure Portal:**

1. Portal → your API Management instance → **APIs** → select your API.
2. Select **All operations**.
3. In the **Inbound processing** box, select the **`</>`** icon to open the policy code editor. This
   editor shows the whole document, not only the inbound section.
4. If the editor already contains policies of your own, **stop and use Form 2 instead** — continuing
   will discard them. Otherwise replace the contents with
   `rdwr-azureapim-securepath-connector-v1.4.xml`.
5. **Save.**

If the save is rejected, the error names the missing Named Value or the offending line. Go back to
Step 3c.

**Azure CLI** — run from the directory containing the policy XML:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

SUB=$(az account show --query id -o tsv)
URI="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/apis/$API_ID/policies/policy?api-version=2024-05-01"

jq -Rs '{properties: {format: "rawxml", value: .}}' \
   rdwr-azureapim-securepath-connector-v1.4.xml > rdwr-policy-body.json &&
az rest --method PUT --uri "$URI" \
        --headers "Content-Type=application/json" \
        --body @rdwr-policy-body.json
```

**PowerShell** (the same upload; this form was not executed by Radware for this release — the
bash form above was):

```powershell
$ctx = New-AzApiManagementContext -ResourceGroupName "your-resource-group" -ServiceName "your-apim-instance"
Set-AzApiManagementPolicy -Context $ctx -ApiId "your-api-resource-name" `
    -PolicyFilePath ".\rdwr-azureapim-securepath-connector-v1.4.xml" `
    -Format "application/vnd.ms-azure-apim.policy.raw+xml"
```

`format` must be `rawxml`. The default rejects the Named Value references this policy uses inside
XML attributes.

---
---

# ▶ STEP 5 — Verify

**What this does:** proves the connector is installed, executing, and actually inspecting — three
different things.

On Developer, Basic, Standard and Premium tiers, wait until Step 1 shows the certificates as
provisioned before running these.

## 5a — Confirm the policy is installed

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

SUB=$(az account show --query id -o tsv)
az rest --method GET \
  --uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/apis/$API_ID/policies/policy?api-version=2024-05-01&format=rawxml"
```

## 5b — Confirm the policy is executing

This needs no connectivity to Radware. First list your operations to get a real path:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

az apim api operation list -g "$RG" --service-name "$APIM" --api-id "$API_ID" \
  --query "[].{method:method,url:urlTemplate}" -o table
```

Then send a request carrying a reserved header, which the connector must reject. The URL is the
API's `path` from Step 0 followed by the operation's `urlTemplate` (`/orders` + `/{id}` →
`/orders/1`); add whatever the API needs to accept the request — a subscription key, a bearer
token — because a `401` from API Management itself means the request was rejected before any
policy ran:

```bash
APIM="your-apim-instance"

curl -s -o /dev/null -w "%{http_code}\n" \
  "https://$APIM.azure-api.net/your/real/operation/path" \
  -H "Ocp-Apim-Subscription-Key: your-subscription-key" \
  -H "x-rdwr-app-id: spoofed"
```

**Expect 403.** Anything else means the policy is not applied to the API or operation you tested.

## 5c — Confirm inspection is actually happening

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

3. **`X-Rdwr-Diag` at your backend** — when a request reaches your backend without a completed
   inspection, the connector adds this header to it (a client cannot forge it: any incoming
   `X-Rdwr-Diag` is removed first). Check your backend access log. Every value the connector can
   send:

| Value | Inspected? | Meaning |
|---|---|---|
| *(header absent)* | yes | Inspection completed with an allow verdict. Blocks and redirects never reach the backend; they are visible in the trace. |
| `uzmcr_allow` | yes | Allowed by the Bot Manager mobile exception (SecurePath sent `uzmcr`). |
| `multipart_headers_only` | yes | A multipart body above `rdwr-multipart-max-size-bytes` was inspected headers-only. |
| `sideband_error_or_timeout` | **no** | The inspection call failed or timed out — Issue 1, Issue 8. |
| `sideband_error_failopen_<status>` | **no** | SecurePath answered a 5xx (for example `sideband_error_failopen_503`). |
| `wrong_api_key_redirect` | **no** | The Application ID / API key pair was not recognised — Issue 3. |
| `unexpected_status_<status>` | **no** | SecurePath answered a status outside the verdicts (for example `unexpected_status_429`) — 3e. |
| `no_app_mapping` | **no** | No application-map entry matched and there is no default application — 3d. |
| `config_incomplete` | **no** | The selected application lacks an Application ID, API key or endpoint — 3a, 3d. |
| `app_map_invalid` | **no** | `rdwr-app-map` or the generated map is not valid, or an entry is mistyped — 3d; the install check names the entry. |

## 5d — About testing with an attack pattern

A common test sends an attack pattern and expects `403`. Treat a `200` carefully, because four
situations produce it:

- Your application is in **monitoring or report-only mode** — a `200` is correct, and the request
  should still appear in the events view.
- Your policy set did not flag that particular request.
- The credentials are not being recognised.
- The inspection call is not completing.

Only 5c distinguishes them.

## 5e — Run the install check

```bash
RG="your-resource-group"
APIM="your-apim-instance"

python3 tools/securepath-apim-lint.py --live -g "$RG" -n "$APIM"
```

`clean` means the connector is installed at exactly one scope, every API and product policy
inherits it, nothing of yours runs ahead of it, and the Named Values and (on v2 tiers) the backend
entity are in place. Anything else is printed with the line to change and the fix. The codes are
explained in `tools/README.md`.

---
---

# ▶ DEBUGGING

## Start here: trace one request

Almost every question about this connector is answered by one API Management trace. The inspection
call is made with errors suppressed, by design, so that a problem on the inspection path never
breaks your traffic. That means failures do not surface anywhere except the trace: no error code,
no failed-request metric, no alert. **A `200` from the gateway proves nothing about inspection.**

There are three ways to get a trace. The first is one command and works everywhere, including
private gateways and traffic that arrives through Front Door.

### Option A — one command: capture and read *(recommended)*

`tools/securepath-apim-trace.sh` obtains a one-hour debug token for the API, sends one request the
way your clients do, fetches the trace by its id, saves it as `trace.json` with the credentials
inside it redacted, and prints a readout.
Anything after the script name goes to `curl` unchanged, so add whatever your API needs to accept
the request — a bearer token, a subscription key, a body.

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"
URL="https://your-client-facing-host/your/api/path"

RG="$RG" APIM="$APIM" API_ID="$API_ID" URL="$URL" tools/securepath-apim-trace.sh -H "Authorization: Bearer <your JWT>"
```

Use the **URL your clients use** (through Front Door if that is how traffic arrives) and a request
that your own policies accept. `API_ID` is the API's resource name from `az apim api list`; the
debug token is issued per API, so a request that matches a different API produces no trace.

A healthy request reads like this:

```
request: GET https://your-apim-instance.azure-api.net/orders/1 -> HTTP 200
Apim-Trace-Id: 538d296a34e84f68b68c930be53fdbb3
trace saved: trace.json (credentials inside it replaced with <redacted>)

Trace summary
  trace file id:          d93a30dc-72e9-436a-a516-5a4500b7195d
  API / operation:        /orders / GET /orders/{id}
  connector ran:          yes (fragments)
  policies before it:     none
  inspection call:        https://afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net/orders/1 -> 200 (allowed)
  verdict:                allow
  response-phase log:     sent
  origin answered:        200

clean
```

The mistake described at the top of this guide — the connector installed correctly, but
`rdwr-app-ep-addr` holding the application's front-end host (`.v1.radwarecloud.net`) instead of
the inspection endpoint — reads like this:

```
request: GET https://your-apim-instance.azure-api.net/orders/1 -> HTTP 200
Apim-Trace-Id: b6f8b4d00c40459fa4ba195ad8ac1ae5
trace saved: trace.json (credentials inside it replaced with <redacted>)

Trace summary
  trace file id:          958f0a61-1b30-4f9b-8534-59905fd27420
  API / operation:        /orders / GET /orders/{id}
  connector ran:          yes (fragments)
  policies before it:     none
  inspection call:        https://afa37f7d53ce4e76a4988c4955c2d7e5.v1.radwarecloud.net/orders/1 -> FAILED: The remote certificate was rejected by the provided RemoteCertificateValidationCallback
  verdict:                served uninspected (X-Rdwr-Diag = sideband_error_or_timeout)
  response-phase log:     not requested
  origin answered:        200

T03 [trace]: the inspection call went to 'afa37f7d53ce4e76a4988c4955c2d7e5.v1.radwarecloud.net', which is not a SecurePath inspection endpoint. Fix: set rdwr-app-ep-addr (or the application-map entry) to <APP_ID>.oop.radwarecloud.net — the '.v1.radwarecloud.net' hostname is the application's front-end address (Step 3a, Step 3c)
T04 [trace]: the inspection call was rejected on TLS (The remote certificate was rejected by the provided RemoteCertificateValidationCallback); the request was served uninspected. Fix: establish trust for exactly this host (Step 1): CA certificates on Developer/Basic/Standard/Premium (Path A), a backend entity with certificate validation disabled on Standard v2/Premium v2 (Path B); fix T03 first — a backend entity created for the .oop host does not apply to this URL
2 finding(s)
```

Each `T` line names the problem, the fix, and the step of this guide that covers it. The codes are
listed in `tools/README.md`. Exit code `0` means the trace shows a completed inspection, `1` a
problem, `2` no trace could be captured (the message says why).

**The trace file is sensitive.** A trace carries the request's own credentials (`Authorization`,
subscription key, cookies), the debug token, and the SecurePath API key the connector sends. The
script replaces those values with `<redacted>` when it saves the file; a trace saved any other way
(the Portal, the commands in Option B) is not redacted until you run
`python3 tools/securepath-apim-lint.py --redact trace.json`. Do that before attaching a trace to a
ticket or sending it to a colleague, and delete the file when you are done.

**Reading a saved trace.** The readout works on any trace file — one the script saved, one you
downloaded from the Portal (this shape was not exercised by Radware; the `listTrace` shape was), or
one a colleague sent you:

```bash
python3 tools/securepath-apim-lint.py --trace trace.json
```

### Option B — the same three calls by hand (CLI or Postman)

If you would rather see each step, or want to send the request from Postman, this is what the
script does.

**1. Get a debug token for the API** (valid one hour):

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

SUB=$(az account show --query id -o tsv)
RES="/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM"
BASE="https://management.azure.com$RES"
az rest --method POST --uri "$BASE/gateways/managed/listDebugCredentials?api-version=2024-05-01" --headers "Content-Type=application/json" --body "{\"credentialsExpireAfter\":\"PT1H\",\"apiId\":\"$RES/apis/$API_ID\",\"purposes\":[\"tracing\"]}" --query token -o tsv
```

`apiId` is the API's ARM resource **path** (`/subscriptions/.../apis/<API_ID>`), not a
`https://management.azure.com/...` URL — the latter is rejected with `LinkedInvalidPropertyId`.

**2. Send one request with the token.** With curl:

```bash
URL="https://your-client-facing-host/your/api/path"
TOKEN="the token from step 1"

curl -s -D - -o /dev/null "$URL" -H "Apim-Debug-Authorization: $TOKEN" -H "Authorization: Bearer <your JWT>" | grep -i "apim-trace-id"
```

With **Postman**: build the request exactly as your client would (URL, method, body, your
`Authorization` header), add a header `Apim-Debug-Authorization` with the token as its value, and
send. The response headers contain `Apim-Trace-Id`; copy its value.

**3. Fetch the trace by id:**

```bash
RG="your-resource-group"
APIM="your-apim-instance"
TRACE_ID="the Apim-Trace-Id from step 2"

SUB=$(az account show --query id -o tsv)
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM"
az rest --method POST --uri "$BASE/gateways/managed/listTrace?api-version=2024-05-01" --headers "Content-Type=application/json" --body "{\"traceId\":\"$TRACE_ID\"}" -o json > trace.json
python3 tools/securepath-apim-lint.py --trace trace.json
```

From Postman instead of the CLI: `POST` the same `listTrace` URL with body `{"traceId":"<id>"}`,
`Content-Type: application/json`, and an `Authorization: Bearer <ARM token>` header, where the ARM
token comes from `az account get-access-token --query accessToken -o tsv`. Save the response body
as `trace.json` and read it with the command above.

### Option C — the Portal Test tab (gateway reachable from the Portal)

1. Portal → your API Management instance → **APIs** → select your API.
2. Open the **Test** tab and select an operation.
3. Enable tracing for the call, then **Send**.
4. Open the **Trace** tab on the response and expand the **Inbound** section.

If the Trace tab is unavailable, tracing is not enabled for the subscription you are testing with.
If the gateway is private or your traffic arrives through Front Door, the Test tab cannot reach it
— use Option A. To read a Portal trace with the tool, download it as JSON and run
`securepath-apim-lint.py --trace` on the file.

## Reading a trace yourself

If you read the raw trace rather than the readout, these are the lines that matter, in the order
they appear in the **Inbound** section:

| Line in the trace | What it tells you | If it is wrong |
|---|---|---|
| `Entering policy fragment 'securepath-inbound'` (fragments) or `set-variable ... rdwrAppEpAddr` (Form 3) | The connector ran on this request. **Absent: the connector is not in this API's policy path** — not installed at a covering scope, or the API's own policy lacks `<base />`. | Step 4, Step 2b |
| Any `validate-jwt`, `check-header`, `ip-filter`, `rate-limit`, `return-response` **above** that line | Your policy runs first. Whatever it rejects is never seen by SecurePath. (A `check-header` on `X-Azure-FDID` ahead of the connector is a deliberate choice: direct-to-gateway probes are dropped before inspection.) | Step 4: move the include lines directly after `<base />` |
| `request to 'https://<host>/...'` inside `send-request` | Where the inspection call went. **The host must end in `.oop.radwarecloud.net`.** A host ending `.v1.radwarecloud.net` is the application's front-end address: the Named Value is wrong. | Step 3a, 3c |
| `... resulted in error, error ignored: <reason>` | The inspection call failed and the request was served uninspected. The reason names the cause: a certificate rejection (trust, Step 1 — for the host actually called), a timeout (network path to the endpoint), a hostname that does not resolve (typo). | Issue 1, Issue 8 |
| `send-request` response with status `301`/`302` and a `location` containing `wrong-api-key` | SecurePath did not recognise the Application ID / API key pair. | Step 3a, Issue 3 |
| `set-variable rwStatus = 200` and `oopRequestStatusHeader = allowed` | Inspection completed, verdict allow. `rwStatus = 403` is a block. `rwStatus >= 500` is a SecurePath-side error and the request is served uninspected. | — |
| `set-header X-Rdwr-Diag: <value>` | The request was served **without** a completed inspection; the value says why (table in 5c). This header goes to your backend, so its access log is an ongoing health signal. | 5c |
| `One way request was successfully send to https://<host>/...` in **Outbound** (or **On error**) | The response-phase log was sent. Absent when SecurePath did not request it (`x-rdwr-oop-log` other than `2`/`3`) — that is normal. | — |

## The one string to search for

If you only have time for one search, search the trace for:

```
error ignored
```

Every suppressed failure appears in that shape:

```
... request to 'https://<host>/...' resulted in error, error ignored: <reason>
```

**If that line is present, the request was not inspected.** It was forwarded to your backend anyway
and the client received a normal response. If it is absent, the inspection call completed — then
look at the host in the `request to` line and at `rwStatus`.

## Issue 1 — Certificate rejected

In the trace:

```
The remote certificate was rejected by the provided RemoteCertificateValidationCallback.
```

Trust is not established. You will see no error code, no failed-request metric and no alert — the
API behaves normally while serving traffic uninspected.

| Your tier | Fix |
|---|---|
| Any — check this first | Look at the host in the `send-request` line just above the error. If it ends in `.v1.radwarecloud.net`, the `rdwr-app-ep-addr` Named Value holds the application's front-end address. Set it to the inspection endpoint (`<APP_ID>.oop.radwarecloud.net`), then continue with the row for your tier. |
| Developer / Basic / Standard / Premium | Complete Step 1 Path A. Upload **both** certificates — the root alone is not sufficient. |
| Already uploaded both | Confirm provisioning finished. It shows *"CA certificate update in progress"* for 15+ minutes and the error persists until it completes. |
| Uploaded and provisioned, still failing | Confirm they are under **CA certificates**, not the general **Certificates** tab. Different stores. |
| Standard v2 / Premium v2 | Complete Step 1 Path B. The CA store does not exist on these tiers; the backend entity is the supported route. |

## Issue 2 — The attack test returns 200

See 5d, then check the trace for `error ignored`.

## Issue 3 — Everything works, nothing appears in the Radware Cloud portal

Usually the wrong `rdwr-app-id`. It is a bare identifier with no dots. Run the check in Step 3c.
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

*"Named Value not found"* means one of the 22 is missing. Run Step 3c, which names it.

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
ran. Re-run the block, then run Step 3c to see what was actually created. If you are pasting into a
shell other than bash, paste one command at a time.

---
---

# ▶ REMOVING THE CONNECTOR

How you remove it depends on which form you installed.

## If you installed fragments (Form 1 or 2)

Delete the four `include-fragment` lines from the policy you added them to. Inspection stops
immediately and the rest of that policy is unaffected. For Form 1 installed from the CLI, that is
the All APIs policy: the block under "If you installed the retired All-APIs policy document"
below resets it to the default.

Then, optionally, remove the fragments themselves — and only after that the Named Values: API
Management refuses to delete a Named Value a fragment still references (a `... is used by the
following entities` error), so the order is policy lines, fragments, Named Values, backend
entities. API Management refuses to delete a fragment that
is still referenced and names the referencing policy, so this cannot silently break a scope you
forgot about:

```bash
RG="your-resource-group"
APIM="your-apim-instance"

SUB=$(az account show --query id -o tsv)
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM"

az rest --method DELETE --uri "$BASE/policyFragments/securepath-inbound?api-version=2024-05-01" --headers "If-Match=*"
az rest --method DELETE --uri "$BASE/policyFragments/securepath-outbound?api-version=2024-05-01" --headers "If-Match=*"
az rest --method DELETE --uri "$BASE/policyFragments/securepath-onerror?api-version=2024-05-01" --headers "If-Match=*"
az rest --method DELETE --uri "$BASE/policyFragments/securepath-app-map?api-version=2024-05-01" --headers "If-Match=*"
```

If the sync tool was used, the generated key Named Values (`rdwr-app-key-*`) are inert once the
fragments are gone; list them with `az apim nv list` and delete them at your convenience.

## If you installed Form 3 — policy document at API scope

Replace that API's policy with the default, which restores normal routing immediately. Note this
restores the *default* policy, not any policy you had before installing:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
API_ID="your-api-resource-name"

SUB=$(az account show --query id -o tsv)
URI="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/apis/$API_ID/policies/policy?api-version=2024-05-01"

printf '{"properties":{"format":"rawxml","value":"<policies><inbound><base /></inbound><backend><base /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>"}}' > rdwr-default-policy.json &&
az rest --method PUT --uri "$URI" --headers "Content-Type=application/json" --body @rdwr-default-policy.json
```

## If you installed the retired All-APIs policy document (v1.3.4 Form B)

Same idea, against the global scope, using the global-scope shape:

```bash
RG="your-resource-group"
APIM="your-apim-instance"

SUB=$(az account show --query id -o tsv)
URI="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM/policies/policy?api-version=2024-05-01"

printf '{"properties":{"format":"rawxml","value":"<policies><inbound /><backend><forward-request /></backend><outbound /><on-error /></policies>"}}' > rdwr-default-global.json &&
az rest --method PUT --uri "$URI" --headers "Content-Type=application/json" --body @rdwr-default-global.json
```

## In every case

The 23 Named Values and the backend entities are inert once the connector is removed. Delete them
after the fragments are gone (API Management refuses while a fragment references them) — and check
first whether any of the six non-`rdwr-` names were already yours before installation (Step 2a
lists them).

---
---

# ▶ SUPPORT

When contacting Radware, include:

1. The `trace.json` of one failing request, saved by `tools/securepath-apim-trace.sh` (Debugging,
   Option A), or a Portal trace downloaded as JSON — redacted first with
   `python3 tools/securepath-apim-lint.py --redact trace.json`.
2. The output of `python3 tools/securepath-apim-lint.py --live -g "$RG" -n "$APIM"` and of the
   Step 3c check.
3. Your tier — `az apim show -g "$RG" -n "$APIM" --query sku.name -o tsv`
4. Whether the request appears in the Radware Cloud events view.
