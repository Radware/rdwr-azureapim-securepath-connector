# Radware SecurePath Connector for Azure API Management

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
> Step 3c catches it.

### The order, and why it matters

| # | Step | Why it belongs here |
|---|------|---------------------|
| 0 | Confirm your tier and find your API | The tier decides which path you take in Step 1. The two paths are not interchangeable. |
| 1 | Establish TLS trust | Until this is in place, every inspection call fails and traffic is served **uninspected**. On some tiers it takes 15+ minutes to provision, so start it early. |
| 2 | Pre-flight checks | Two things can silently damage an existing configuration or silently disable protection. Both are checked before anything is created. |
| 3 | Create the Named Values | The policy resolves them when it is saved. If one is missing, Step 4 is rejected outright. |
| 4 | Install the connector | Needs an existing API and all 22 Named Values already in place. Choose an install form — see below. |
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

**Default: policy fragments at All APIs scope.** The connector is three reusable policy
fragments. Referenced from the All APIs scope, they run before every API's own policy: API
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
| **2 — Fragments inside one API or product policy** | that API or product | untouched; you add three lines | you must limit the connector to some APIs and cannot use a product |
| **3 — Policy document at API scope** | one API | **replaced** | the API has no policy of its own and never will |

If the instance serves several SecurePath applications, see "Protecting APIs that belong to
different SecurePath applications" in Step 3.

**For the Azure CLI path** you need `jq`, and a shell opened in the directory containing the policy
XML. If you would rather not install `jq`, the Azure Portal paths need no local tooling.


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

RDWR_NAMES="rdwr-app-id rdwr-app-ep-addr rdwr-api-key rdwr-app-ep-port rdwr-app-ep-ssl rdwr-app-ep-timeout-seconds rdwr-body-max-size-bytes rdwr-partial-body-size-bytes rdwr-multipart-max-size-bytes rdwr-true-client-ip-header rdwr-api-base-path rdwr-bot-manager-enabled plugin-version-info static-extensions-enabled static-list-of-methods-not-to-inspect static-list-of-bypassed-extensions static-inspect-if-query-string-exists chunked-request-allowed-content-types rdwr-inline-trusted-sources rdwr-inline-headers-enabled rdwr-app-map rdwr-true-host-header"
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

Needed for the default install (fragments at All APIs scope). `tools/securepath-apim-lint.py --live` performs this check as finding L03; the block below is the same check in plain shell.

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

**What this does:** creates the 22 settings the policy reads. All 22 must exist before Step 4, or
the install is rejected.

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

## 3b — The 19 configuration values

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

## 3c — Verify the Named Values

```bash
RG="your-resource-group"
APIM="your-apim-instance"

EXPECTED="rdwr-app-id rdwr-app-ep-addr rdwr-api-key rdwr-app-ep-port rdwr-app-ep-ssl rdwr-app-ep-timeout-seconds rdwr-body-max-size-bytes rdwr-partial-body-size-bytes rdwr-multipart-max-size-bytes rdwr-true-client-ip-header rdwr-api-base-path rdwr-bot-manager-enabled plugin-version-info static-extensions-enabled static-list-of-methods-not-to-inspect static-list-of-bypassed-extensions static-inspect-if-query-string-exists chunked-request-allowed-content-types rdwr-inline-trusted-sources rdwr-inline-headers-enabled rdwr-app-map rdwr-true-host-header"
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
the gateway directly.

### The application map

`rdwr-app-map` holds one JSON object. **Use single quotes** — a Named Value is inserted into
the policy text, where a double quote is not allowed — and no `&` or `<`:

```
{'orders-api': {'app_id': 'afa37f7d53ce4e76a4988c4955c2d7e5', 'api_key': 'f4b1c2d3-1111-2222-3333-abcdefabcdef', 'endpoint': 'afa37f7d53ce4e76a4988c4955c2d7e5.oop.radwarecloud.net', 'base_path': '/orders'},
 'shop.example.com': {'app_id': '0b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f', 'api_key': 'aaaa1111-2222-3333-4444-555566667777', 'endpoint': '0b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f.oop.radwarecloud.net'},
 '*': {'app_id': '9f8e7d6c5b4a39281706f5e4d3c2b1a0', 'api_key': 'bbbb1111-2222-3333-4444-555566667777', 'endpoint': '9f8e7d6c5b4a39281706f5e4d3c2b1a0.oop.radwarecloud.net'}}
```

Each entry needs `app_id`, `api_key` and `endpoint`. Optional per entry: `base_path` (the path
prefix to strip before inspection, for an API that lives under a prefix SecurePath does not
know; overrides `rdwr-api-base-path`), `port`, `ssl` and `bot_manager` (override the instance
values). Mark the Named Value **secret**.

```bash
RG="your-resource-group"
APIM="your-apim-instance"
MAP="{'orders-api': {'app_id': 'first-application-id', 'api_key': 'first-api-key', 'endpoint': 'first-application-id.oop.radwarecloud.net'}, 'shop.example.com': {'app_id': 'second-application-id', 'api_key': 'second-api-key', 'endpoint': 'second-application-id.oop.radwarecloud.net'}}"

az apim nv update -g "$RG" --service-name "$APIM" --named-value-id rdwr-app-map --secret true --value "$MAP"
```

On Standard v2 and Premium v2 every distinct `endpoint` needs its own backend entity (Step 1,
Path B, one per endpoint; `deploy/securepath-apim.bicep` creates them from the `appMap`
parameter). `tools/securepath-apim-lint.py --live` reports an endpoint without one as L09.

### Keeping up with your Radware Cloud account: the generated map

Hand-editing `rdwr-app-map` is fine for a handful of applications; a Named Value holds about
4,000 characters, roughly seventeen entries. For anything larger, or to stop maintaining it by
hand at all, let `tools/securepath-apim-sync.py` write the **generated map**. It reads the
SecurePath applications of your account through the Radware Cloud API (a portal API key and
your Application Protection ID), and writes:

- the policy fragment `securepath-app-map` — hostname, application id and inspection endpoint
  per application (a fragment holds hundreds of entries);
- one **secret** Named Value per application, `rdwr-app-key-<application id>`, holding that
  application's API key — the fragment references it, so no key is ever written into policy
  text, exactly like `rdwr-api-key`;
- on Standard v2 / Premium v2, the backend entity each inspection endpoint needs.

Your `rdwr-app-map` entries are never touched and take precedence over generated ones.

```bash
RG="your-resource-group"
APIM="your-apim-instance"
CLOUD_API_KEY="your-radware-cloud-portal-api-key"
CLOUD_CONTEXT="your-application-protection-id"

python3 tools/securepath-apim-sync.py plan -g "$RG" -n "$APIM" --cloud-api-key "$CLOUD_API_KEY" --cloud-context "$CLOUD_CONTEXT"
```

`plan` prints one line per application: `add`, `update`, `unchanged`, or `gone` (an entry whose
application no longer exists in the account; kept unless you ask otherwise), plus the backend
entities it would create. Nothing is written. Then:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
CLOUD_API_KEY="your-radware-cloud-portal-api-key"
CLOUD_CONTEXT="your-application-protection-id"

python3 tools/securepath-apim-sync.py apply -g "$RG" -n "$APIM" --cloud-api-key "$CLOUD_API_KEY" --cloud-context "$CLOUD_CONTEXT"
```

Run `apply` again after onboarding an application or rotating a key; it changes only the
difference. Add `--prune` to also drop entries (and their key Named Values) whose application
is gone — not when several accounts feed one instance, because the other account's entries
look gone. `check` exits 1 when the instance differs from the account, so a scheduler can
alert; `export --out appmap.parameters.json` writes the map as a parameter file for
`deploy/securepath-apim.bicep`; `--from-file apps.json` uses a saved copy of the account's
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

---
---

# ▶ STEP 4 — Install the connector

**What this does:** installs the connector. Whichever form you choose, it covers the request
path, the response path and requests rejected by your own policies. There is no separate step
for response-phase logging.

Pick **one** form and install at **one** scope.

---

## Form 1 — Fragments at All APIs scope *(default)*

**Bicep, one command.** See `deploy/README.md`. It creates the Named Values and registers all
four fragments, so Step 3 can be skipped when you use it.

**Azure CLI.** Run from the directory containing the `fragments/` folder, after Step 3:

```bash
RG="your-resource-group"
APIM="your-apim-instance"

SUB=$(az account show --query id -o tsv)
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM"

for F in app-map inbound outbound onerror; do
  jq -Rs "{properties:{format:\"rawxml\",description:\"Radware SecurePath $F\",value:.}}" \
     fragments/securepath-$F.fragment.xml > rdwr-frag-$F.json &&
  az rest --method PUT --uri "$BASE/policyFragments/securepath-$F?api-version=2024-05-01" \
          --headers "Content-Type=application/json" --body @rdwr-frag-$F.json -o none > /dev/null || exit 1
done
printf '{"properties":{"format":"rawxml","value":"<policies><inbound><include-fragment fragment-id=\\"securepath-app-map\\" /><include-fragment fragment-id=\\"securepath-inbound\\" /></inbound><backend><forward-request /></backend><outbound><include-fragment fragment-id=\\"securepath-outbound\\" /></outbound><on-error><include-fragment fragment-id=\\"securepath-onerror\\" /></on-error></policies>"}}' > rdwr-global-policy.json &&
az rest --method PUT --uri "$BASE/policies/policy?api-version=2024-05-01" \
        --headers "Content-Type=application/json" --body @rdwr-global-policy.json -o none > /dev/null &&
echo "installed at All APIs scope"
```

**Azure Portal.** APIs → **Policy fragments** → **+ Create**, four times, pasting each file
from `fragments/`. Then APIs → **All APIs** → **Policies**, open the code editor and replace the
document with:

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

There is no `<base />` at this scope: the All APIs policy has no parent to inherit from.

Updating the connector later means replacing the fragments; every scope that references them
picks up the change. `securepath-app-map` is the one fragment the sync tool rewrites (Step 3d);
a connector update leaves it as it is. A fragment cannot be deleted while a policy still references it; API
Management refuses and names the referencing policy.

---

## Form 2 — Fragments inside an existing API or product policy

Register the fragments exactly as in Form 1 (the loop, or the Portal). Then open the policy for
the API or product and add the four `include-fragment` lines **immediately after `<base />`,
before any policy of your own**:

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

Upload with `format` set to `rawxml`. The CLI block under Form 3 shows the exact command; point
it at your edited file instead of the shipped document.

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

**PowerShell:**

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

## 4e — Run the install check

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
immediately and the rest of that policy is unaffected.

Then, optionally, remove the fragments themselves. API Management refuses to delete a fragment that
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

The 22 Named Values and the backend entities are inert once the connector is removed. Delete them at
your convenience — but check first whether any of the six non-`rdwr-` names were already yours
before installation (Step 2a lists them).

---
---

# ▶ SUPPORT

When contacting Radware, include:

1. The trace for one failing request, with the **Inbound** section expanded.
2. The output of the Step 3c check.
3. Your tier — `az apim show -g "$RG" -n "$APIM" --query sku.name -o tsv`
4. Whether the request appears in the Radware Cloud events view.
