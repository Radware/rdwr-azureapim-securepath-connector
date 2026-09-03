# One-shot install with Bicep

Installs the connector at **All APIs** scope on an existing API Management instance: the 22
Named Values, the three policy fragments, the All APIs policy that references them, and the
backend entity that establishes trust for the inspection endpoint on Standard v2 / Premium v2.
Policies you already have on APIs and products are not touched; they inherit the connector
through `<base />`.

Needs: Azure CLI 2.20 or later (Bicep is installed on first use), the **API Management Service
Contributor** role on the instance, and your three SecurePath values (Application ID, API key,
inspection endpoint; see "Your six settings" in the main README). Run the commands from the
directory that contains `deploy/` and `fragments/`.

## Preview what will change

```bash
RG="your-resource-group"
APIM="your-apim-instance"
APP_ID="your-application-id"
API_KEY="your-api-key"
APP_EP="your-application-id.oop.radwarecloud.net"

az deployment group what-if -g "$RG" --template-file deploy/securepath-apim.bicep \
  --parameters apimName="$APIM" appId="$APP_ID" apiKey="$API_KEY" endpoint="$APP_EP"
```

`~ Modify` on a Named Value that already exists means the deployment will overwrite it. Six of
the 20 names carry no `rdwr-` prefix (main README, Step 2a); check those before continuing.

## Install

```bash
RG="your-resource-group"
APIM="your-apim-instance"
APP_ID="your-application-id"
API_KEY="your-api-key"
APP_EP="your-application-id.oop.radwarecloud.net"

az deployment group create -g "$RG" -n securepath-connector --template-file deploy/securepath-apim.bicep \
  --parameters apimName="$APIM" appId="$APP_ID" apiKey="$API_KEY" endpoint="$APP_EP"
```

On Developer, Basic, Standard and Premium tiers add `createBackend=false` to the parameters and
complete main README Step 1 Path A (install the Radware CA) instead; on those tiers the
certificate is fully validated.

## Verify

```bash
RG="your-resource-group"
APIM="your-apim-instance"

python3 tools/securepath-apim-lint.py --live -g "$RG" -n "$APIM"
```

Expect `clean`. Then follow main README Step 5: a request carrying a reserved header returns
403, and a normal request appears in the Radware Cloud events view.

## Update the connector later

Re-run the same `az deployment group create` from the new release. The fragments are replaced in
place and every scope that references them picks up the change.

## Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `apimName` | required | existing instance name |
| `appId`, `apiKey`, `endpoint` | required | your SecurePath application values |
| `endpointPort` / `endpointSsl` | `443` / `true` | leave unless Radware told you otherwise |
| `botManagerEnabled` | `false` | `true` if Bot Manager is enabled on your application |
| `trueClientIpHeader` | `x-forwarded-for` | header carrying the real client IP when a proxy or CDN fronts the gateway |
| `apiBasePath` | `/` | path prefix to strip before inspection |
| `createBackend` | `true` | backend entity for endpoint trust (Path B); set `false` on tiers where the CA is installed |
| `appMap` | `{}` | several SecurePath applications on one instance: `{ "orders-api": { "app_id": "...", "api_key": "...", "endpoint": "...oop.radwarecloud.net" } }`, keyed by API id, hostname or `*`; a backend entity is created per distinct endpoint. See the main README, "Protecting APIs that belong to different SecurePath applications" |
| `trueHostHeader` | `##DISABLED##` | header carrying the client-facing hostname when Front Door or a CDN fronts the gateway (`X-Forwarded-Host`) |

`securepath-apim.parameters.example.json` shows the parameter-file form of the same values.

For several SecurePath applications, let the sync tool produce the map from your account and
pass it as a parameter file:

```bash
RG="your-resource-group"
APIM="your-apim-instance"
APP_ID="your-application-id"
API_KEY="your-api-key"
APP_EP="your-application-id.oop.radwarecloud.net"
CLOUD_API_KEY="your-radware-cloud-portal-api-key"
CLOUD_CONTEXT="your-application-protection-id"

python3 tools/securepath-apim-sync.py export --cloud-api-key "$CLOUD_API_KEY" --cloud-context "$CLOUD_CONTEXT" --out appmap.parameters.json &&
az deployment group create -g "$RG" -n securepath-connector --template-file deploy/securepath-apim.bicep \
  --parameters @appmap.parameters.json --parameters apimName="$APIM" appId="$APP_ID" apiKey="$API_KEY" endpoint="$APP_EP"
```
