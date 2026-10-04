// Radware SecurePath connector for Azure API Management: one-shot install at All APIs scope.
//
// Creates the Named Values, sets the All APIs policy, and (by default) creates the backend entity
// that establishes trust for the inspection endpoint on Standard v2 / Premium v2. Existing API and
// product policies are left untouched; they inherit the connector through <base />.
//
// The four policy fragments are NOT embedded here: the inbound fragment exceeds the size a Bicep
// template may embed (loadTextContent caps at 131072 characters), so the fragments are registered
// by the documented CLI block (README Step 4, Form 1, first block) or the Portal BEFORE this
// template is deployed. This template's All APIs policy references them by name.
//
// See deploy/README.md for usage and the parameter table.
targetScope = 'resourceGroup'

@description('Name of the existing API Management instance in this resource group.')
param apimName string

@description('SecurePath Application ID (no dots).')
param appId string

@secure()
@description('SecurePath API key.')
param apiKey string

@description('Inspection endpoint hostname, ending in .oop.radwarecloud.net.')
param endpoint string

@description('Inspection endpoint port.')
param endpointPort int = 443

@description('Use TLS to the inspection endpoint.')
param endpointSsl bool = true

@description('Set true if Bot Manager is enabled on the SecurePath application.')
param botManagerEnabled bool = false

@description('Request header carrying the real client IP when a proxy you control fronts the gateway and is its sole path (for example X-Forwarded-For). ##DISABLED## uses the connection address. A client that can reach the gateway directly can write that header.')
param trueClientIpHeader string = '##DISABLED##'

@description('Path prefix to strip before inspection. "/" strips nothing.')
param apiBasePath string = '/'

@description('Create the backend entity that disables certificate validation for the endpoint. Required on Standard v2 / Premium v2. Set false on Developer, Basic, Standard and Premium after installing the Radware CA (README Step 1, Path A), where the certificate is fully validated.')
param createBackend bool = true

@secure()
@description('Optional map of API id or hostname (or "*") to {app_id, api_key, endpoint[, port, ssl, bot_manager, bot_block_statuses, base_path]} for instances serving several SecurePath applications. Empty means the three values above apply to every API. See README "Protecting APIs that belong to different SecurePath applications".')
param appMap object = {}

@description('Header(s) carrying the client-facing hostname when a CDN or Front Door fronts the gateway, comma-separated and tried in order (for example "x-forwarded-host,forwarded"). ##DISABLED## uses the host the gateway received. Only set this when that proxy is the sole path to the gateway.')
param trueHostHeader string = '##DISABLED##'

@description('Used when none of the trueHostHeader headers yields a valid hostname: "gateway" (the host API Management received) or a literal hostname of your own.')
param hostFallback string = 'gateway'

@description('Bot Manager: SecurePath status codes, beyond the standard verdicts, that the connector relays to the client as a Bot Manager block response, for example "429" or "429,418"; "*" for any such status; ##DISABLED## off. Used only when botManagerEnabled is true; a 5xx is never relayed. See README 3e.')
param customBotBlockStatuses string = '##DISABLED##'

@description('Accepted for compatibility and no longer used: this template does not register the fragments (they are registered by README Step 4 before deployment), so it never replaces a sync-managed application-map fragment.')
#disable-next-line no-unused-params
param manageAppMapFragment bool = true

resource apim 'Microsoft.ApiManagement/service@2024-05-01' existing = {
  name: apimName
}

var namedValues = [
  { name: 'rdwr-app-id', value: appId, secret: false }
  { name: 'rdwr-app-ep-addr', value: endpoint, secret: false }
  { name: 'rdwr-api-key', value: apiKey, secret: true }
  { name: 'rdwr-app-ep-port', value: string(endpointPort), secret: false }
  { name: 'rdwr-app-ep-ssl', value: endpointSsl ? 'true' : 'false', secret: false }
  { name: 'rdwr-app-ep-timeout-seconds', value: '10', secret: false }
  { name: 'rdwr-body-max-size-bytes', value: '100000', secret: false }
  { name: 'rdwr-partial-body-size-bytes', value: '10240', secret: false }
  { name: 'rdwr-multipart-max-size-bytes', value: '100000', secret: false }
  { name: 'rdwr-true-client-ip-header', value: trueClientIpHeader, secret: false }
  { name: 'rdwr-api-base-path', value: apiBasePath, secret: false }
  { name: 'rdwr-bot-manager-enabled', value: botManagerEnabled ? 'true' : 'false', secret: false }
  { name: 'plugin-version-info', value: '700-v1.5.0', secret: false }
  { name: 'static-extensions-enabled', value: 'true', secret: false }
  { name: 'static-list-of-methods-not-to-inspect', value: 'GET,HEAD', secret: false }
  { name: 'static-list-of-bypassed-extensions', value: 'png,jpg,css,js,jpeg,gif,ico,ttf,svg,woff,woff2,svc,swf,otf,eot,webp,avif', secret: false }
  { name: 'static-inspect-if-query-string-exists', value: 'true', secret: false }
  { name: 'chunked-request-allowed-content-types', value: 'application/json,application/x-www-form-urlencoded,text/plain,application/soap+xml,text/xml,application/xml,xml/text', secret: false }
  { name: 'rdwr-inline-trusted-sources', value: '##DISABLED##', secret: false }
  { name: 'rdwr-inline-headers-enabled', value: 'false', secret: false }
  { name: 'rdwr-true-host-header', value: trueHostHeader, secret: false }
  { name: 'rdwr-host-fallback', value: hostFallback, secret: false }
  { name: 'rdwr-custom-bot-block-statuses', value: customBotBlockStatuses, secret: false }
]

// A Named Value is substituted inside an XML attribute at policy save time, so the map is
// stored as single-quoted JSON (the policy's parser accepts it).
var appMapValue = empty(appMap) ? '##DISABLED##' : replace(string(appMap), '"', '\'')
var mapUrls = [for e in items(appMap): '${(contains(e.value, 'ssl') && e.value.ssl == false) ? 'http' : 'https'}://${toLower(string(e.value.endpoint))}${(contains(e.value, 'port') && e.value.port != 443 && e.value.port != 80) ? ':${e.value.port}' : ''}']
var distinctMapUrls = union(mapUrls, [])

resource nv 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = [for item in namedValues: {
  parent: apim
  name: item.name
  properties: {
    displayName: item.name
    value: item.value
    secret: item.secret
  }
}]

resource nvAppMap 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  parent: apim
  name: 'rdwr-app-map'
  properties: {
    displayName: 'rdwr-app-map'
    value: appMapValue
    secret: true
  }
}

resource globalPolicy 'Microsoft.ApiManagement/service/policies@2024-05-01' = {
  parent: apim
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '<policies><inbound><include-fragment fragment-id="securepath-app-map" /><include-fragment fragment-id="securepath-inbound" /></inbound><backend><forward-request /></backend><outbound><include-fragment fragment-id="securepath-outbound" /></outbound><on-error><include-fragment fragment-id="securepath-onerror" /><choose><when condition="@((bool)context.Variables.GetValueOrDefault("rdwrUnrouted", false))"><include-fragment fragment-id="securepath-app-map" /><include-fragment fragment-id="securepath-inbound" /><include-fragment fragment-id="securepath-outbound" /></when></choose></on-error></policies>'
  }
  // the four fragments must already be registered (README Step 4); this policy references them
  dependsOn: [nv, nvAppMap]
}

var endpointScheme = endpointSsl ? 'https' : 'http'
var endpointPortSuffix = (endpointPort == 443 || endpointPort == 80) ? '' : ':${endpointPort}'

resource backend 'Microsoft.ApiManagement/service/backends@2024-05-01' = if (createBackend) {
  parent: apim
  name: 'securepath-sideband'
  properties: {
    title: 'SecurePath inspection endpoint'
    protocol: 'http'
    url: '${endpointScheme}://${endpoint}${endpointPortSuffix}'
    tls: {
      validateCertificateChain: false
      validateCertificateName: false
    }
  }
}

resource mapBackends 'Microsoft.ApiManagement/service/backends@2024-05-01' = [for (u, i) in distinctMapUrls: if (createBackend && u != '${endpointScheme}://${toLower(endpoint)}${endpointPortSuffix}') {
  parent: apim
  name: 'securepath-sideband-${i + 1}'
  properties: {
    title: 'SecurePath inspection endpoint (application map)'
    protocol: 'http'
    url: u
    tls: {
      validateCertificateChain: false
      validateCertificateName: false
    }
  }
}]

output gatewayUrl string = apim.properties.gatewayUrl
output installedScope string = 'All APIs'
