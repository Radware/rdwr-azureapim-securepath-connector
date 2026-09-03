// Radware SecurePath connector for Azure API Management: one-shot install at All APIs scope.
//
// Creates the Named Values, registers the three policy fragments, sets the All APIs policy
// to reference them, and (by default) creates the backend entity that establishes trust for
// the inspection endpoint on Standard v2 / Premium v2. Existing API and product policies are
// left untouched; they inherit the connector through <base />.
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

@description('Request header carrying the real client IP when a proxy or CDN fronts the gateway.')
param trueClientIpHeader string = 'x-forwarded-for'

@description('Path prefix to strip before inspection. "/" strips nothing.')
param apiBasePath string = '/'

@description('Create the backend entity that disables certificate validation for the endpoint. Required on Standard v2 / Premium v2. Set false on Developer, Basic, Standard and Premium after installing the Radware CA (README Step 1, Path A), where the certificate is fully validated.')
param createBackend bool = true

@secure()
@description('Optional map of API id or hostname (or "*") to {app_id, api_key, endpoint[, port, ssl, bot_manager, base_path]} for instances serving several SecurePath applications. Empty means the three values above apply to every API. See README "Protecting APIs that belong to different SecurePath applications".')
param appMap object = {}

@description('Request header carrying the client-facing hostname when a CDN or Front Door fronts the gateway (for example X-Forwarded-Host). ##DISABLED## uses the host the gateway received.')
param trueHostHeader string = '##DISABLED##'

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
  { name: 'plugin-version-info', value: '700-v1.4.0', secret: false }
  { name: 'static-extensions-enabled', value: 'true', secret: false }
  { name: 'static-list-of-methods-not-to-inspect', value: 'GET,HEAD', secret: false }
  { name: 'static-list-of-bypassed-extensions', value: 'png,jpg,css,js,gif,ico,svg,woff,woff2', secret: false }
  { name: 'static-inspect-if-query-string-exists', value: 'true', secret: false }
  { name: 'chunked-request-allowed-content-types', value: 'application/json,application/x-www-form-urlencoded', secret: false }
  { name: 'rdwr-inline-trusted-sources', value: '##DISABLED##', secret: false }
  { name: 'rdwr-inline-headers-enabled', value: 'false', secret: false }
  { name: 'rdwr-true-host-header', value: trueHostHeader, secret: false }
]

// A Named Value is substituted inside an XML attribute at policy save time, so the map is
// stored as single-quoted JSON (the policy's parser accepts it).
var appMapValue = empty(appMap) ? '##DISABLED##' : replace(string(appMap), '"', '\'')
var mapEndpoints = [for e in items(appMap): toLower(string(e.value.endpoint))]
var distinctMapEndpoints = union(mapEndpoints, [])

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

resource fragMap 'Microsoft.ApiManagement/service/policyFragments@2024-05-01' = {
  parent: apim
  name: 'securepath-app-map'
  properties: {
    description: 'Radware SecurePath generated application map (written by tools/securepath-apim-sync.py)'
    format: 'rawxml'
    value: loadTextContent('../fragments/securepath-app-map.fragment.xml')
  }
  dependsOn: [nv]
}

resource fragIn 'Microsoft.ApiManagement/service/policyFragments@2024-05-01' = {
  parent: apim
  name: 'securepath-inbound'
  properties: {
    description: 'Radware SecurePath inbound'
    format: 'rawxml'
    value: loadTextContent('../fragments/securepath-inbound.fragment.xml')
  }
  dependsOn: [nv, nvAppMap, fragMap]
}

resource fragOut 'Microsoft.ApiManagement/service/policyFragments@2024-05-01' = {
  parent: apim
  name: 'securepath-outbound'
  properties: {
    description: 'Radware SecurePath outbound'
    format: 'rawxml'
    value: loadTextContent('../fragments/securepath-outbound.fragment.xml')
  }
  dependsOn: [nv]
}

resource fragErr 'Microsoft.ApiManagement/service/policyFragments@2024-05-01' = {
  parent: apim
  name: 'securepath-onerror'
  properties: {
    description: 'Radware SecurePath on-error'
    format: 'rawxml'
    value: loadTextContent('../fragments/securepath-onerror.fragment.xml')
  }
  dependsOn: [nv]
}

resource globalPolicy 'Microsoft.ApiManagement/service/policies@2024-05-01' = {
  parent: apim
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '<policies><inbound><include-fragment fragment-id="securepath-inbound" /></inbound><backend><forward-request /></backend><outbound><include-fragment fragment-id="securepath-outbound" /></outbound><on-error><include-fragment fragment-id="securepath-onerror" /></on-error></policies>'
  }
  dependsOn: [fragIn, fragOut, fragErr]
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

resource mapBackends 'Microsoft.ApiManagement/service/backends@2024-05-01' = [for (ep, i) in distinctMapEndpoints: if (createBackend && ep != toLower(endpoint)) {
  parent: apim
  name: 'securepath-sideband-${i + 1}'
  properties: {
    title: 'SecurePath inspection endpoint (application map)'
    protocol: 'http'
    url: 'https://${ep}'
    tls: {
      validateCertificateChain: false
      validateCertificateName: false
    }
  }
}]

output gatewayUrl string = apim.properties.gatewayUrl
output installedScope string = 'All APIs'
