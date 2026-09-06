# Radware certificate authority for the inspection endpoint

The SecurePath inspection endpoint (`<APP_ID>.oop.radwarecloud.net`) presents a certificate
issued by a private Radware certificate authority. API Management does not trust it by default,
and every inspection call fails until trust is established — the connector then serves traffic
uninspected and says so (main README, Debugging, Issue 1).

| File | Content | Use |
|---|---|---|
| `rdwr-root-ca.pem` | the root authority (`RDWR Root R1`) | upload as a **Root** CA certificate |
| `rdwr-intermediate-ca.pem` | the issuing authority (`RDWR CA 1A1`) | upload as an **Intermediate** CA certificate |
| `rdwr-ca-chain.pem` | both, in one file | for tools that take a chain (not needed by API Management) |

These are public certificates presented on every TLS handshake, not secrets.

## Which tiers need them

**Developer, Basic, Standard, Premium** have a service-level CA certificate store: upload both
certificates there (main README, Step 1, Path A). **Standard v2 and Premium v2** have no such
store; trust is configured on a backend entity instead (Path B), and these files are not used.

## Uploading — Azure Portal *(the path Radware executed for this release)*

1. Rename the files to `.cer`: PEM and CER are the same Base64 X.509 format, and the upload
   dialog filters on the extension.
2. Portal → your API Management instance → **Security → Certificates → CA certificates → + Add**.
3. `rdwr-root-ca.cer`: Certificate ID `rdwr-root-r1`, store **Trusted Root Certification
   Authorities**, no password. **Add**, then **Save**.
4. `rdwr-intermediate-ca.cer`: Certificate ID `rdwr-ca-1a1`, store **Intermediate Certification
   Authorities**. **Add**, then **Save**.

Under *Security → Certificates* there are two tabs. The plain **Certificates** tab holds client
certificates used to authenticate *to* a backend; putting the Radware CAs there has no effect on
the inspection call. They must go in **CA certificates**. Provisioning shows as *"CA certificate
update in progress"* and can take 15 minutes or more.

## Uploading — PowerShell *(from Microsoft's documentation; not executed by Radware for this release)*

`az apim` has no CA-certificate command. In PowerShell the two certificates become system
certificate configurations that are applied to the instance with `Set-AzApiManagement`:

```powershell
$root = New-AzApiManagementSystemCertificate -StoreName "Root" -PfxPath ".\certs\rdwr-root-ca.pem"
$int  = New-AzApiManagementSystemCertificate -StoreName "CertificateAuthority" -PfxPath ".\certs\rdwr-intermediate-ca.pem"
$apim = Get-AzApiManagement -ResourceGroupName "your-resource-group" -Name "your-apim-instance"
$apim.SystemCertificates = @($root, $int)
Set-AzApiManagement -InputObject $apim
```

## Uploading — ARM / Bicep *(from the ARM schema; not executed by Radware for this release)*

CA certificates are a property of the service resource itself (`properties.certificates`), not a
child resource. The `Microsoft.ApiManagement/service/certificates` child resource is the client
certificate store mentioned above and does not establish trust for the inspection call.

```bicep
param apimName string
param location string        // az apim show --query location
param skuName string         // az apim show --query sku.name
param skuCapacity int        // az apim show --query sku.capacity
param publisherEmail string  // az apim show --query publisherEmail
param publisherName string   // az apim show --query publisherName

resource trust 'Microsoft.ApiManagement/service@2024-05-01' = {
  name: apimName
  location: location
  sku: { name: skuName, capacity: skuCapacity }
  properties: {
    publisherEmail: publisherEmail
    publisherName: publisherName
    certificates: [
      { encodedCertificate: base64(loadTextContent('../certs/rdwr-root-ca.pem')), storeName: 'Root' }
      { encodedCertificate: base64(loadTextContent('../certs/rdwr-intermediate-ca.pem')), storeName: 'CertificateAuthority' }
    ]
  }
}
```

An update to the service resource must repeat the properties the instance already has; run
`what-if` before deploying it.

## Confirm they landed in the trust store

```bash
RG="your-resource-group"
APIM="your-apim-instance"

az apim show -g "$RG" -n "$APIM" --query "certificates[].{store:storeName,subject:certificate.subject}" -o table
```

Expect two rows, one `Root` and one `CertificateAuthority`. Then trace one request (main README,
Debugging, Option A): the readout shows the inspection call answering, with no `error ignored`.

## Notes

- Both certificates are needed; the root alone is not sufficient.
- They cover every SecurePath inspection endpoint (`*.oop.radwarecloud.net`).
- If a TLS-inspecting proxy sits between the gateway and the internet, its own root certificate
  must be uploaded the same way.
- API Management allows at most 10 CA certificates per instance.
