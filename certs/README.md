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

## Uploading — Azure CLI *(executed by Radware for this release, on a Developer tier instance)*

`az apim` has no CA-certificate command, but the CA list is a property of the API Management
service itself and `az rest` can set it. Run from the directory that contains `certs/`.

The request **replaces** the instance's CA certificate list. First check that the instance has
none yet; if this prints anything, use the Portal instead, which adds to the list:

```bash
RG="your-resource-group"
APIM="your-apim-instance"

az apim show -g "$RG" -n "$APIM" --query "certificates[].certificate.subject" -o tsv
```

Then upload both certificates in one request. Nothing else on the instance changes:

```bash
RG="your-resource-group"
APIM="your-apim-instance"

SUB=$(az account show --query id -o tsv)
ROOT=$(grep -v -- "-----" certs/rdwr-root-ca.pem | tr -d '\r\n')
INT=$(grep -v -- "-----" certs/rdwr-intermediate-ca.pem | tr -d '\r\n')
printf '{"properties":{"certificates":[{"encodedCertificate":"%s","storeName":"Root"},{"encodedCertificate":"%s","storeName":"CertificateAuthority"}]}}' "$ROOT" "$INT" > rdwr-ca-certs.json &&
az rest --method PATCH --uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM?api-version=2024-05-01" \
  --headers "Content-Type=application/json" --body @rdwr-ca-certs.json -o none &&
echo "CA certificates submitted; provisioning takes 15 minutes or more"
```

The instance shows *Updating* until provisioning finishes (about 20 minutes when Radware ran it).

**ARM template or Bicep.** CA certificates are a property of the service resource itself
(`properties.certificates`); the `Microsoft.ApiManagement/service/certificates` child resource is the
client-certificate store and does not establish trust for the inspection call. A template that
declares the service resource replaces its properties as a whole: run `what-if` first. When Radware
ran one that declared only the certificates, `what-if` showed it would also remove the instance's
protocol and cipher settings and its public network access setting, and switch on the legacy
developer portal. Use the `az rest` request above, which changes only the CA list.

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
