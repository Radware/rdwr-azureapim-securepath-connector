# SecurePath Endpoint CA Certificates

The SecurePath endpoint (`*.oop.radwarecloud.net`) uses a private Radware CA chain, not a public CA. Azure APIM must trust this chain for the `<send-request>` (sideband) and `<send-one-way-request>` (response-phase log) policies to succeed over HTTPS.

## Certificate Chain

| File | Subject | Issuer | Expires |
|------|---------|--------|---------|
| `rdwr-root-ca.pem` | RDWR Root R1 | RDWR Root R1 (self-signed) | 2042-01-25 |
| `rdwr-intermediate-ca.pem` | RDWR CA 1A1 | RDWR Root R1 | 2032-01-28 |
| `rdwr-ca-chain.pem` | Both certificates combined (informational; APIM needs them uploaded individually) | - | - |

## Azure APIM Setup

Both the root and intermediate CA certificates must be uploaded to Azure APIM's **CA certificates** store. **Available on Developer / Basic / Standard / Premium tiers only.** On the v2 tiers (Standard v2 / Premium v2) and the Consumption tier, the CA-certificates page is unavailable; trust is configured per-backend instead — see Microsoft's [Add a Custom CA Certificate](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-ca-certificates) doc.

> **Important — `az apim` CLI does NOT support CA certificate management.** The `az apim` command tree has no `certificate` or `certificate-authority` subcommand (verify with `az apim --help`). Earlier revisions of these docs incorrectly suggested `az apim certificate create` and `az apim certificate-authority create` — neither command exists in `az apim`. The supported programmatic paths are PowerShell and ARM/Bicep; for one-time onboarding the Portal is the simplest.

### Option 1: Azure Portal (recommended for one-time setup)

1. **Rename the `.pem` files to `.cer`** before uploading. APIM's upload dialog filters by file extension and only accepts `.cer` — but PEM and CER are the same Base64 X.509 format, so renaming is sufficient (no conversion needed):
   ```bash
   cp rdwr-root-ca.pem rdwr-root-ca.cer
   cp rdwr-intermediate-ca.pem rdwr-intermediate-ca.cer
   ```
2. Open the Azure Portal, navigate to your APIM instance.
3. In the left menu, under **Security**, select **Certificates** → **CA certificates** → **+ Add**.
4. Browse to `rdwr-root-ca.cer`. **Store** = *Trusted Root Certification Authorities*. Certificate ID = `rdwr-root-r1`. Password = (leave blank — only the public key is needed). Click **Add** → **Save**.
5. Click **+ Add** again. Browse to `rdwr-intermediate-ca.cer`. **Store** = *Intermediate Certification Authorities*. Certificate ID = `rdwr-ca-1a1`. Click **Add** → **Save**.

The provisioning step ("CA certificate update in progress") can take 15+ minutes on larger instances.

### Option 2: Azure PowerShell (for scripted environments)

Microsoft's documented PowerShell command for this is `New-AzApiManagementSystemCertificate`. See [Microsoft's CA-certificate doc](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-ca-certificates) for the parameter list — the cmdlet accepts the certificate file path directly (PEM works in PowerShell; the file-extension restriction is a Portal-upload-dialog filter, not a service-side requirement).

### Option 3: ARM / Bicep (for IaC pipelines)

The CA-certificate ARM resource type is `Microsoft.ApiManagement/service/certificates`:

```json
{
  "type": "Microsoft.ApiManagement/service/certificates",
  "apiVersion": "2022-08-01",
  "name": "[concat(parameters('apimName'), '/rdwr-root-r1')]",
  "properties": {
    "data": "[base64(parameters('rdwrRootCaPem'))]"
  }
}
```

Repeat for `rdwr-ca-1a1` with the intermediate CA contents.

## Verification

After uploading, test the sideband connection by sending a request through APIM to a SecurePath-protected endpoint. If the certificates are not trusted, the `<send-request>` policy will fail with a TLS handshake error in the API Inspector trace (look for `RemoteCertificateChainErrors` or similar).

## Notes

- Both certificates (root AND intermediate) must be uploaded. The intermediate alone is not sufficient.
- These certificates apply to all SecurePath endpoints (`*.oop.radwarecloud.net`).
- If your network uses a TLS-inspecting proxy (e.g., Zscaler), you may also need to upload that proxy's root CA to the APIM CA certificates store.
- APIM enforces a hard limit of **10 CA certificates per instance**.
