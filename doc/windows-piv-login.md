# Setting up PIV / smartcard Login for AD-joined Windows workstations, without ADCS

These instructions assume you'll be using `hsm-secrets` tool for key management and certificate signing on a YubiHSM2, but the process is pretty much the same for any offline Public Key Infrastructure you might want to use instead of ADCS.
## How PIV Login Works

1. User inserts smartcard into workstation.
2. Workstation reads the certificate from the smartcard.
3. Workstation sends a login request to the DC, including the user's certificate.
4. DC validates the certificate chain against its trusted root store.
5. DC checks the user's AD account and associated certificate.
6. If valid, DC issues a Kerberos ticket to the workstation.
7. Workstation grants user access based on the Kerberos ticket.

This relies on properly configured certificates, published Certificate Revocation Lists (CRLs), and correct Group Policy settings.

## Prerequisites

- Active Directory environment
- Yubikeys for user authentication
- Web server for CRL distribution
- `hsm-secrets` + YubiHSM2 (adapt yourself for for other external PKIs)

## Step 1: Prepare the Certificate Authorities (CAs)

First we'll create a root CA and an intermediate CA specifically for PIV/smartcard use.

1. Set up the HSM ([instructions using hsm-secrets](/doc/setup-workflow.md)) to generate a root CA and PIV Intermediate CA.
2. Retrieve certificate files:
   ```
   hsm-secrets x509 cert get cert_ca-root-a1-ecp384 cert_piv-p1-ecp384
   ```
3. Create and publish empty CRLs for them
   ```
   hsm-secrets x509 crl init cert_ca-root-a1-ecp384 cert_piv-p1-ecp384
   ```
   - Host these CRLs on a web server accessible via the URLs specified in your [config](/hsm-conf.yml). Use plain HTTP, not HTTPS.

## Step 2: Configure Group Policies

Create two Group Policies are used to distribute certificates and configure smartcard settings across the domain (both Domain Controllers and workstations):

1. Open Group Policy Management:
   - On a Domain Controller or a machine with RSAT tools, open "Start" menu.
   - Search for and run "Group Policy Management".

2. In GPMC, navigate to your domain (e.g., yourdomain.com).

3. Right-click on the domain and select "Create a GPO in this domain, and Link it here".

### GPO 1: Root Certificate Installation

1. Name the first GPO "PIV Root Certificate Installation" and click "OK".
2. Right-click the new GPO and select "Edit".
3. In the Group Policy Management Editor, navigate to:
   `Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies`
4. Right-click on "Trusted Root Certification Authorities" and select "Import".
5. Follow the Certificate Import Wizard to import your root CA certificate.
6. Close the Group Policy Management Editor.

### GPO 2: Intermediate Certificate and Smart Card Settings

1. Create another GPO named "PIV Intermediate Certificate and Smart Card Settings".
2. Edit this new GPO.
3. Import the Intermediate Certificate:
   - Navigate to: `Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies`
   - Right-click on "Intermediate Certification Authorities" and select "Import".
   - Use the Certificate Import Wizard to import your PIV Intermediate certificate.

4. Configure Smart Card Settings:
   - Navigate to: `Computer Configuration > Policies > Administrative Templates > Windows Components > Smart Card`
   - Configure each setting as follows:

<table border="1">
  <tr>
    <th>Policy Setting</th>
    <th>Configuration</th>
  </tr>
  <tr>
    <td>Allow ECC certificates to be used for logon and authentication</td>
    <td>Enabled</td>
  </tr>
  <tr>
    <td>Allow integrated unblock screen to be displayed at Ctrl+Alt+Del</td>
    <td>Enabled</td>
  </tr>
  <tr>
    <td>Allow time invalid certificates</td>
    <td>Enabled</td>
  </tr>
  <tr>
    <td>Allow user name hint</td>
    <td>Enabled</td>
  </tr>
  <tr>
    <td>Force reading all certificates from the smart card</td>
    <td>Enabled</td>
  </tr>
  <tr>
    <td>Reverse the subject name stored in a certificate when displaying</td>
    <td>DISABLED</td>
  </tr>
</table>

5. Configure the Strong Certificate Binding registry setting:
   - Navigate to: `Computer Configuration > Preferences > Windows Settings > Registry`
   - Right-click, select "New" > "Registry Item"
   - Configure as follows:
     - Action: Create
     - Hive: `HKEY_LOCAL_MACHINE`
     - Key Path: `SYSTEM\CurrentControlSet\Services\Kdc`
     - Value name: `StrongCertificateBindingEnforcement`
     - Value type: REG_DWORD
     - Value data: 2

6. Close the Group Policy Management Editor.

### Applying the GPOs

1. In GPMC, ensure both GPOs are linked to the domain.
2. To apply these settings to specific OUs (e.g., "Domain Controllers" or "Workstations"):
   - Right-click the target OU.
   - Choose "Link an Existing GPO".
   - Select each of the GPOs you created.

3. Set GPO Link Order:
   - In GPMC, select your domain.
   - In the right pane, under "Linked Group Policy Objects", arrange the GPOs:
     - "PIV Root Certificate Installation" should be higher in the list.
     - "PIV Intermediate Certificate and Smart Card Settings" should be lower.

4. Force a Group Policy update:
   - On a test machine (DC or workstation), open Command Prompt as Administrator.
   - Run: `gpupdate /force`

5. Verify GPO application:
   - On the test machine, run: `gpresult /r` or `rsop.msc`
   - Confirm that both GPOs are applied.


## Step 3: Publish the Intermediate CA

The intermediate CA needs to be trusted for authentication throughout the domain. Adding it to the NTAuth store accomplishes this.

As an Enterprise Admin, add the PIV intermediate to the `NTAuthCA` store:
```
certutil -dspublish -f <intermed.cer> NTAuthCA
```

## Step 4: Create Kerberos PKINIT Certificates for Domain Controllers

For PIV, the Domain Controllers need special certificates for Kerberos PKINIT, which allows initial authentication using certificates instead of passwords.

Excellent suggestion. Here's the compact version with bolded values to distinguish them from menu labels:

## Step 4: Create Kerberos PKINIT Certificates for Domain Controllers

1. Open MMC (Win + R, type **`mmc`**, press Enter)

2. Add Certificate snap-in:
   - File > Add/Remove Snap-in > Certificates > Add > **Computer account** > **Local computer**

3. Create CSR:
   - Certificates (Local Computer) > Personal > Right-click > All Tasks > Advanced Operations > Create Custom Request
   - **Custom request** > **No template** > Properties

4. Configure CSR:

<table border="1">
  <tr>
    <th>Parameter</th>
    <th>Value</th>
  </tr>
    <tr>
    <td>Friendly name</td>
    <td>e.g., "DC01 Kerberos PKINIT Cert"</td>
  </tr>
  <tr>
    <td>Subject Name</td>
    <td>CN=dc01.yourdomain.com</td>
  </tr>
  <tr>
    <td rowspan="2">Subject Alternative Names (SANs)</td>
    <td>DNS: All server's FQDNs and NetBIOS names (e.g. plain "DC01")</td>
  </tr>
  <tr>
    <td>IP: All server's IP addresses</td>
  </tr>
  <tr>
    <td>Key Usage</td>
    <td>Digital Signature, Key Encipherment</td>
  </tr>
  <tr>
    <td rowspan="4">Extended Key Usage</td>
    <td>KDC Authentication (1.3.6.1.5.2.3.5)</td>
  </tr>
  <tr>
    <td>Smart Card Logon (1.3.6.1.4.1.311.20.2.2)</td>
  </tr>
  <tr>
    <td>Client Authentication</td>
  </tr>
  <tr>
    <td>Server Authentication (optional, for LDAPS)</td>
  </tr>
  <tr>
    <td rowspan="2">Key Type</td>
    <td>RSA 2048-bit</td>
  </tr>
  <tr>
    <td><em>(Do NOT check 'Make private key exportable')</em></td>
  </tr>
  <tr>
    <td>Signature Algorithm</td>
    <td>SHA256</td>
  </tr>
</table>

5. Save CSR (e.g., **`DC01_PKINIT.csr`**)

6. Sign CSR:
   ```
   hsm-secrets piv sign-dc-cert DC01_PKINIT.csr
   ```

7. Import signed certificate:
   - MMC > Personal > All Tasks > Import
   - Select generated **.cer** file

8. Double-click the imported certificate and verify properties and chain
9. On the DC, run: `net stop kdc & net start kdc`

**Repeat for each Domain Controller**, using their respective FQDNs and IP addresses.

## Step 5: Install Yubico Minidriver

- On DCs: `msiexec /i YubiKey-Minidriver-4.1.1.210-x64.msi INSTALL_LEGACY_NODE=1` (for remote servers, PIV over RDP)
- On workstations (USB inserted locally): Install the standard Yubico minidriver.

## Step 6: Update Group Policies

Run `gpupdate /force` on DCs and your test workstation.

## Step 7: Verify Certificate Chain

On Windows, run:
```
certutil -enterprise -store NTAuth
```
Ensure the intermediate certificate is listed. It should have been pulled from AD by the `gpupdate`.

## Step 8: Generate User Certificates

PIV user certificates stored on Yubikeys are what allow individual users to authenticate. These need to be created and properly mapped to AD user accounts.

1. Generate a user certificate on Yubikey:
   ```
   hsm-secrets piv yubikey generate firstname.lastname
   ```
2. Verify it on a Windows workstation:
   ```
   certutil -scinfo
   ```
   Ensure this shows root and intermediate as valid, CRLs are reachable, and there are no warnings about untrusted certificates.

3. Add the Strong Certificate Mapping (KB5014754) ID to the Yubikey user's AD object:
   - In ADUC, add the reported ID (something like `X509:<SKI>9a9075be4598dfb711d1897ae906615eb411d1dd`) to the user's `altSecurityIdentities` attribute.

## Step 9: Test Login

Testing ensures that all components are working together correctly for smartcard authentication.

Attempt to log in using the Yubikey on a workstation.
