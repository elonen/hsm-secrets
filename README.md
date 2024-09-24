# `hsm-secrets` – Config file driven CLI for YubiHSM2 ops

[![Integration Tests](https://github.com/elonen/hsm-secrets/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/elonen/hsm-secrets/actions/workflows/integration-tests.yml)

Higher level interactive CLI tool for YubiHSM2 operations, based on a YAML configuration file (see [hsm-conf.yml](hsm-conf.yml)).

The config file approach simplifies planning, setup, validity checking and daily use while maintaining high security standards.

Built mostly on top of Yubico's Python APIs and the Cryptography library.

## Highlights

<table>
  <tbody>
    <tr>
      <td>Define HSM with config file</td>
      <td>
        <ul>
          <li>Single YML file to configure keys, certs and users</li>
          <li>Automatic key/cert generation based on the config file</li>
          <li>Sensible default config with comments</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>High level service tools</td>
      <td>
        <ul>
          <li><strong>TLS</strong> server cert creation</li>
          <li><strong>PIV / Smartcard</strong> cert generation (Windows login with YubiKey)</li>
          <li><strong>Codesigning</strong> (Authenticode) for Windows executables (you'll need <em>osslsigncode</em> also)</li>
          <li><strong>OpenSSH</strong> certificate creation and signing, including hardware token <strong>sk-ed25519</strong> and <strong>sk-ecdsa</strong> keys</li>
          <li>Generic <strong>X.509</strong> certificate creation and signing</li>
          <li>Stateless <strong>password derivation</strong> for VMs etc.</li>
          <li>Sanity checks / lint for generated certificates by usage</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Improved security</td>
      <td>
        <ul>
          <li>Authenticate all daily HSM ops by YubiKey 5 hardware tokens</li>
          <li>Integrated Yubikey (HSMauth slot) management</li>
          <li>When service accounts keys are needed, use ENV for passwords instead of CLI args</li>
          <li>Fully within one process, does not invoke external CLI tools (except in unit tests)</li>
	        <li>Avoid leaking secrets in process listings, disk, or terminal scrollback</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>HSM audit logging</td>
      <td>
        <ul>
          <li>Specify HSM audit policy in config file</li>
          <li>Incrementally fetch and parse log entries from YubiHSM</li>
          <li>Store into SQlite database</li>
          <li>Convenient "forced logging mode" support (with <code>log fetch --clear</code>)</li>
          <li>Show log entries in human-readable format</li>
          <li>Verify audit chain integrity</li>
          <li>Export new logs to JSONL, for log server submission</li>
          <li>Supports multiple devices (for HA / load balancing)</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>Improved Secret Sharing (SSSS) vs. yubihsm-setup</td>
      <td>
        <ul>
          <li>Password protected shares (optional)</li>
          <li>Better display hygiene</li>
          <li>Detailed interactive guiding</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

## Practical Examples

**Example 1: Create a signed OpenSSH user certificate**

```
$ hsm-secrets ssh sign --username "john.doe" --principals "Admins,Users" ~/.ssh/id_ed25519_sk_yubinano_25563692_non-resident.pub

Using config file: hsm-conf.yml
Yubikey hsmauth label: user_john.doe

Signing key with CA ssh-ed25519-ca-root-key as cert ID john.doe-1721680993-admins+users with principals: ['Admins', 'Users']
Authenticating as YubiHSM key ID '0xe001' with local YubiKey (25563692) hsmauth slot 'user_john.doe'
Enter PIN/password for YubiKey HSM slot 'user_john.doe':
Authenticating... (Touch your YubiKey if it blinks)
Session authenticated Ok.

Certificate written to: ~/.ssh/id_ed25519_sk_yubinano_25563692_non-resident-cert.pub
  - Send it to the user and ask them to put it in ~/.ssh/ along with the private key
  - To view it, run: ssh-keygen -L -f /.ssh/id_ed25519_sk_yubinano_25563692_non-resident-cert.pub
  - To allow access (adapt principals as neede), add this to your server authorized_keys file(s):
    cert-authority,principals="Admins,Users" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKoQBm7TClzEQwXlBhYAf7UBx/KwdqWmSjzFs5wMMdbp HSM_ssh-ed25519-ca-root-key
```

Note how all the secrets are safe from malware exfiltration:
 - SSH user's private key is on a YubiKey (sk-ed25519 type)
 - HSM operator auth keys are on a YubiKey (PIN + touch)
 - SSH CA "root" private key is on YubiHSM2

**Example 2: Create and sign an HTTPS certificate**

```
$ hsm-secrets tls server-cert --out certs/wiki-server --common-name "wiki.example.com" --san-dns "docs.example.com"

Using config file: hsm-conf.yml
Yubikey hsmauth label: user_john.doe

Authenticating as YubiHSM key ID '0xe001' with local YubiKey (25563692) hsmauth slot 'user_john.doe'
Enter PIN/password for YubiKey HSM slot 'user_john.doe':
Authenticating... (Touch your YubiKey if it blinks)
Session authenticated Ok.

Signed with CA cert 0x0333: <Name(CN=Example TLS Intermediate I1,O=Example Inc.,L=Duckburg,ST=Calisota,C=US)>
Key written to: ./certs/wiki-server.key.pem
CSR written to: ./certs/wiki-server.csr.pem
Cert written to: ./certs/wiki-server.cer.pem
Chain (bundle) written to: ./certs/wiki-server.chain.pem

To view certificate details, use:
openssl crl2pkcs7 -nocrl -certfile ./certs/wiki-server.cer.pem | openssl  pkcs7 -print_certs | openssl x509 -text -noout
```

In this example, the HTTPS server key was generated and written on local disk, for convenience.
For added separation of concerns, it could also have been created on the web server by a webmaster (perhaps with openssl), and the HSM operator would only have signed the CSR (Certificate Signing Request) with `hsm-secrets tls sign wiki-server.csr.pem`.

## Development

**Work in progress**, but usable and useful.

This rather niche software is being developed to scratch some particular sysops itches, not as a "product".
Even if you don't actually use the tool, I hope this repository shares some knowledge and technical details.
Corrections, improvements and observations are welcome.

## Unit tests

Run `make test` to install requirements and run a test suite.

The tests **do not** use an actual YubiHSM device, but rather a mock
implementation (using `--mock` option) to test the commands with `openssl`, `ssh-keygen` etc.

## Installation and upgrade

**LINUX**:

Assuming you have a `~/bin/` directory in path, this will install(/upgrade) the
tool in a `_venv` and link it into your bin directory:

```
git pull
make clean
make
rm -f ~/bin/hsm-secrets; ln -s $(pwd)/_venv/bin/hsm-secrets ~/bin/
```

**WINDOWS**:

```
git pull
python3 -m venv _venv
_venv\Scripts\activate
pip install setuptools
pip install -r requirements.txt
pip install -e .
```

Then add to PowerShell profile something like this:

```
$env:HSM_SECRETS_CONFIG = "$HOME\hsm-secrets\hsm-conf.yml"
Set-Alias -Name hsm-secrets -Value "$HOME\hsm-secrets\_venv\Scripts\hsm-secrets"
```
...and restart PowerShell. After this configuration, you can call the `hsm-secrets` command from any directory in PowerShell.

## Authentication

Default HSM authentication method depends on the subcommand:
- most daily ops use personal YubiKeys by default
- initial setup / super admin commands use "insecure default admin password" (`password`) by default

The idea is to reactivate the default password when doing super admin key management on a secure (airgapped) computer,
and then deactivate it again for daily use with YubiKeys (and/or password-based service keys, if necessary).

You can always force a different authentication type, though:

- `--auth-yubikey`: force Yubikey login
- `--auth-default-admin`: force default auth key login (for testing etc)
- `--auth-password-id TEXT`:  Auth key ID (hex) to login with password from env HSM_PASSWORD

## HSM initial setup

1. Adapt configuration in `hsm-conf.yml` for your requirements.
   - For details about the format, read the Pydantic 2 schema at [hsm_secrets/config.py](hsm_secrets/config.py)
   - You can check the validity by `hsm-secrets nop`. If it says "No errors", the config file adheres to schema.

2. Perform initial setup on an airgapped system. In summary:
   - Connect all HSMs and reset to factory defaults
   - Distribute a common wrap key with `hsm-secrets hsm backup make-key`
   - Create a Shamir's Shared Secret admin key with `hsm-secrets hsm admin sharing-ceremony`
     - shares can be optionally password-protected
   - Add user YubiKeys with `hsm-secrets user add-yubikey`
   - Generate keys and certificates with `hsm-secrets hsm objects create-missing`
   - Apply your logging settings from config to the device with `hsm log apply-settings`
   - Check that everything's been created with `hsm compare`
   - Clone master HSM to other devices using `hsm backup export` and `hsm backup import`

   See [Setup Workflow](doc/setup-workflow.md) for the full process.

3. For day-to-day use, operators authenticate with YubiKeys to run commands, such as:
   - `hsm-secrets ssh sign` to sign SSH certs
   - `hsm-secrets tls sign` to sign TLS certs
   - `hsm-secrets pass get` to derive a password
   - `hsm-secrets pass rotate` to rotate derived password(s)

4. Rarely, for admin changes, on an airgapped computer:
   - Temporarily enable default admin key with `hsm-secrets hsm admin default-enable` (asks key custodians for SSSS shared secret)
   - Make changes on one of the devices (master)
   - Re-clone HSMs with `hsm backup export` and `hsm backup import`
   - Disable the default admin again with `hsm-secrets hsm admin default-disable`

YubiHSM2 devices are easy to reset, so you might want to do a test-run or two before an actual production deployment.

## License

Released under the MIT license

Copyright 2024 by Jarno Elonen

## Disclaimer

The software is provided "as is", the license disclaims any warranties and liabilities. Use at your own risk.

Thoroughly audit before production use, and use it as part of a comprehensive security strategy.
