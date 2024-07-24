# `hsm-secrets` – Config file driven CLI for YubiHSM2 ops

Higher level interactive CLI tool for YubiHSM2 operations, based on a YAML configuration file (see [hsm-conf.yml](hsm-conf.yml)).

The config file approach simplifies planning, setup and daily use while maintaining high security standards.

## Highlights

- Centralized configuration in a single YAML file
  - Automatic key/cert generation based on the config file
- Authenticate HSM operators by YubiKey 5 hardware tokens to avoid credential theft by malware
  - Integrated Yubikey HSM auth (yubihsm-auth) slot setup for operators
- Discourage leaking secrets in process listing, local disk or terminal history
  - Fully within one process, does not invoke external CLI processes
- Integrate daily operations under a single tool:
  - OpenSSH certificate creation and signing, including hardware token **sk-ed25519** and **sk-ecdsa** keys
  - X.509 certificate creationg and signing (TLS, SSH, X.509)
  - Password derivation for VMs etc.
- Improved Secret Sharing ceremony vs. YubiHSM setup util (vs. yubihsm-setup)
  - password protected shares (optional)
  - better display hygiene
  - detailed interactive guiding

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

## Development status

Work-in-progress, but usable and useful.

## Installation and upgrade

Assuming you have a `~/bin/` directory in path, this will install(/upgrade) the
tool in a `_venv` and link it into your bin directory:

```
git pull
make clean
make
rm -f ~/bin/hsm-secrets; ln -s $(pwd)/_venv/bin/hsm-secrets ~/bin/
```

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
   - Distribute a common wrap key with `hsm-secrets hsm make-wrap-key`
   - Create a Shamir's Shared Secret admin key with `hsm-secrets hsm admin-sharing-ceremony`
     - shares can be optionally password-protected
   - Add user YubiKeys with `hsm-secrets user add-yubikey`
   - Generate keys and certificates with `hsm-secrets hsm compare --create` and `hsm-secrets x509 create --all`
   - Clone master HSM to other devices using `hsm backup` and `hsm restore`

   See [Setup Workflow](doc/setup-workflow.md) for the full process.

3. For day-to-day use, operators authenticate with YubiKeys to run commands, such as:
   - `hsm-secrets ssh sign` to sign SSH certs
   - `hsm-secrets tls sign` to sign TLS certs
   - `hsm-secrets pass get` to derive a password
   - `hsm-secrets pass rotate` to rotate derived password(s)

4. Rarely, for admin changes, on an airgapped computer:
   - Temporarily enable default admin key with `hsm-secrets hsm default-admin-enable` (asks key custodians for SSSS shared secret)
   - Make changes on one of the devices (master)
   - Re-clone HSMs with `hsm backup` and `hsm restore`
   - Disable the default admin again with `hsm-secrets hsm default-admin-disable`

YubiHSM2 devices are easy to reset, so you might want to do a test-run or two before an actual production deployment.

## Security tips

- Always perform setup on airgapped systems
- Password-protect the shared admin secrets
- Secure physical access to HSMs
- Favor YubiKey auth for daily operations over service accounts
- Audit HSM logs

Airgapped setup is necessary to prevent supply chain attacks from exfiltrating any generated secrets.
You might want to use something like Tails Linux on USB stick, and wipe/destroy the media after setup.

## Disclaimer

The software is provided "as is", the license disclaims any warranties and liabilities. Use at your own risk.

Thoroughly audit before production use, and use it as part of a comprehensive security strategy.
