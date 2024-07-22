# `hsm-secrets` - Config-file driven CLI for YubiHSM2 setup and operations

Streamlined CLI tool for YubiHSM2 operations, based on a YAML configuration file (see [hsm-conf.yml](hsm-conf.yml) for example). The config file approach simplifies planning, setup and daily use while maintaining high security standards. The config file does not contain any secrets, only the devices.

All the sub-commands are implemented in Python, and designed to simplify daily operations under a single tool, authenticated by the YubiKey 5 hsmauth to avoid operator credential leaks by malware.

## Status

Work-in-progress, but usable and useful.

## Features

- Centralized configuration in a single YAML file
- Streamlined setup process with guided commands
- Cloning for High availability (HA)
- Enhanced daily operation security with YubiKey authentication
- Password-protected Shamir's Shared Secret k-of-n super admin key
- OpenSSH certificate management, including hardware token **sk-ed25519** and **sk-ecdsa** keys
- X.509 certificate management (TLS, SSH, X.509)
- Secure password derivation for service accounts

## Installation and upgrade

Assuming you have a `~/bin/` directory in path, this will install(/upgrade) the
tool in a `_venv` and link it into your bin directory:

```
git pull
make clean
make
rm -f ~/bin/hsm-secrets; ln -s $(pwd)/_venv/bin/hsm-secrets ~/bin/
```

## HSM Setup and Usage

1. Adapt HSM configuration in `hsm-conf.yml` for your requirements

2. Perform initial setup on an airgapped system. In summary:
   - Connect all HSMs and reset to factory defaults
   - Distribute a common wrap key with `hsm-secrets hsm make-common-wrap-key`
   - Create a Shamir's Shared Secret admin key with `hsm-secrets hsm make-shared-admin-key`
     - shares can be optionally password-protected
   - Add user YubiKeys with `hsm-secrets user add-user-yubikey`
   - Generate keys and certificates with `hsm-secrets hsm compare-config --create` and `hsm-secrets x509 create-cert --all`
   - Clone master HSM to other devices using `backup-hsm` and `restore-hsm`

   See [Setup Workflow](doc/setup-workflow.md) for the full process.

3. For day-to-day use, operators authenticate with YubiKeys to run commands, such as:
   - `hsm-secrets ssh sign-key` to sign SSH certs
   - `hsm-secrets tls sign-csr` to sign TLS certs
   - `hsm-secrets pass get` to derive service passwords

4. Rarely, for admin changes, on an airgapped computer:
   - Temporarily enable default admin key with `hsm-secrets hsm insecure-admin-key-enable` (asks key custodians for SSSS shared secret)
   - Make changes on one of the devices (master)
   - Re-clone HSMs with `backup-hsm` and `restore-hsm`
   - Disable the default admin again with `hsm-secrets hsm insecure-admin-key-disable`

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

Thoroughly audit before production use, and use it as part of a comprehensive security strategy.
The software is provided "as is", the license disclaims any warranties and liabilities. Use at your own risk.
