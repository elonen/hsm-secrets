# This file contains the Pydantic validation models for the HSM configuration file.

from pydantic import BaseModel, HttpUrl, Field, StringConstraints
from typing_extensions import Annotated
from typing import Literal, NewType
import click
from click import echo
import yaml


def load_hsm_config(file_name: str) -> 'HSMConfig':
    """
    Load a YAML configuration file, validate with Pydantic, and return a HSMConfig object.
    """
    echo("Using config file: " + click.style(file_name, fg='cyan'))
    with click.open_file(file_name) as f:
        hsm_conf = yaml.load(f, Loader=yaml.FullLoader)
    if not isinstance(hsm_conf, dict):
        raise click.ClickException("Configuration file must be a YAML dictionary.")
    return HSMConfig(**hsm_conf)


# ----------------- Pydantic models -----------------

class HSMConfig(BaseModel):
    general: 'General'
    admin: 'Admin'
    ssh: 'SSH'

    def find_auth_key(self, label: str) -> 'HSMAuthKey':
        for key_set in [self.admin.auth_keys, self.ssh.auth_keys]:
            for key in key_set:
                if key.label == label:
                    return key
        raise ValueError(f"Auth key '{label}' not found in the configuration file.")


class HSMDomains(BaseModel):
    device_admin: Annotated[int, Field(strict=True, gt=0, lt=17, alias='device-admin')]
    openssh: Annotated[int, Field(strict=True, gt=0, lt=17)]
    tls: Annotated[int, Field(strict=True, gt=0, lt=17)]
    password_derivation: Annotated[int, Field(strict=True, gt=0, lt=17, alias='password-derivation')]

class General(BaseModel):
    connector_url: HttpUrl
    domains: HSMDomains

# Some type definitions for the models
KeyID = Annotated[int, Field(strict=True, gt=0, lt=0xFFFF)]
KeyLabel = Annotated[str, Field(max_length=40)]
DomainNum = Annotated[int, Field(strict=True, gt=0, lt=17)]


AsymmetricAlgorithm = Literal["rsa2048", "rsa3072", "rsa4096", "ecp256", "ecp384", "ecp521", "eck256", "ecbp256", "ecbp384", "ecbp512", "ed25519", "ecp224"]
AsymmetricCapabilityName = Literal[
    "none", "sign-pkcs", "sign-pss", "sign-ecdsa", "sign-eddsa", "decrypt-pkcs", "decrypt-oaep", "derive-ecdh",
    "exportable-under-wrap", "sign-ssh-certificate", "sign-attestation-certificate"
]
class HSMAsymmetricKey(BaseModel):
    label: KeyLabel
    id: KeyID
    domains: list[Annotated[int, Field(strict=True, gt=0, lt=17)]]
    capabilities: set[AsymmetricCapabilityName]
    algorithm: AsymmetricAlgorithm


AuthKeyCapabilityName = Literal[
    "none", "all", "change-authentication-key", "create-otp-aead", "decrypt-oaep", "decrypt-otp", "decrypt-pkcs",
    "delete-asymmetric-key", "delete-authentication-key", "delete-hmac-key", "delete-opaque", "delete-otp-aead-key",
    "delete-template", "delete-wrap-key", "derive-ecdh", "export-wrapped", "exportable-under-wrap", "generate-asymmetric-key",
    "generate-hmac-key", "generate-otp-aead-key", "generate-wrap-key", "get-log-entries", "get-opaque", "get-option",
    "get-pseudo-random", "get-template", "import-wrapped", "put-asymmetric-key", "put-authentication-key", "put-mac-key",
    "put-opaque", "put-otp-aead-key", "put-template", "put-wrap-key", "randomize-otp-aead", "reset-device",
    "rewrap-from-otp-aead-key", "rewrap-to-otp-aead-key", "set-option", "sign-attestation-certificate", "sign-ecdsa",
    "sign-eddsa", "sign-hmac", "sign-pkcs", "sign-pss", "sign-ssh-certificate", "unwrap-data", "verify-hmac", "wrap-data"
]
AuthKeyDelegatedCapabilityName = Literal[
    "none", "all", "change-authentication-key", "create-otp-aead", "decrypt-oaep", "decrypt-otp", "decrypt-pkcs",
    "delete-asymmetric-key", "delete-authentication-key", "delete-hmac-key", "delete-opaque", "delete-otp-aead-key",
    "delete-template", "delete-wrap-key", "derive-ecdh", "export-wrapped", "exportable-under-wrap", "generate-asymmetric-key",
    "generate-hmac-key", "generate-otp-aead-key", "generate-wrap-key", "get-log-entries", "get-opaque", "get-option",
    "get-pseudo-random", "get-template", "import-wrapped", "put-asymmetric-key", "put-authentication-key", "put-mac-key",
    "put-opaque", "put-otp-aead-key", "put-template", "put-wrap-key", "randomize-otp-aead", "reset-device",
    "rewrap-from-otp-aead-key", "rewrap-to-otp-aead-key", "set-option", "sign-attestation-certificate", "sign-ecdsa",
    "sign-eddsa", "sign-hmac", "sign-pkcs", "sign-pss", "sign-ssh-certificate", "unwrap-data", "verify-hmac", "wrap-data"
]

class HSMAuthKey(BaseModel):
    label: Annotated[str, StringConstraints(max_length=40)]
    id: Annotated[int, Field(strict=True, gt=0, lt=0xFFFF)]
    domains: list[Annotated[int, Field(strict=True, gt=0, lt=17)]]
    capabilities: set[AuthKeyCapabilityName]
    delegated_capabilities: set[AuthKeyDelegatedCapabilityName]

class Admin(BaseModel):
    auth_keys: list[HSMAuthKey]

class SSH(BaseModel):
    root_ca_keys: list[HSMAsymmetricKey]
    auth_keys: list[HSMAuthKey]

