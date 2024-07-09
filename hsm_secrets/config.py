# This file contains the Pydantic validation models for the HSM configuration file.

from pydantic import BaseModel, ConfigDict, HttpUrl, Field, StringConstraints
from typing_extensions import Annotated
from typing import List, Literal, NewType, Optional, Sequence, Union
from yubihsm.defs import CAPABILITY
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

class NoExtraBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HSMConfig(NoExtraBaseModel):
    general: 'General'
    user_keys: list['HSMAuthKey']
    service_keys: list['HSMAuthKey']

    admin: 'Admin'
    x509: 'X509'
    tls: 'TLS'
    nac: 'NAC'
    gpg: 'GPG'
    codesign: 'CodeSign'
    ssh: 'SSH'
    password_derivation: 'PasswordDerivation'
    encryption: 'Encryption'

    def find_auth_key(self, label: str) -> 'HSMAuthKey':
        for key_set in [self.user_keys, self.service_keys]:
            for key in key_set:
                if key.label == label:
                    return key
        raise ValueError(f"Auth key '{label}' not found in the configuration file.")

    def get_domain_nums(self, names: Sequence['HSMDomainName']) -> set['HSMDomainNum']:
        if 'all' in names:
            return {i+1 for i in range(16)}
        else:
            return {getattr(self.general.domains, name) for name in names}

    def get_domain_bitfield(self, names: set['HSMDomainName']) -> int:
        res = sum(1 << (num-1) for num in self.get_domain_nums(tuple(names)))
        assert 0 <= res <= 0xFFFF, f"Domain bitfield out of range: {res}"
        return res

    def CapabilityFromNames(self, names: set[Union['AsymmetricCapabilityName', 'SymmetricCapabilityName', 'HmacCapabilityName', 'AuthKeyCapabilityName', 'AuthKeyDelegatedCapabilityName']]) -> CAPABILITY:
        capability = CAPABILITY.NONE
        for name in names:
            if name == "none":
                continue
            elif name == "all":
                return CAPABILITY.ALL
            else:
                try:
                    capability |= getattr(CAPABILITY, name.upper().replace("-", "_"))
                except AttributeError:
                    raise ValueError(f"Unknown capability name: {name}")
        return capability



# Some type definitions for the models
KeyID = Annotated[int, Field(strict=True, gt=0, lt=0xFFFF)]
KeyLabel = Annotated[str, Field(max_length=40)]
HSMDomainNum = Annotated[int, Field(strict=True, gt=0, lt=17)]
HSMDomainName = Literal["all", "device_admin", "x509", "tls", "nac", "gpg", "codesign", "ssh", "password_derivation", "encryption", "service_keys", "user_keys"]

class HSMDomains(NoExtraBaseModel):
    device_admin: HSMDomainNum
    service_keys: HSMDomainNum
    user_keys: HSMDomainNum

    x509: HSMDomainNum
    tls: HSMDomainNum
    nac: HSMDomainNum
    gpg: HSMDomainNum
    codesign: HSMDomainNum
    ssh: HSMDomainNum
    password_derivation: HSMDomainNum
    encryption: HSMDomainNum


class General(NoExtraBaseModel):
    connector_url: HttpUrl
    domains: HSMDomains
    x509_defaults: 'X509Info'


class HSMKeyBase(NoExtraBaseModel):
    model_config = ConfigDict(extra="forbid")
    label: KeyLabel
    id: KeyID
    domains: set[HSMDomainName]


# -- Asymmetric key models --
AsymmetricAlgorithm = Literal["rsa2048", "rsa3072", "rsa4096", "ecp256", "ecp384", "ecp521", "eck256", "ecbp256", "ecbp384", "ecbp512", "ed25519", "ecp224"]
AsymmetricCapabilityName = Literal[
    "none", "sign-pkcs", "sign-pss", "sign-ecdsa", "sign-eddsa", "decrypt-pkcs", "decrypt-oaep", "derive-ecdh",
    "exportable-under-wrap", "sign-ssh-certificate", "sign-attestation-certificate"
]
class HSMAsymmetricKey(HSMKeyBase):
    capabilities: set[AsymmetricCapabilityName]
    algorithm: AsymmetricAlgorithm

# -- Symmetric key models --
SymmetricAlgorithm = Literal["aes128", "aes192", "aes256"]
SymmetricCapabilityName = Literal["none", "encrypt-ecb", "decrypt-ecb", "encrypt-cbc", "decrypt-cbc", "exportable-under-wrap"]
class HSMSymmetricKey(HSMKeyBase):
    capabilities: set[SymmetricCapabilityName]
    algorithm: SymmetricAlgorithm

# -- HMAC key models --
HmacAlgorithm = Literal["hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512"]
HmacCapabilityName = Literal["none", "sign-hmac", "verify-hmac", "exportable-under-wrap"]
class HSMHmacKey(HSMKeyBase):
    capabilities: set[HmacCapabilityName]
    algorithm: HmacAlgorithm

# -- Auth key models --
AuthKeyCapabilityName = Literal[
    "none", "all", "change-authentication-key", "create-otp-aead", "decrypt-oaep", "decrypt-otp", "decrypt-pkcs",
    "delete-asymmetric-key", "delete-authentication-key", "delete-hmac-key", "delete-opaque", "delete-otp-aead-key",
    "delete-template", "delete-wrap-key", "derive-ecdh", "export-wrapped", "exportable-under-wrap", "generate-asymmetric-key",
    "generate-hmac-key", "generate-otp-aead-key", "generate-wrap-key", "get-log-entries", "get-opaque", "get-option",
    "get-pseudo-random", "get-template", "import-wrapped", "put-asymmetric-key", "put-authentication-key", "put-mac-key",
    "put-opaque", "put-otp-aead-key", "put-template", "put-wrap-key", "randomize-otp-aead", "reset-device",
    "rewrap-from-otp-aead-key", "rewrap-to-otp-aead-key", "set-option", "sign-attestation-certificate", "sign-ecdsa",
    "sign-eddsa", "sign-hmac", "sign-pkcs", "sign-pss", "sign-ssh-certificate", "unwrap-data", "verify-hmac", "wrap-data",
    "decrypt-ecb", "encrypt-ecb", "decrypt-cbc", "encrypt-cbc",
]
AuthKeyDelegatedCapabilityName = Literal[
    "none", "all", "change-authentication-key", "create-otp-aead", "decrypt-oaep", "decrypt-otp", "decrypt-pkcs",
    "delete-asymmetric-key", "delete-authentication-key", "delete-hmac-key", "delete-opaque", "delete-otp-aead-key",
    "delete-template", "delete-wrap-key", "derive-ecdh", "export-wrapped", "exportable-under-wrap", "generate-asymmetric-key",
    "generate-hmac-key", "generate-otp-aead-key", "generate-wrap-key", "get-log-entries", "get-opaque", "get-option",
    "get-pseudo-random", "get-template", "import-wrapped", "put-asymmetric-key", "put-authentication-key", "put-mac-key",
    "put-opaque", "put-otp-aead-key", "put-template", "put-wrap-key", "randomize-otp-aead", "reset-device",
    "rewrap-from-otp-aead-key", "rewrap-to-otp-aead-key", "set-option", "sign-attestation-certificate", "sign-ecdsa",
    "sign-eddsa", "sign-hmac", "sign-pkcs", "sign-pss", "sign-ssh-certificate", "unwrap-data", "verify-hmac", "wrap-data",
    "decrypt-ecb", "encrypt-ecb", "decrypt-cbc", "encrypt-cbc",
]
class HSMAuthKey(HSMKeyBase):
    capabilities: set[AuthKeyCapabilityName]
    delegated_capabilities: set[AuthKeyDelegatedCapabilityName]

# -- Helper models --
X509KeyUsage = Literal[
    "digitalSignature",     # Allow signing files, messages, etc.
    "nonRepudiation",       # Allow for assurance of the signer's identity, preventing them from denying their actions (e.g. in legal disputes)
    "keyEncipherment",      # Allow for encrypting other keys
    "dataEncipherment",     # Allow encrypting data (not usual for certificates)
    "keyAgreement",         # Allow use in key exchange (Diffie-Hellman)
    "keyCertSign",          # Allow signing other certificates (=CA)
    "cRLSign",              # Allow signing certificate revocation lists
    "encipherOnly",         # In keyAgreement: only allow encryption, not decryption
    "decipherOnly"          # In keyAgreement: only allow decryption, not encryption
]
X509ExtendedKeyUsage = Literal["serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping"]

class X509CertAttribs(NoExtraBaseModel):
    common_name: str                                    # FQDN for host, or username for user, etc.
    subject_alt_names: List[str]                        # Subject Alternative Names (SANs)
    organization: Optional[str] = Field(default=None)   # Legal entity name
    # organizational_unit: str                          # Deprecated TLS field, so commented out
    locality: Optional[str] = Field(default=None)       # City
    state: Optional[str] = Field(default=None)          # State or province where the organization is located
    country: Optional[str] = Field(default=None)        # Country code (2-letter ISO 3166-1)

class X509Info(NoExtraBaseModel):
    is_ca: Optional[bool] = Field(default=True)         # Is this a CA certificate? If so, make sure to include keyCertSign and cRLSign in key_usage
    validity_days: Optional[int] = Field(default=3650)  # Default validity period for the certificate
    attribs: Optional[X509CertAttribs] = Field(default=None)
    key_usage: Optional[set[X509KeyUsage]] = Field(default=None)
    extended_key_usage: Optional[set[X509ExtendedKeyUsage]] = Field(default=None)

class X509Cert(NoExtraBaseModel):
    key: HSMAsymmetricKey
    x509_info: Optional[X509Info] = Field(default=None) # If None, use the default values from the global configuration (applies to sub-fields, too)



# ----------------- Subsystem models -----------------

class Admin(NoExtraBaseModel):
    wrap_key_id_min: KeyID
    wrap_key_id_max: KeyID
    default_admin_password: str
    default_admin_key: HSMAuthKey
    shared_admin_key: HSMAuthKey


class X509(NoExtraBaseModel):
    root_certs: List[X509Cert]

class TLS(NoExtraBaseModel):
    intermediate_certs: List[X509Cert]

class NAC(NoExtraBaseModel):
    intermediate_certs: List[X509Cert]

class GPG(NoExtraBaseModel):
    keys: List[HSMAsymmetricKey]

class CodeSign(NoExtraBaseModel):
    intermediate_certs: List[X509Cert]

class SSHTemplateSlots(NoExtraBaseModel):
    min: int
    max: int

class SSH(NoExtraBaseModel):
    root_ca_keys: List[HSMAsymmetricKey]
    template_slots: SSHTemplateSlots

class PasswordDerivation(NoExtraBaseModel):
    keys: List[HSMHmacKey]

class Encryption(NoExtraBaseModel):
    keys: List[HSMSymmetricKey]
