# This file contains the Pydantic validation models for the HSM configuration file.

from pydantic import BaseModel, ConfigDict, HttpUrl, Field, StringConstraints
from typing_extensions import Annotated
from typing import List, Literal, NewType, Optional, Sequence, Union
from yubihsm.defs import CAPABILITY, ALGORITHM
import click
from click import echo
import yaml


# -----  Pydantic models -----

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

    @staticmethod
    def domain_bitfield_to_nums(bitfield: int) -> set['HSMDomainNum']:
        return {i+1 for i in range(16) if bitfield & (1 << i)}

    @staticmethod
    def capability_from_names(names: set[Union['AsymmetricCapabilityName', 'SymmetricCapabilityName', 'WrapCapabilityName', 'HmacCapabilityName', 'AuthKeyCapabilityName', 'AuthKeyDelegatedCapabilityName', 'WrapDelegateCapabilityName']]) -> CAPABILITY:
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

    @staticmethod
    def capability_to_names(capability: CAPABILITY) -> set:
        names = set()
        for name in CAPABILITY.__members__:
            if capability & getattr(CAPABILITY, name):
                names.add(name.lower().replace("_", "-"))
        if len(names) == 0:
            names.add("none")
        elif len(names) == len(CAPABILITY.__members__):
            names.clear()
            names.add("all")
        return names

    @staticmethod
    def algorithm_from_name(algo: Union['AsymmetricAlgorithm', 'SymmetricAlgorithm', 'WrapAlgorithm', 'HmacAlgorithm', 'OpaqueObjectAlgorithm']) -> ALGORITHM:
        exceptions = {
            'rsa2048': ALGORITHM.RSA_2048, 'rsa3072': ALGORITHM.RSA_3072, 'rsa4096': ALGORITHM.RSA_4096,
            'ecp256': ALGORITHM.EC_P256, 'ecp384': ALGORITHM.EC_P384, 'ecp521': ALGORITHM.EC_P521, 'eck256': ALGORITHM.EC_K256,
            'ecbp256': ALGORITHM.EC_BP256, 'ecbp384': ALGORITHM.EC_BP384, 'ecbp512': ALGORITHM.EC_BP512,
            'ed25519': ALGORITHM.EC_ED25519, 'ecp224': ALGORITHM.EC_P224,
        }
        if algo in exceptions:
            return exceptions[algo]
        name = algo.upper().replace("-", "_")
        res = getattr(ALGORITHM, name)
        assert res is not None, f"Algorithm '{name}' not found in the YubiHSM library."
        return res


# Some type definitions for the models
KeyID = Annotated[int, Field(strict=True, gt=0, lt=0xFFFF)]
KeyLabel = Annotated[str, Field(max_length=40)]
HSMDomainNum = Annotated[int, Field(strict=True, gt=0, lt=17)]
HSMDomainName = Literal["all", "x509", "tls", "nac", "gpg", "codesign", "ssh", "password_derivation", "encryption"]

class HSMDomains(NoExtraBaseModel):
    x509: HSMDomainNum
    tls: HSMDomainNum
    nac: HSMDomainNum
    gpg: HSMDomainNum
    codesign: HSMDomainNum
    ssh: HSMDomainNum
    password_derivation: HSMDomainNum
    encryption: HSMDomainNum



class General(NoExtraBaseModel):
    master_device: str              # serial number of the master device
    all_devices: dict[str, str]     # serial number -> connection URL

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

# -- Wrap key models --
WrapAlgorithm = Literal["aes128-ccm-wrap", "aes192-ccm-wrap", "aes256-ccm-wrap"]
WrapCapabilityName = Literal["none", "wrap-data", "unwrap-data", "export-wrapped", "import-wrapped", "exportable-under-wrap"]
WrapDelegateCapabilityName = Literal[
    "none", "all", "change-authentication-key", "create-otp-aead", "decrypt-oaep", "decrypt-otp", "decrypt-pkcs",
    "delete-asymmetric-key", "delete-authentication-key", "delete-hmac-key", "delete-opaque", "delete-otp-aead-key",
    "delete-template", "delete-wrap-key", "derive-ecdh", "export-wrapped", "exportable-under-wrap", "generate-asymmetric-key",
    "generate-hmac-key", "generate-otp-aead-key", "generate-wrap-key", "get-log-entries", "get-opaque", "get-option",
    "get-pseudo-random", "get-template", "import-wrapped", "put-asymmetric-key", "put-authentication-key", "put-mac-key",
    "put-opaque", "put-otp-aead-key", "put-template", "put-wrap-key", "randomize-otp-aead", "reset-device",
    "rewrap-from-otp-aead-key", "rewrap-to-otp-aead-key", "set-option", "sign-attestation-certificate", "sign-ecdsa",
    "sign-eddsa", "sign-hmac", "sign-pkcs", "sign-pss", "sign-ssh-certificate", "unwrap-data", "verify-hmac", "wrap-data"]
class HSMWrapKey(HSMKeyBase):
    capabilities: set[WrapCapabilityName]
    delegated_capabilities: set[WrapDelegateCapabilityName]
    algorithm: WrapAlgorithm

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

# -- Opaque object models --
OpaqueObjectAlgorithm = Literal["opaque-data", "opaque-x509-certificate"]
class OpaqueObject(HSMKeyBase):
    algorithm: OpaqueObjectAlgorithm
    sign_by: Optional[KeyID]    # ID of the key to sign the object with (if applicable)

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
    signed_certs: List[OpaqueObject] = Field(default_factory=list)  # Storage for signed certificates


# -----  Subsystem models -----

class Admin(NoExtraBaseModel):
    default_admin_password: str
    default_admin_key: HSMAuthKey
    shared_admin_key: HSMAuthKey
    wrap_key: HSMWrapKey
    audit_key: HSMAuthKey

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


# ----- Utility functions -----

def load_hsm_config(file_name: str) -> 'HSMConfig':
    """
    Load a YAML configuration file, validate with Pydantic, and return a HSMConfig object.
    """
    echo("Using config file: " + click.style(file_name, fg='cyan'))
    with click.open_file(file_name) as f:
        hsm_conf = yaml.load(f, Loader=yaml.FullLoader)
    if not isinstance(hsm_conf, dict):
        raise click.ClickException("Configuration file must be a YAML dictionary.")
    res = HSMConfig(**hsm_conf)

    items_per_type, _ = find_all_config_items_per_type(res)
    seen_ids = set()
    for _, key_list in items_per_type.items():
        for key in key_list:
            if hasattr(key, 'id'):
                if key.id in seen_ids:
                    raise click.ClickException(f"Duplicate key ID '{key.id}' found in the configuration file. YubiHSM allows this between different key types, but this tool enforces strict uniqueness.")
                seen_ids.add(key.id)
    return res


def find_config_items_of_class(conf: HSMConfig, cls: type) -> list:
    """
    Find all instances of a given class in the configuration object, recursively.
    """
    from typing import Type, TypeVar, Generator, Any
    T = TypeVar('T')
    def find_instances(obj: Any, target_type: Type[T]) -> Generator[T, None, None]:
        if isinstance(obj, target_type):
            yield obj
        elif isinstance(obj, (list, tuple, set)):
            for item in obj:
                yield from find_instances(item, target_type)
        elif isinstance(obj, dict):
            for value in obj.values():
                yield from find_instances(value, target_type)
        elif hasattr(obj, '__dict__'):
            for value in vars(obj).values():
                yield from find_instances(value, target_type)

    return list(find_instances(conf, cls))



def find_all_config_items_per_type(conf: HSMConfig) -> tuple[dict, dict]:
    """
    Find all instances of each key type in the configuration file.
    Returns a dictionary with lists of each key type, and a mapping from config type to YubiHSM object type.
    """
    import yubihsm.objects

    from hsm_secrets.config import HSMAsymmetricKey, HSMSymmetricKey, HSMWrapKey, OpaqueObject, HSMHmacKey, HSMAuthKey
    config_to_hsm_type = {
        HSMAuthKey: yubihsm.objects.AuthenticationKey,
        HSMWrapKey: yubihsm.objects.WrapKey,
        HSMHmacKey: yubihsm.objects.HmacKey,
        HSMSymmetricKey: yubihsm.objects.SymmetricKey,
        HSMAsymmetricKey: yubihsm.objects.AsymmetricKey,
        OpaqueObject: yubihsm.objects.Opaque,
    }
    config_items_per_type: dict = {t: find_config_items_of_class(conf, t) for t in config_to_hsm_type.keys()} # type: ignore
    return config_items_per_type, config_to_hsm_type
