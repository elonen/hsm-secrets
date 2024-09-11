# This file contains the Pydantic validation models for the HSM configuration file.

from dataclasses import dataclass
from datetime import datetime
import os
import re
import typing
import click.shell_completion
from pydantic import BaseModel, ConfigDict, HttpUrl, Field, StringConstraints
from typing_extensions import Annotated
from typing import Any, Callable, Dict, Iterable, List, Literal, NewType, Optional, Sequence, TypeVar, Union, cast
from yubihsm.defs import CAPABILITY, ALGORITHM, COMMAND  # type: ignore [import]
import click
import yaml	# type: ignore [import]

class NoExtraBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

AnyCapability = Union['AsymmetricCapabilityName', 'SymmetricCapabilityName', 'WrapCapabilityName', 'HmacCapabilityName', 'AuthKeyCapabilityName', 'AuthKeyDelegatedCapabilityName', 'WrapDelegateCapabilityName']

# Some type definitions for the models
HSMKeyID = Annotated[int, Field(strict=True, gt=0, lt=0xFFFF)]
HSMKeyLabel = Annotated[str, Field(max_length=40)]
HSMDomainNum = Annotated[int, Field(strict=True, gt=0, lt=17)]
HSMDomainName = Literal["all", "x509", "tls", "nac","piv",  "ssh", "gpg", "codesign", "password_derivation", "encryption"]

class HSMObjBase(NoExtraBaseModel):
    model_config = ConfigDict(extra="forbid")
    label: HSMKeyLabel
    id: HSMKeyID
    domains: set[HSMDomainName]


# -----  Config model tree -----
T = TypeVar('T')

class HSMConfig(NoExtraBaseModel):
    general: 'HSMConfig.General'
    user_keys: list['HSMAuthKey']
    service_keys: list['HSMAuthKey']

    admin: 'HSMConfig.Admin'
    x509: 'HSMConfig.X509'
    tls: 'HSMConfig.TLS'
    nac: 'HSMConfig.NAC'
    piv: 'HSMConfig.PIV'
    gpg: 'HSMConfig.GPG'
    codesign: 'HSMConfig.CodeSign'
    ssh: 'HSMConfig.SSH'
    password_derivation: 'HSMConfig.PasswordDerivation'
    encryption: 'HSMConfig.Encryption'

    class General(NoExtraBaseModel):
        master_device: str              # serial number of the master device
        all_devices: dict[str, str]     # serial number -> connection URL

        domains: 'HSMDomains'
        x509_defaults: 'X509CertInfo'

        class HSMDomains(NoExtraBaseModel):
            x509: HSMDomainNum
            tls: HSMDomainNum
            nac: HSMDomainNum
            piv: HSMDomainNum
            ssh: HSMDomainNum
            gpg: HSMDomainNum
            codesign: HSMDomainNum
            password_derivation: HSMDomainNum
            encryption: HSMDomainNum

    class Admin(NoExtraBaseModel):
        default_admin_password: str
        default_admin_key: 'HSMAuthKey'
        shared_admin_key: 'HSMAuthKey'
        wrap_key: 'HSMWrapKey'
        audit: 'HSMAuditSettings'

    class X509(NoExtraBaseModel):
        root_certs: List['X509CA']

    class TLS(NoExtraBaseModel):
        default_ca_id: HSMKeyID
        intermediate_cas: List['X509CA']

    class PIV(NoExtraBaseModel):
        default_ca_id: HSMKeyID
        default_piv_domain: str
        intermediate_cas: List['X509CA']
        dc_cert_templates: Dict[str, 'X509CertInfo']  # Overrides global defaults
        user_cert_templates: Dict[str, 'X509CertInfo']

    class NAC(NoExtraBaseModel):
        intermediate_cas: List['X509CA']

    class GPG(NoExtraBaseModel):
        keys: List['HSMAsymmetricKey']

    class CodeSign(NoExtraBaseModel):
        certs: List['X509CA']

    class SSHTemplateSlots(NoExtraBaseModel):
        min: int
        max: int

    class SSH(NoExtraBaseModel):
        default_user_ca: HSMKeyID
        default_host_ca: HSMKeyID
        root_ca_keys: List['HSMAsymmetricKey']

    class PasswordDerivation(NoExtraBaseModel):
        keys: List['HSMHmacKey']
        default_rule: HSMKeyLabel
        rules: List['PwdRule']

        class PwdRule(NoExtraBaseModel):
            id: HSMKeyLabel
            key: HSMKeyID
            format: Literal["bip39", "hex"] = Field(default="bip39")
            separator: str = Field(default=".")
            bits: Literal[64, 128, 256] = Field(default=64)
            rotation_tokens: List['PwdRotationToken'] = Field(default_factory=list)

            class PwdRotationToken(NoExtraBaseModel):
                name_hmac: Optional[Annotated[int, Field(strict=True, gt=0)]] = Field(default=None)
                nonce: Annotated[int, Field(strict=True, gt=0)]
                ts: Annotated[int, Field(strict=True, ge=0)]

    class Encryption(NoExtraBaseModel):
        keys: List['HSMSymmetricKey']


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

    def find_def(self, id_or_label: Union[int, str], type_to_find: type[T], sub_conf: Any = None) -> T:
        assert type_to_find is not None, "enforce_type cannot be None, use find_def_non_typed() instead."
        res = self.find_def_non_typed(id_or_label, type_to_find, sub_conf)
        assert isinstance(res, type_to_find), f"Expected type {type_to_find}, but got {type(res)}"
        return res

    def find_def_non_typed(self, id_or_label: Union[int, str], type_to_find: Optional[type] = None, sub_conf: Any|None = None) -> 'HSMObjBase':
        return _find_def_by_id_or_label(sub_conf or self, id_or_label, type_to_find)

    @staticmethod
    def domain_bitfield_to_nums(bitfield: int) -> set['HSMDomainNum']:
        return {i+1 for i in range(16) if bitfield & (1 << i)}

    @classmethod
    def capability_from_names(cls, names: Iterable[AnyCapability]) -> CAPABILITY:
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

    @classmethod
    def delegated_capability_from_names(
        cls,
        names: Iterable[Union['AuthKeyDelegatedCapabilityName', 'WrapDelegateCapabilityName']],
        non_delegated_caps: Optional[Iterable[AnyCapability]] = None
    ) -> CAPABILITY:
        """
        Convert a set of delegated capability names to a bitfield.
        If 'same' is included in the names, the non-delegated capabilities must be passed in as well,
        and the resulting bitfield will include both the 'names' and 'non_delegated_caps' sets.
        """
        names_set = {n for n in names}
        without_same: list[AnyCapability] = [cast(AnyCapability, n) for n in (names_set - {"same"})]
        res = cls.capability_from_names(without_same)
        if "same" in names:
            assert non_delegated_caps is not None, "Cannot use 'same' in delegated capabilities without passing in non-delegated capabilities."
            res |= cls.capability_from_names(non_delegated_caps)
        return res


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


# -- Logging / audit --

YubiHsm2AuditMode = Literal['off', 'on', 'fixed']
YubiHsm2Command = Literal['echo', 'create-session', 'authenticate-session', 'session-message', 'device-info', 'reset-device', 'get-device-public-key', 'close-session', 'get-storage-info', 'put-opaque', 'get-opaque', 'put-authentication-key', 'put-asymmetric-key', 'generate-asymmetric-key', 'sign-pkcs1', 'list-objects', 'decrypt-pkcs1', 'export-wrapped', 'import-wrapped', 'put-wrap-key', 'get-log-entries', 'get-object-info', 'set-option', 'get-option', 'get-pseudo-random', 'put-hmac-key', 'sign-hmac', 'get-public-key', 'sign-pss', 'sign-ecdsa', 'derive-ecdh', 'delete-object', 'decrypt-oaep', 'generate-hmac-key', 'generate-wrap-key', 'verify-hmac', 'sign-ssh-certificate', 'put-template', 'get-template', 'decrypt-otp', 'create-otp-aead', 'randomize-otp-aead', 'rewrap-otp-aead', 'sign-attestation-certificate', 'put-otp-aead-key', 'generate-otp-aead-key', 'set-log-index', 'wrap-data', 'unwrap-data', 'sign-eddsa', 'blink-device', 'change-authentication-key', 'put-symmetric-key', 'generate-symmetric-key', 'decrypt-ecb', 'encrypt-ecb', 'decrypt-cbc', 'encrypt-cbc']
class HSMAuditSettings(NoExtraBaseModel):
    forced_audit: YubiHsm2AuditMode
    default_command_logging: YubiHsm2AuditMode
    command_logging: dict[YubiHsm2Command, YubiHsm2AuditMode]

    def apply_defaults(self):
        # Fill command_logging with default value for any missing commands
        for cmd in typing.get_args(YubiHsm2Command):
            if cmd not in self.command_logging:
                self.command_logging[cmd] = self.default_command_logging

def lookup_hsm_cmd(cmd: YubiHsm2Command) -> COMMAND:
    x = COMMAND._member_map_[cmd.upper().replace("-","_")]
    assert isinstance(x, COMMAND), f"Command '{cmd}' not found in the YubiHSM library."
    return x

# -- Asymmetric key models --
AsymmetricAlgorithm = Literal["rsa2048", "rsa3072", "rsa4096", "ecp256", "ecp384", "ecp521", "eck256", "ecbp256", "ecbp384", "ecbp512", "ed25519", "ecp224"]
AsymmetricCapabilityName = Literal[
    "none", "sign-pkcs", "sign-pss", "sign-ecdsa", "sign-eddsa", "decrypt-pkcs", "decrypt-oaep", "derive-ecdh",
    "exportable-under-wrap", "sign-ssh-certificate", "sign-attestation-certificate"
]
class HSMAsymmetricKey(HSMObjBase):
    capabilities: set[AsymmetricCapabilityName]
    algorithm: AsymmetricAlgorithm

# -- Symmetric key models --
SymmetricAlgorithm = Literal["aes128", "aes192", "aes256"]
SymmetricCapabilityName = Literal["none", "encrypt-ecb", "decrypt-ecb", "encrypt-cbc", "decrypt-cbc", "exportable-under-wrap"]
class HSMSymmetricKey(HSMObjBase):
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
class HSMWrapKey(HSMObjBase):
    capabilities: set[WrapCapabilityName]
    delegated_capabilities: set[WrapDelegateCapabilityName]
    algorithm: WrapAlgorithm

# -- HMAC key models --
HmacAlgorithm = Literal["hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512"]
HmacCapabilityName = Literal["none", "sign-hmac", "verify-hmac", "exportable-under-wrap"]
class HSMHmacKey(HSMObjBase):
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
    "same"
]
class HSMAuthKey(HSMObjBase):
    capabilities: set[AuthKeyCapabilityName]
    delegated_capabilities: set[AuthKeyDelegatedCapabilityName]

# -- Opaque object models --
OpaqueObjectAlgorithm = Literal["opaque-data", "opaque-x509-certificate"]
class HSMOpaqueObject(HSMObjBase):
    algorithm: OpaqueObjectAlgorithm
    sign_by: Optional[HSMKeyID]    # ID of the key to sign the object with (if applicable)

# -- Helper models --
X509KeyUsageName = Literal[
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
X509ExtendedKeyUsageName = Literal["serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping", "ocspSigning", "anyExtendedKeyUsage", "smartcardLogon", "kerberosPKINITKDC"]
X509NameType = Literal["dns", "ip", "rfc822", "uri", "upn", "directory", "registered_id", "oid"]

class X509Extension(BaseModel):
    critical: bool = False

class X509CertInfo(NoExtraBaseModel):
    validity_days: Optional[int] = None
    attribs: Optional['X509CertInfo.CertAttribs'] = None
    basic_constraints: Optional['X509CertInfo.BasicConstraints'] = None
    key_usage: Optional['X509CertInfo.KeyUsage'] = None
    extended_key_usage: Optional['X509CertInfo.ExtendedKeyUsage'] = None
    subject_alt_name: Optional['X509CertInfo.SubjectAltName'] = None
    issuer_alt_name: Optional['X509CertInfo.IssuerAltName'] = None
    subject_key_identifier: Optional['X509CertInfo.SubjectKeyIdentifier'] = None
    authority_key_identifier: Optional['X509CertInfo.AuthorityKeyIdentifier'] = None
    name_constraints: Optional['X509CertInfo.NameConstraints'] = None
    certificate_policies: Optional['X509CertInfo.CertificatePolicies'] = None
    policy_constraints: Optional['X509CertInfo.PolicyConstraints'] = None
    inhibit_any_policy: Optional['X509CertInfo.InhibitAnyPolicy'] = None

    # Nested models (x509 extensions)

    class BasicConstraints(X509Extension):
        ca: bool = True
        path_len: Optional[int] = 0

        def __init__(self, **data):
            super().__init__(**data)
            # set Basic Constraints critical by default unless explicitly set to False
            if 'critical' not in data:
                self.critical = True

    class CertAttribs(NoExtraBaseModel):
        common_name: str                                    # FQDN for host, or username for user, etc.
        organization: Optional[str] = Field(default=None)   # Legal entity name
        organizational_unit: str = Field(default=None)      # NOTE: Deprecated TLS field
        locality: Optional[str] = Field(default=None)       # City
        state: Optional[str] = Field(default=None)          # State or province where the organization is located
        country: Optional[str] = Field(default=None)        # Country code (2-letter ISO 3166-1)

    class KeyUsage(X509Extension):
        usages: set[X509KeyUsageName] = Field(default_factory=set)

    class ExtendedKeyUsage(X509Extension):
        usages: set[X509ExtendedKeyUsageName] = Field(default_factory=set)

    class SubjectAltName(X509Extension):
        names: Dict[X509NameType, List[str]] = Field(default_factory=dict)

    class IssuerAltName(X509Extension):
        names: Dict[X509NameType, List[str]] = Field(default_factory=dict)

    class NameConstraints(X509Extension):
        permitted: Optional[Dict[X509NameType, List[str]]] = Field(default_factory=dict)
        excluded: Optional[Dict[X509NameType, List[str]]] = Field(default_factory=dict)

    #class AuthorityInfoAccess(X509Extension):
    #    ocsp: List[str] = Field(default_factory=list)
    #    ca_issuers: List[str] = Field(default_factory=list)

    class SubjectKeyIdentifier(X509Extension):
        method: Literal["hash", "160-bit"] = "hash"

    class AuthorityKeyIdentifier(X509Extension):
        key_identifier: Optional[str] = None
        authority_cert_issuer: Optional[Dict[X509NameType, List[str]]] = None
        authority_cert_serial_number: Optional[str] = None

    class CertificatePolicies(X509Extension):
        policies: List['X509CertInfo.CertificatePolicies.PolicyInformation'] = Field(default_factory=list)

        class PolicyInformation(BaseModel):
            policy_identifier: str
            policy_qualifiers: Optional[List[Union[str, 'X509CertInfo.CertificatePolicies.PolicyInformation.UserNotice']]] = None

            class UserNotice(BaseModel):
                notice_ref: Optional['X509CertInfo.CertificatePolicies.PolicyInformation.NoticeReference'] = None
                explicit_text: Optional[str] = None

            class NoticeReference(BaseModel):
                organization: str
                notice_numbers: List[int]

    class PolicyConstraints(X509Extension):
        require_explicit_policy: Optional[int] = None
        inhibit_policy_mapping: Optional[int] = None

    class InhibitAnyPolicy(X509Extension):
        skip_certs: int


class X509CA(NoExtraBaseModel):
    key: HSMAsymmetricKey
    x509_info: Optional[X509CertInfo] = Field(default=None) # If None, use the default values from the global configuration (applies to sub-fields, too)
    crl_distribution_points: list[str] = Field(default_factory=list)   # CRL URLs to include in certificates signed by this key
    signed_certs: List[HSMOpaqueObject] = Field(default_factory=list)  # Storage for signed certificates


# ----- Utility functions -----

def load_hsm_config(file_name: str) -> 'HSMConfig':
    """
    Load a YAML configuration file, validate with Pydantic, and return a HSMConfig object.
    """
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
                    raise click.ClickException(f"Duplicate key ID 0x{key.id:04x} found in the configuration file. YubiHSM allows this between different key types, but this tool enforces strict uniqueness.")
                seen_ids.add(key.id)
    return res


def find_config_items_of_class(conf: Any, cls: type) -> list:
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


def parse_keyid(key_id: str) -> int:
    """
    Parse a key ID from a string in the format '0x1234'.
    :raises ValueError: If the key ID is not a hexadecimal number with the '0x' prefix.
    """
    if not key_id.startswith('0x'):
        raise ValueError(f"Key ID '{key_id}' must be a hexadecimal number with the '0x' prefix.")
    return int(key_id.replace('0x',''), 16)


def _find_def_by_id_or_label(conf: HSMConfig, id_or_label: int|str, enforce_type: type|None = None) -> HSMObjBase:
    """
    Find the configuration object for a given key ID or label.
    :raises KeyError: If the key is not found in the configuration file.
    """
    # Check and parse the id/label
    id = None
    if isinstance(id_or_label, str):
        if re.match(r'^0x[0-9a-fA-F]+$', id_or_label.strip()):
            id = parse_keyid(id_or_label)
        elif id_or_label.isdigit():
            raise ValueError(f"Key ID ('{id_or_label}') must be a hexadecimal number with the '0x' prefix.")
    elif isinstance(id_or_label, int):
        id = id_or_label
        if id <= 0 or id >= 0xFFFF:
            raise ValueError(f"Key ID '{id}' is out of range (16 bit unsigned integer).")

    # Search by ID or label
    for t in [HSMAsymmetricKey, HSMSymmetricKey, HSMWrapKey, HSMHmacKey, HSMAuthKey, HSMOpaqueObject]:
        for key in find_config_items_of_class(conf, t):
            if (id and key.id == id) or key.label == id_or_label:
                if enforce_type and not isinstance(key, enforce_type):
                    raise ValueError(f"Key '{id_or_label}' is not of the expected type '{enforce_type.__name__}'.")
                return key

    raise KeyError(f"Key with ID or label '{id_or_label}' not found in the configuration file.")



def find_all_config_items_per_type(conf: HSMConfig) -> tuple[dict, dict]:
    """
    Find all instances of each key type in the configuration file.
    Returns a dictionary with lists of each key type, and a mapping from config type to YubiHSM object type.
    """
    import yubihsm.objects  # type: ignore [import]

    from hsm_secrets.config import HSMAsymmetricKey, HSMSymmetricKey, HSMWrapKey, HSMOpaqueObject, HSMHmacKey, HSMAuthKey
    config_to_hsm_type = {
        HSMAuthKey: yubihsm.objects.AuthenticationKey,
        HSMWrapKey: yubihsm.objects.WrapKey,
        HSMHmacKey: yubihsm.objects.HmacKey,
        HSMSymmetricKey: yubihsm.objects.SymmetricKey,
        HSMAsymmetricKey: yubihsm.objects.AsymmetricKey,
        HSMOpaqueObject: yubihsm.objects.Opaque,
    }
    config_items_per_type: dict = {t: find_config_items_of_class(conf, t) for t in config_to_hsm_type.keys()} # type: ignore
    return config_items_per_type, config_to_hsm_type


def click_hsm_obj_auto_complete(cls: type|None, subsection: str|None = None, ids: bool = True, labels: bool = True) -> Callable:
    """
    Make a shell auto completion function for HSM objects (keys, etc.) in the configuration file.
    :param cls: The class of the HSM object to complete. If None, all objects are included.
    :subsection: The name of the configuration subsection to search in, e.g. 'ssh.root_ca_keys'
    :param ids: Include the key IDs in the completion list.
    :param labels: Include the key labels in the completion list.
    """
    def autocomplete(ctx, args, incomplete) -> list[click.shell_completion.CompletionItem]:
        conf: HSMConfig = ctx.obj['config']
        if subsection:
            for attr in subsection.split('.'):
                conf = getattr(conf, attr)

        if cls:
            items: list[HSMObjBase] = find_config_items_of_class(conf, cls)
        else:
            all_items: dict[type, list[HSMObjBase]] = find_all_config_items_per_type(conf)[0]
            items = []
            for key_list in all_items.values():
                items.extend(key_list)

        res = []
        if ids:
            res += [click.shell_completion.CompletionItem(f'0x{x.id:04x}', help=f"'{x.label}' ({type(x).__name__})") for x in items if incomplete in f'0x{x.id:04x}']
        if labels:
            res += [click.shell_completion.CompletionItem(x.label, help=f"0x{x.id:04x} ({type(x).__name__})") for x in items if incomplete in x.label]
        return res

    return autocomplete
