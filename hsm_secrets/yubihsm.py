from abc import ABC, abstractmethod
from dataclasses import dataclass
import datetime
from hashlib import sha256
from typing import Sequence, cast
import pickle
import os
import typing

import click
from yubihsm.defs import CAPABILITY, ALGORITHM, ERROR, OBJECT, ORIGIN, COMMAND, AUDIT     # type: ignore [import]
from yubihsm.objects import AsymmetricKey, HmacKey, SymmetricKey, WrapKey, YhsmObject, AuthenticationKey, Opaque     # type: ignore [import]
from yubihsm.core import AuthSession, LogData, LogEntry     # type: ignore [import]
from yubihsm.exceptions import YubiHsmDeviceError     # type: ignore [import]
from yubihsm.objects import ObjectInfo

# Mock YubiHSM2 device with Cryptodome library
import cryptography.hazmat.primitives.ciphers.algorithms as haz_algs
import cryptography.hazmat.primitives.ciphers as haz_ciphers
import cryptography.hazmat.primitives.ciphers.modes as haz_cipher_modes
import cryptography.hazmat.primitives.asymmetric.rsa as haz_rsa
import cryptography.hazmat.primitives.asymmetric.ed25519 as haz_ed25519
import cryptography.hazmat.primitives.asymmetric.ec as haz_ec
import cryptography.hazmat.primitives.hashes as haz_hashes
import cryptography.hazmat.primitives.hmac as haz_hmac
import cryptography.hazmat.primitives.serialization as haz_ser
from cryptography.hazmat.primitives import _serialization as haz_priv_ser
import cryptography.hazmat.primitives.asymmetric.padding as haz_asym_padding
import cryptography.x509 as haz_x509

from hsm_secrets.config import HSMAsymmetricKey, HSMAuditSettings, HSMAuthKey, HSMConfig, HSMHmacKey, HSMKeyID, HSMObjBase, HSMOpaqueObject, HSMSymmetricKey, HSMWrapKey, NoExtraBaseModel, YubiHsm2AuditMode, YubiHsm2Command, lookup_hsm_cmd
from hsm_secrets.key_adapters import PrivateKeyOrAdapter, make_private_key_adapter

"""
Abstracts the YubiHSM2 interface for the purpose of testing.

This module provides both real (pass-through) and mock implementations of YubiHSM2 operations
that the rest of the application uses. The mock implementation is used for testing purposes,
and can simulate several YubiHSM2 devices with different objects stored in them.

The mock devices are stored in pickle files, and can be loaded and saved using the
load_mock_hsms() and save_mock_hsms() functions.
"""

HSM_KEY_TYPES = (HSMAuthKey, HSMWrapKey, HSMSymmetricKey, HSMAsymmetricKey, HSMHmacKey, HSMOpaqueObject)

class HSMSession(ABC):
    """
    Abstract base class for HSM sessions.

    This class defines the interface for interacting with a Hardware Security Module (HSM),
    whether it's a real YubiHSM2 or a mock HSM for testing purposes.
    """

    @abstractmethod
    def get_serial(self) -> int:
        """
        Get the serial number of the HSM device.
        """
        pass

    @abstractmethod
    def get_info(self, objdef: HSMObjBase) -> ObjectInfo:
        """
        Get information about an object in the HSM.

        :param objdef: Object definition
        :return: Object information
        """
        pass

    @abstractmethod
    def get_info_raw(self, id: HSMKeyID, type: OBJECT) -> ObjectInfo:
        """
        Get information about an object in the HSM, given its id and type.

        :param id: Object ID
        :param type: Object type
        :return: Object information
        """
        pass

    @abstractmethod
    def object_exists(self, objdef: HSMObjBase) -> ObjectInfo | None:
        """
        Check if an object exists in the HSM and return its info.

        :param objdef: Object definition
        :return: Object information if it exists, None otherwise
        """
        pass

    @abstractmethod
    def object_exists_raw(self, id: HSMKeyID, type: OBJECT) -> ObjectInfo | None:
        """
        Check if an object exists in the HSM, given its id and type.

        :param id: Object ID
        :param type: Object type
        :return: Object information if it exists, None otherwise
        """
        pass

    @abstractmethod
    def put_wrap_key(self, keydef: HSMWrapKey, secret: bytes) -> ObjectInfo:
        """
        Put a wrap key on device.

        :param keydef: Wrap key definition
        :param secret: Key secret
        :return: Object information of the created wrap key
        """
        pass

    @abstractmethod
    def attest_asym_key(self, key_id: HSMKeyID) -> haz_x509.Certificate:
        """
        Attest an asymmetric key.

        :param key_id: Key ID
        :return: Attestation certificate
        """
        pass

    @abstractmethod
    def export_wrapped(self, wrap_key: HSMWrapKey, obj_id: HSMKeyID, obj_type: OBJECT) -> bytes:
        """
        Export an object from the HSM, encrypted with a wrap key.

        :param wrap_key: Wrap key to use for encryption
        :param obj_id: ID of the object to export
        :param obj_type: Type of the object to export
        :return: Encrypted object data
        """
        pass

    @abstractmethod
    def import_wrapped(self, wrap_key: HSMWrapKey, data: bytes) -> ObjectInfo:
        """
        Import an object into the HSM, decrypting it with a wrap key.

        :param wrap_key: Wrap key to use for decryption
        :param data: Encrypted object data
        :return: Object information of the imported object
        """
        pass

    @abstractmethod
    def auth_key_put_derived(self, keydef: HSMAuthKey, password: str) -> ObjectInfo:
        """
        Create a new authentication key from a password.

        :param keydef: Authentication key definition
        :param password: Password to derive the key from
        :return: Object information of the created authentication key
        """
        pass

    @abstractmethod
    def auth_key_put(self, keydef: HSMAuthKey, key_enc: bytes, key_mac: bytes) -> ObjectInfo:
        """
        Create a new authentication key from raw key material.

        :param keydef: Authentication key definition
        :param key_enc: Encryption key
        :param key_mac: MAC key
        :return: Object information of the created authentication key
        """
        pass

    @abstractmethod
    def sym_key_generate(self, keydef: HSMSymmetricKey) -> ObjectInfo:
        """
        Create a new symmetric key.

        :param keydef: Symmetric key definition
        :return: Object information of the created symmetric key
        """
        pass

    @abstractmethod
    def asym_key_generate(self, keydef: HSMAsymmetricKey) -> ObjectInfo:
        """
        Create a new asymmetric key.

        :param keydef: Asymmetric key definition
        :return: Object information of the created asymmetric key
        """
        pass

    @abstractmethod
    def hmac_key_generate(self, keydef: HSMHmacKey) -> ObjectInfo:
        """
        Create a new HMAC key.

        :param keydef: HMAC key definition
        :return: Object information of the created HMAC key
        """
        pass

    @abstractmethod
    def get_pseudo_random(self, length: int) -> bytes:
        """
        Generate pseudo-random bytes.

        :param length: Number of bytes to generate
        :return: Pseudo-random bytes
        """
        pass

    @abstractmethod
    def list_objects(self) -> Sequence['YhsmObject | MockYhsmObject']:
        """
        List all objects in the HSM.

        :return: Sequence of HSM objects
        """
        pass

    @abstractmethod
    def delete_object(self, objdef: HSMObjBase) -> None:
        """
        Delete an object from the HSM, given its definition.

        :param objdef: Object definition
        """
        pass

    @abstractmethod
    def delete_object_raw(self, id: HSMKeyID, type: OBJECT) -> None:
        """
        Delete an object from the HSM, given its key and type.

        :param id: Object ID
        :param type: Object type
        """
        pass

    @abstractmethod
    def sign_hmac(self, keydef: HSMHmacKey, data: bytes) -> bytes:
        """
        Sign data with an HMAC key.

        :param keydef: HMAC key definition
        :param data: Data to sign
        :return: HMAC signature
        """
        pass

    @abstractmethod
    def get_certificate(self, keydef: HSMOpaqueObject) -> haz_x509.Certificate:
        """
        Get a certificate from the HSM.

        :param keydef: Opaque object definition containing the certificate
        :return: X.509 Certificate
        """
        pass

    @abstractmethod
    def put_certificate(self, keydef: HSMOpaqueObject, certificate: haz_x509.Certificate) -> ObjectInfo:
        """
        Store a certificate in the HSM.

        :param keydef: Opaque object definition to store the certificate
        :param certificate: X.509 Certificate to store
        :return: Object information of the stored certificate
        """
        pass

    @abstractmethod
    def get_private_key(self, keydef: HSMAsymmetricKey) -> PrivateKeyOrAdapter:
        """
        Get a private key adapter for an asymmetric key.

        :param keydef: Asymmetric key definition
        :return: Private key or adapter
        """
        pass

    @abstractmethod
    def get_public_key(self, keydef: HSMAsymmetricKey) -> haz_rsa.RSAPublicKey | haz_ec.EllipticCurvePublicKey | haz_ed25519.Ed25519PublicKey:
        """
        Get the public key from an asymmetric key.

        :param keydef: Asymmetric key definition
        :return: Public key (RSA, EC, or Ed25519)
        """
        pass

    @abstractmethod
    def get_log_entries(self, previous_entry: LogEntry | None = None) -> LogData:
        """
        Get the log entries from the HSM.

        NOTE! If `previous_entry` is given, it must be the exactly previous entry to
        the first one on the device! It's used for validation, NOT pagination by the
        underlying Yubico library.
        """
        pass

    @abstractmethod
    def free_log_entries(self, up_until_num: int) -> None:
        """
        Free log entries up until (and including) a given number (id), to make space for new ones.

        :param up_until_num: Log entry number (id) to free up until
        """
        pass

    @abstractmethod
    def get_audit_settings(self) -> tuple[HSMAuditSettings, dict[str, YubiHsm2AuditMode]]:
        """
        Get the audit settings from the HSM.
        First return value is the settings known in the config definition, second lists
        any unknown ones read from the device.
        """
        pass

    @abstractmethod
    def set_audit_settings(self, settings: HSMAuditSettings) -> None:
        """
        Set the audit settings on the HSM.
        """
        pass

# --------- Real YubiHSM2 ---------

_conf_class_to_yhs_object_type = {
    HSMAuthKey: OBJECT.AUTHENTICATION_KEY,
    HSMWrapKey: OBJECT.WRAP_KEY,
    HSMSymmetricKey: OBJECT.SYMMETRIC_KEY,
    HSMAsymmetricKey: OBJECT.ASYMMETRIC_KEY,
    HSMHmacKey: OBJECT.HMAC_KEY,
    HSMOpaqueObject: OBJECT.OPAQUE
}

class RealHSMSession(HSMSession):
    """
    Implementation of the HSM session for a real YubiHSM2 device.
    """

    def __init__(self, conf: HSMConfig, session: AuthSession, dev_serial: int):
        """
        Initialize the real HSM session.

        :param conf: HSM configuration
        :param session: Authenticated session with the YubiHSM2
        :param dev_serial: Device serial number
        """
        self.dev_serial: int = dev_serial
        self.backend: AuthSession = session
        self.conf: HSMConfig = conf

    def get_serial(self) -> HSMKeyID:
        return self.dev_serial

    def get_info(self, objdef: HSMObjBase) -> ObjectInfo:
        res = self.object_exists(objdef)
        if not res:
            raise YubiHsmDeviceError(ERROR.OBJECT_NOT_FOUND)
        return res

    def get_info_raw(self, id: HSMKeyID, type: OBJECT) -> ObjectInfo:
        res = self.object_exists_raw(id, type)
        if not res:
            raise YubiHsmDeviceError(ERROR.OBJECT_NOT_FOUND)
        return res

    def object_exists(self, objdef: HSMObjBase) -> ObjectInfo | None:
        assert isinstance(objdef, HSM_KEY_TYPES)
        obj_type = _conf_class_to_yhs_object_type[objdef.__class__]
        return self.object_exists_raw(objdef.id, obj_type)

    def object_exists_raw(self, id: HSMKeyID, type: OBJECT) -> ObjectInfo | None:
        try:
            return self.backend.get_object(id, type).get_info()
        except YubiHsmDeviceError as e:
            if e.code == ERROR.OBJECT_NOT_FOUND:
                return None
            raise e

    def put_wrap_key(self, keydef: HSMWrapKey, secret: bytes) -> ObjectInfo:
        wrap_key = self.backend.get_object(keydef.id, OBJECT.WRAP_KEY)
        assert isinstance(wrap_key, WrapKey)
        res = wrap_key.put(
            session=self.backend,
            object_id=keydef.id,
            label=keydef.label,
            algorithm=self.conf.algorithm_from_name(keydef.algorithm),
            domains=self.conf.get_domain_bitfield(keydef.domains),
            capabilities=self.conf.capability_from_names(keydef.capabilities),
            delegated_capabilities=self.conf.delegated_capability_from_names(
                keydef.delegated_capabilities,
                non_delegated_caps=keydef.capabilities),
            key=secret)
        return res.get_info()

    def attest_asym_key(self, key_id: HSMKeyID) -> haz_x509.Certificate:
        asym_key = self.backend.get_object(key_id, OBJECT.ASYMMETRIC_KEY)
        assert isinstance(asym_key, AsymmetricKey)
        return asym_key.attest()

    def export_wrapped(self, wrap_key: HSMWrapKey, obj_id: HSMKeyID, obj_type: OBJECT) -> bytes:
        wrap_key_obj = self.backend.get_object(wrap_key.id, OBJECT.WRAP_KEY)
        assert isinstance(wrap_key_obj, WrapKey)
        export_obj = self.backend.get_object(obj_id, obj_type)
        return wrap_key_obj.export_wrapped(export_obj)

    def import_wrapped(self, wrap_key: HSMWrapKey, data: bytes) -> ObjectInfo:
        wrap_key_obj = self.backend.get_object(wrap_key.id, OBJECT.WRAP_KEY)
        assert isinstance(wrap_key_obj, WrapKey)
        return wrap_key_obj.import_wrapped(data).get_info()

    def auth_key_put_derived(self, keydef: HSMAuthKey, password: str) -> ObjectInfo:
        auth_key = self.backend.get_object(keydef.id, OBJECT.AUTHENTICATION_KEY)
        assert isinstance(auth_key, AuthenticationKey)
        return auth_key.put_derived(
            session=self.backend,
            object_id=keydef.id,
            label=keydef.label,
            domains=self.conf.get_domain_bitfield(keydef.domains),
            capabilities=self.conf.capability_from_names(keydef.capabilities),
            delegated_capabilities=self.conf.delegated_capability_from_names(
                keydef.delegated_capabilities,
                non_delegated_caps=keydef.capabilities),
            password=password).get_info()

    def auth_key_put(self, keydef: HSMAuthKey, key_enc: bytes, key_mac: bytes) -> ObjectInfo:
        auth_key = self.backend.get_object(keydef.id, OBJECT.AUTHENTICATION_KEY)
        assert isinstance(auth_key, AuthenticationKey)
        return auth_key.put(
            session=self.backend,
            object_id=keydef.id,
            label=keydef.label,
            domains=self.conf.get_domain_bitfield(keydef.domains),
            capabilities=self.conf.capability_from_names(keydef.capabilities),
            delegated_capabilities=self.conf.delegated_capability_from_names(
                keydef.delegated_capabilities,
                non_delegated_caps=keydef.capabilities),
            key_enc=key_enc,
            key_mac=key_mac).get_info()

    def sym_key_generate(self, keydef: HSMSymmetricKey) -> ObjectInfo:
        sym_key = self.backend.get_object(keydef.id, OBJECT.SYMMETRIC_KEY)
        assert isinstance(sym_key, SymmetricKey)
        return sym_key.generate(
            session=self.backend,
            object_id=keydef.id,
            label=keydef.label,
            domains=self.conf.get_domain_bitfield(keydef.domains),
            capabilities=self.conf.capability_from_names(keydef.capabilities),
            algorithm=self.conf.algorithm_from_name(keydef.algorithm)).get_info()

    def asym_key_generate(self, keydef: HSMAsymmetricKey) -> ObjectInfo:
        asym_key = self.backend.get_object(keydef.id, OBJECT.ASYMMETRIC_KEY)
        assert isinstance(asym_key, AsymmetricKey)
        return asym_key.generate(
            session=self.backend,
            object_id=keydef.id,
            label=keydef.label,
            domains=self.conf.get_domain_bitfield(keydef.domains),
            capabilities=self.conf.capability_from_names(keydef.capabilities),
            algorithm=self.conf.algorithm_from_name(keydef.algorithm)).get_info()

    def hmac_key_generate(self, keydef: HSMHmacKey) -> ObjectInfo:
        hmac_key = self.backend.get_object(keydef.id, OBJECT.HMAC_KEY)
        assert isinstance(hmac_key, HmacKey)
        return hmac_key.generate(
            session=self.backend,
            object_id=keydef.id,
            label=keydef.label,
            domains=self.conf.get_domain_bitfield(keydef.domains),
            capabilities=self.conf.capability_from_names(keydef.capabilities),
            algorithm=self.conf.algorithm_from_name(keydef.algorithm)).get_info()

    def get_pseudo_random(self, length: int) -> bytes:
        return self.backend.get_pseudo_random(length)

    def list_objects(self) -> Sequence[YhsmObject]:
        return self.backend.list_objects()

    def delete_object(self, objdef: HSMObjBase) -> None:
        assert isinstance(objdef, HSM_KEY_TYPES)
        obj_type = _conf_class_to_yhs_object_type[objdef.__class__]
        self.delete_object_raw(objdef.id, obj_type)

    def delete_object_raw(self, id: HSMKeyID, type: OBJECT) -> None:
        self.backend.get_object(id, type).delete()

    def sign_hmac(self, keydef: HSMHmacKey, data: bytes) -> bytes:
        hmac_key = self.backend.get_object(keydef.id, OBJECT.HMAC_KEY)
        assert isinstance(hmac_key, HmacKey)
        return hmac_key.sign_hmac(data)

    def get_certificate(self, keydef: HSMOpaqueObject) -> haz_x509.Certificate:
        obj = self.backend.get_object(keydef.id, OBJECT.OPAQUE)
        assert isinstance(obj, Opaque)
        return obj.get_certificate()

    def put_certificate(self, keydef: HSMOpaqueObject, certificate: haz_x509.Certificate) -> ObjectInfo:
        obj = self.backend.get_object(keydef.id, OBJECT.OPAQUE)
        assert isinstance(obj, Opaque)
        return obj.put_certificate(
            session=self.backend,
            object_id=keydef.id,
            label=keydef.label,
            domains=self.conf.get_domain_bitfield(keydef.domains),
            capabilities=self.conf.capability_from_names({'exportable-under-wrap'}),
            certificate=certificate).get_info()

    def get_private_key(self, keydef: HSMAsymmetricKey) -> PrivateKeyOrAdapter:
        asym_key = self.backend.get_object(keydef.id, OBJECT.ASYMMETRIC_KEY)
        assert isinstance(asym_key, AsymmetricKey)
        return make_private_key_adapter(asym_key)

    def get_public_key(self, keydef: HSMAsymmetricKey) -> haz_rsa.RSAPublicKey | haz_ec.EllipticCurvePublicKey | haz_ed25519.Ed25519PublicKey:
        asym_key = self.backend.get_object(keydef.id, OBJECT.ASYMMETRIC_KEY)
        assert isinstance(asym_key, AsymmetricKey)
        return asym_key.get_public_key()

    def get_log_entries(self, previous_entry: LogEntry | None = None) -> LogData:
        return self.backend.get_log_entries(previous_entry)

    def free_log_entries(self, up_until_num: int) -> None:
        self.backend.set_log_index(up_until_num)

    def get_audit_settings(self) -> tuple[HSMAuditSettings, dict[str, YubiHsm2AuditMode]]:
        def tristate(val: AUDIT) -> YubiHsm2AuditMode:
            return 'off' if val == AUDIT.OFF else ('on' if val == AUDIT.ON else 'fixed')

        uknown_res: dict[str, YubiHsm2AuditMode] = {}
        known_res = HSMAuditSettings(
            forced_audit=tristate(self.backend.get_force_audit()),
            default_command_logging='off',
            command_logging = {})

        std_enum_vals = {int(x[1].value) for x in COMMAND._member_map_.items()}
        conf_cmd_literals = typing.get_args(YubiHsm2Command)

        for cmd, a in self.backend.get_command_audit().items():
            cmd_name = f'{cmd.name.lower().replace("_","-")}'
            if cmd.value in std_enum_vals and cmd_name in conf_cmd_literals:
                known_res.command_logging[cast(YubiHsm2Command, cmd_name)] = tristate(a)
            else:
                cmd_name = f'0x{cmd.value:02x}-{cmd.name}'
                uknown_res[cmd_name] = tristate(a)

        return known_res, uknown_res


    def set_audit_settings(self, settings: HSMAuditSettings) -> None:
        tristate: dict[YubiHsm2AuditMode, AUDIT] = {'off': AUDIT.OFF, 'on': AUDIT.ON, 'fixed': AUDIT.FIXED}
        self.backend.set_force_audit(tristate[settings.forced_audit])
        audit_mapping: dict[COMMAND, AUDIT]  = {lookup_hsm_cmd(k): tristate[v] for k,v in settings.command_logging.items()}
        self.backend.set_command_audit(audit_mapping)


# --------- Mock YubiHSM2 ---------


_g_mock_hsms: dict[int, 'MockHSMDevice'] = {}
_g_conf: HSMConfig|None

def open_mock_hsms(path: str, serial: int, conf: HSMConfig, auth_key_id: HSMKeyID):
    """
    Open mock HSM devices from a pickle file and/or
    create a new mock HSM device with the given serial.
    """
    global _g_mock_hsms, _g_conf
    _g_conf = conf

    if os.path.exists(path):
        with open(path, 'rb') as f:
            _g_mock_hsms = pickle.loads(f.read())
        click.echo(click.style(f"~🤡~ Loaded {len(_g_mock_hsms)} mock YubiHSMs from '{path}' ~🤡~", fg='yellow'), err=True)

    if serial not in _g_mock_hsms:
        dev = MockHSMDevice(serial=serial, objects={})
        _g_mock_hsms[serial] = dev
        click.echo(click.style(f"~🤡~ Created new mock YubiHSM with serial {serial} ~🤡~", fg='yellow'), err=True)

        # Store the default admin key in the device, like on a fresh YubiHSM2
        ses = MockHSMSession(serial, auth_key_id)
        ses.auth_key_put_derived(
            keydef = _g_conf.admin.default_admin_key,
            password = _g_conf.admin.default_admin_password)


def save_mock_hsms(path: str):
    """
    Save mock HSM devices to a pickle file.
    """
    global _g_mock_hsms
    with open(path, 'wb') as f:
        blob = pickle.dumps(_g_mock_hsms)
        f.write(blob)
    click.echo(click.style(f"~🤡~ Saved {len(_g_mock_hsms)} mock YubiHSMs to '{path}' ~🤡~", fg='yellow'), err=True)


# ----------------------------

class MockHSMDevice:
    serial: int
    objects: dict[tuple[HSMKeyID, OBJECT], 'MockYhsmObject']
    log_entries:list[LogEntry]
    prev_entry: LogEntry

    def __init__(self, serial: int, objects: dict):
        self.serial = serial
        self.objects = objects
        self.audit_settings = HSMAuditSettings(forced_audit='off', default_command_logging='off', command_logging={})
        # Inject example initial log entries from an actual YubiHSM2
        self.log_entries = [LogEntry.parse(bytes.fromhex(e)) for e in (
            '0001ffffffffffffffffffffffffffffcf87d1b7256b135b12ca27ec1365e50e',
            '0002000000ffff000000000000000000fc215fbee7154f4d061d80806250f678')]
        self.prev_entry = self.log_entries[-1]

    def add_log(self, cmd_name: YubiHsm2Command, target_key: HSMKeyID|None, second_key: HSMKeyID|None):
        # Emulate the YubiHSM2 logging
        assert _g_conf
        session_key = _g_conf.admin.default_admin_key.id    # TODO: emulate other auth keys on the mock device?
        default_logging = self.audit_settings.default_command_logging

        if self.audit_settings.command_logging.get(cmd_name, default_logging) != 'off':

            if len(self.log_entries) >= 62 and self.audit_settings.forced_audit != 'off':
                if cmd_name not in ('authenticate-session', 'reset-device', 'close-session', 'create-session', 'set-log-index', 'get-log-entries'):
                    raise YubiHsmDeviceError(ERROR.LOG_FULL)

            e = LogEntry(
                number = (self.prev_entry.number + 1) & 0xffff,
                command = lookup_hsm_cmd(cmd_name), length = 123,
                session_key = session_key or 0,
                target_key = target_key or 0,
                second_key = second_key or 0,
                result = 42, tick = self.prev_entry.tick + 7, digest = b'')
            new_digest = sha256(e.data + self.prev_entry.digest).digest()[:16]

            res = LogEntry(e.number, e.command, e.length,
                e.session_key, e.target_key, e.second_key,
                e.result, e.tick, new_digest)

            self.log_entries.append(res)
            self.prev_entry = res


    def get_mock_object(self, key: HSMKeyID, type: OBJECT) -> 'MockYhsmObject':
        if (key, type) not in self.objects:
            raise YubiHsmDeviceError(ERROR.OBJECT_NOT_FOUND)
        return self.objects[(key, type)]

    def put_mock_object(self, obj: 'MockYhsmObject') -> None:
        assert isinstance(obj.mock_obj, HSM_KEY_TYPES)
        key, type = obj.mock_obj.id, obj.object_type
        if (key, type) in self.objects:
            raise YubiHsmDeviceError(ERROR.OBJECT_EXISTS)
        self.objects[(key, type)] = obj

    def del_mock_object(self, key: HSMKeyID, type: OBJECT) -> None:
        if (key, type) not in self.objects:
            raise YubiHsmDeviceError(ERROR.OBJECT_NOT_FOUND)
        del self.objects[(key, type)]


class MockYhsmObject:
    """
    Mock version of the YhsmObject class (returned by list_objects() among others).
    Implements get_info() and delete() methods only.
    """
    def __init__(self, serial: int, mock_obj: HSMObjBase, data: bytes):
        self.mock_device_serial = serial
        self.mock_obj = mock_obj
        self.data = data

    @property
    def id(self) -> HSMKeyID:
        assert isinstance(self.mock_obj, HSM_KEY_TYPES)
        return self.mock_obj.id

    @property
    def object_type(self) -> OBJECT:
        assert isinstance(self.mock_obj, HSM_KEY_TYPES)
        return _conf_class_to_yhs_object_type[self.mock_obj.__class__]

    def get_info(self) -> ObjectInfo:
        global _g_conf
        assert _g_conf
        assert isinstance(self.mock_obj, HSM_KEY_TYPES)

        if algo_name := getattr(self.mock_obj, "algorithm", None):
            yhsm_algo = _g_conf.algorithm_from_name(algo_name)
        elif isinstance(self.mock_obj, HSMAuthKey):
            yhsm_algo = ALGORITHM.AES128_YUBICO_AUTHENTICATION
        else:
            raise ValueError(f"Don't know how to get algorithm for object: {self.mock_obj}")

        yhsm_caps = CAPABILITY.NONE
        if caps := getattr(self.mock_obj, "capabilities", None):
            yhsm_caps = _g_conf.capability_from_names(set(caps))

        yhsm_deleg_caps = CAPABILITY.NONE
        if deleg_caps := getattr(self.mock_obj, "delegated_capabilities", None):
            yhsm_deleg_caps = _g_conf.capability_from_names(set(deleg_caps))

        global _g_mock_hsms
        device = _g_mock_hsms[self.mock_device_serial]
        device.add_log('get-object-info', self.mock_obj.id, None)

        return ObjectInfo(
            id = self.mock_obj.id,
            object_type = self.object_type,
            algorithm = yhsm_algo,
            label = self.mock_obj.label,
            size = len(self.data),
            domains = _g_conf.get_domain_bitfield(self.mock_obj.domains),
            sequence = 123456,
            origin = ORIGIN.IMPORTED,
            capabilities = yhsm_caps,
            delegated_capabilities = yhsm_deleg_caps)

    def delete(self) -> None:
        global _g_mock_hsms
        assert isinstance(self.mock_obj, HSM_KEY_TYPES)
        key = (self.mock_obj.id, self.object_type)
        assert self.mock_device_serial in _g_mock_hsms, f"Mock device not found: {self.mock_device_serial}"
        device = _g_mock_hsms[self.mock_device_serial]
        device.del_mock_object(key[0], key[1])
    def __repr__(self):
        return "{0.__class__.__name__}(id={0.id})".format(self)


class MockHSMSession(HSMSession):
    """
    Implementation of the HSM session for a mock HSM device.
    """
    def __init__(self, dev_serial: int, auth_key_id: HSMKeyID):
        global _g_mock_hsms
        self.backend = _g_mock_hsms[dev_serial]
        self.dev_serial = dev_serial
        self.auth_key = auth_key_id

    def get_serial(self) -> int:
        return self.dev_serial

    def get_info(self, objdef: HSMObjBase) -> ObjectInfo:
        res = self.object_exists(objdef)
        if not res:
            raise YubiHsmDeviceError(ERROR.OBJECT_NOT_FOUND)
        return res

    def get_info_raw(self, id: HSMKeyID, type: OBJECT) -> ObjectInfo:
        res = self.object_exists_raw(id, type)
        if not res:
            raise YubiHsmDeviceError(ERROR.OBJECT_NOT_FOUND)
        return res

    def object_exists(self, objdef: HSMObjBase) -> ObjectInfo | None:
        assert isinstance(objdef, HSM_KEY_TYPES)
        obj_type = _conf_class_to_yhs_object_type[objdef.__class__]
        return self.object_exists_raw(objdef.id, obj_type)

    def object_exists_raw(self, id: HSMKeyID, type: OBJECT) -> ObjectInfo | None:
        try:
            self.backend.add_log('get-object-info', id, None)
            return self.backend.get_mock_object(id, type).get_info()
        except YubiHsmDeviceError as e:
            if e.code == ERROR.OBJECT_NOT_FOUND:
                return None
            raise e

    def put_wrap_key(self, keydef: HSMWrapKey, secret: bytes) -> ObjectInfo:
        obj = MockYhsmObject(self.backend.serial, keydef, secret)
        self.backend.objects[(keydef.id, OBJECT.WRAP_KEY)] = obj
        self.backend.add_log('put-wrap-key', keydef.id, None)
        return obj.get_info()

    def attest_asym_key(self, key_id: HSMKeyID) -> haz_x509.Certificate:
        asym_pem = self.backend.get_mock_object(key_id, OBJECT.ASYMMETRIC_KEY).data
        asym_key = haz_ser.load_pem_private_key(asym_pem, password=None)
        assert isinstance(asym_key, (haz_rsa.RSAPrivateKey, haz_ec.EllipticCurvePrivateKey, haz_ed25519.Ed25519PrivateKey))
        public_key = asym_key.public_key()

        issuer_key = haz_ec.generate_private_key(haz_ec.SECP256R1())
        builder = haz_x509.CertificateBuilder(
            ).subject_name(haz_x509.Name([haz_x509.NameAttribute(haz_x509.NameOID.COMMON_NAME, u"Mock Attestation")])
            ).issuer_name(haz_x509.Name([haz_x509.NameAttribute(haz_x509.NameOID.COMMON_NAME, u"The Mock Attestation Authority")])
            ).public_key(public_key
            ).not_valid_before(datetime.datetime.now()
            ).not_valid_after(datetime.datetime.now() + datetime.timedelta(days=365)
            ).serial_number(haz_x509.random_serial_number()
            ).add_extension(haz_x509.BasicConstraints(ca=False, path_length=None), critical=True
            ).add_extension(haz_x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
            ).add_extension(haz_x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False
            ).add_extension(haz_x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False
            ), critical=True)

        self.backend.add_log('sign-attestation-certificate', key_id, None)
        return builder.sign(issuer_key, haz_hashes.SHA256())

    def export_wrapped(self, wrap_key: HSMWrapKey, obj_id: HSMKeyID, obj_type: OBJECT) -> bytes:
        if not self.object_exists(wrap_key):
            raise click.ClickException(f"Wrap key missing. Create it first.")
        aes_key = self.backend.objects.get((wrap_key.id, OBJECT.WRAP_KEY))
        if not aes_key:
            raise YubiHsmDeviceError(ERROR.OBJECT_NOT_FOUND)
        export_blob = pickle.dumps(self.backend.get_mock_object(obj_id, obj_type))
        cipher = haz_ciphers.Cipher(haz_algs.AES(aes_key.data), haz_cipher_modes.GCM(b"\0" * 16))
        encryptor = cipher.encryptor()
        enc_blob = encryptor.update(export_blob) + encryptor.finalize()
        tag = encryptor.tag
        self.backend.add_log('export-wrapped', wrap_key.id, obj_id)
        return pickle.dumps((enc_blob, tag))

    def import_wrapped(self, wrap_key: HSMWrapKey, data: bytes) -> ObjectInfo:
        aes_key = self.backend.get_mock_object(wrap_key.id, OBJECT.WRAP_KEY).data
        decryptor = haz_ciphers.Cipher(haz_algs.AES(aes_key), haz_cipher_modes.GCM(b"\0" * 16)).decryptor()
        enc_blob, tag = pickle.loads(data)
        export_blob = decryptor.update(enc_blob) + decryptor.finalize_with_tag(tag)
        obj: MockYhsmObject = pickle.loads(export_blob)
        assert isinstance(obj.mock_obj, HSM_KEY_TYPES)
        self.backend.put_mock_object(obj)
        self.backend.add_log('import-wrapped', wrap_key.id, obj.id)
        return obj.get_info()

    def auth_key_put_derived(self, keydef: HSMAuthKey, password: str) -> ObjectInfo:
        data = f"derived:{password}".encode()
        obj = MockYhsmObject(self.backend.serial, keydef, data)
        self.backend.objects[(keydef.id, OBJECT.AUTHENTICATION_KEY)] = obj
        self.backend.add_log('put-authentication-key', keydef.id, None)
        return obj.get_info()

    def auth_key_put(self, keydef: HSMAuthKey, key_enc: bytes, key_mac: bytes) -> ObjectInfo:
        data = f"key_enc:{key_enc.hex()},key_mac:{key_mac.hex()}".encode()
        obj = MockYhsmObject(self.backend.serial, keydef, data)
        self.backend.objects[(keydef.id, OBJECT.AUTHENTICATION_KEY)] = obj
        self.backend.add_log('put-authentication-key', keydef.id, None)
        return obj.get_info()

    def sym_key_generate(self, keydef: HSMSymmetricKey) -> ObjectInfo:
        data = {"key_enc": self.get_pseudo_random(256//8), "key_mac": self.get_pseudo_random(256//8)}
        obj = MockYhsmObject(self.backend.serial, keydef, pickle.dumps(data))
        self.backend.objects[(keydef.id, OBJECT.SYMMETRIC_KEY)] = obj
        self.backend.add_log('generate-symmetric-key', keydef.id, None)
        return obj.get_info()

    def asym_key_generate(self, keydef: HSMAsymmetricKey) -> ObjectInfo:
        priv_key: PrivateKeyOrAdapter
        if "rsa" in keydef.algorithm.lower():
            priv_key = haz_rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif "ec" in keydef.algorithm.lower():
            priv_key = haz_ec.generate_private_key(haz_ec.SECP256R1())
        elif "ed25519" in keydef.algorithm.lower():
            priv_key = haz_ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"Unsupported algorithm: {keydef.algorithm}")

        priv_pem = priv_key.private_bytes(haz_ser.Encoding.PEM, haz_ser.PrivateFormat.PKCS8, haz_ser.NoEncryption())
        obj = MockYhsmObject(self.backend.serial, keydef, priv_pem)
        self.backend.objects[(keydef.id, OBJECT.ASYMMETRIC_KEY)] = obj
        self.backend.add_log('generate-asymmetric-key', keydef.id, None)
        return obj.get_info()

    def hmac_key_generate(self, keydef: HSMHmacKey) -> ObjectInfo:
        data = self.get_pseudo_random(256//8)
        obj = MockYhsmObject(self.backend.serial, keydef, data)
        self.backend.put_mock_object(obj)
        self.backend.add_log('generate-hmac-key', keydef.id, None)
        return obj.get_info()

    def get_pseudo_random(self, length: int) -> bytes:
        self.backend.add_log('get-pseudo-random', None, None)
        return (b'0123' * length)[:length]  # Mock: use deterministic data for tests

    def list_objects(self) -> Sequence[MockYhsmObject]:
        self.backend.add_log('list-objects', None, None)
        return list(self.backend.objects.values())

    def delete_object(self, objdef: HSMObjBase) -> None:
        assert isinstance(objdef, HSM_KEY_TYPES)
        obj_type = _conf_class_to_yhs_object_type[objdef.__class__]
        self.delete_object_raw(objdef.id, obj_type)

    def delete_object_raw(self, id: HSMKeyID, type: OBJECT) -> None:
        self.backend.add_log('delete-object', id, None)
        self.backend.del_mock_object(id, type)

    def sign_hmac(self, keydef: HSMHmacKey, data: bytes) -> bytes:
        hmac_key = self.backend.objects[(keydef.id, OBJECT.HMAC_KEY)].data
        hmac = haz_hmac.HMAC(hmac_key, haz_hashes.SHA256())
        hmac.update(data)
        self.backend.add_log('sign-hmac', keydef.id, None)
        return hmac.finalize()

    def get_certificate(self, keydef: HSMOpaqueObject) -> haz_x509.Certificate:
        self.backend.add_log('get-opaque', keydef.id, None)
        return haz_x509.load_pem_x509_certificate(self.backend.objects[(keydef.id, OBJECT.OPAQUE)].data)

    def put_certificate(self, keydef: HSMOpaqueObject, certificate: haz_x509.Certificate) -> ObjectInfo:
        obj = MockYhsmObject(self.backend.serial, keydef, certificate.public_bytes(encoding=haz_ser.Encoding.PEM))
        self.backend.objects[(keydef.id, OBJECT.OPAQUE)] = obj
        self.backend.add_log('put-opaque', keydef.id, None)
        return obj.get_info()

    def get_private_key(self, keydef: HSMAsymmetricKey) -> PrivateKeyOrAdapter:
        asym_pem = self.backend.objects[(keydef.id, OBJECT.ASYMMETRIC_KEY)].data
        asym_key = haz_ser.load_pem_private_key(asym_pem, password=None)
        assert isinstance(asym_key, (haz_rsa.RSAPrivateKey, haz_ec.EllipticCurvePrivateKey, haz_ed25519.Ed25519PrivateKey))
        return asym_key

    def get_public_key(self, keydef: HSMAsymmetricKey) -> haz_rsa.RSAPublicKey | haz_ec.EllipticCurvePublicKey | haz_ed25519.Ed25519PublicKey:
        asym_pem = self.backend.objects[(keydef.id, OBJECT.ASYMMETRIC_KEY)].data
        asym_key = haz_ser.load_pem_private_key(asym_pem, password=None)
        assert isinstance(asym_key, (haz_rsa.RSAPrivateKey, haz_ec.EllipticCurvePrivateKey, haz_ed25519.Ed25519PrivateKey))
        self.backend.add_log('get-public-key', keydef.id, None)
        return asym_key.public_key()

    def get_log_entries(self, previous_entry: LogEntry | None = None) -> LogData:
        res = LogData(0, 0, self.backend.log_entries)
        self.backend.add_log('get-log-entries', None, None)
        return res

    def free_log_entries(self, up_until_num: int) -> None:
        self.backend.log_entries = [e for e in self.backend.log_entries if e.number > up_until_num]
        self.backend.add_log('set-log-index', None, None)

    def get_audit_settings(self) -> tuple[HSMAuditSettings, dict[str, YubiHsm2AuditMode]]:
        self.backend.audit_settings.apply_defaults()
        return self.backend.audit_settings, {}    # No unknown audit settings on the mock device

    def set_audit_settings(self, settings: HSMAuditSettings) -> None:
        self.backend.add_log('set-option', None, None)
        self.backend.audit_settings = settings
        self.backend.audit_settings.apply_defaults()

