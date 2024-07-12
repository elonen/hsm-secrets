import os
from typing import Optional, Sequence
from contextlib import contextmanager

from click import echo
import click

from yubihsm import YubiHsm # type: ignore
from yubihsm.core import AuthSession
from yubihsm.defs import CAPABILITY, ALGORITHM, ERROR
from yubihsm.objects import AsymmetricKey, YhsmObject

from yubikit.hsmauth import HsmAuthSession  #, DEFAULT_MANAGEMENT_KEY
from yubihsm.exceptions import YubiHsmDeviceError
from ykman import scripting
import yubikit.core
import yubikit.hsmauth as hsmauth

import hsm_secrets.config as hscfg



def ask_for_password(title: str) -> str:
    return click.prompt(f"Enter the password for {title}", hide_input=False)


def list_yubikey_hsm_creds() -> Sequence[hsmauth.Credential]:
    """
    List the labels of all YubiKey HSM auth credentials.
    """
    yubikey = scripting.single()    # Connect to the first YubiKey found
    hsm = hsmauth.HsmAuthSession(connection=yubikey.smart_card())
    return list(hsm.list_credentials())


def connect_hsm_and_auth_with_yubikey(config: hscfg.HSMConfig, yubikey_slot_label: str, device_serial: str|None, yubikey_password: Optional[str] = None) -> AuthSession:
    """
    Connects to a YubHSM and authenticates a session using the first YubiKey found.
    YubiHSM auth key ID is read from the config file by label (arg yubikey_slot_label).

    Args:
        username (str): The username for the key labels.
        config (Config): The configuration object containing the connector URL and user.
        yubikey_slot_label (str): The label of the YubiKey slot to use for authenticating with the HSM.
        device_serial (str): Serial number of the YubiHSM device to connect to.
        yubikey_password (Optional[str]): The password for the YubiKey HSM slot. If None, the user is asked for the password.

    Returns:
        HsmAuthSession: The authenticated HSM session.
    """
    try:
        assert device_serial, "HSM device serial not provided nor inferred."
        connector_url = config.general.all_devices.get(device_serial)
        if not connector_url:
            raise ValueError(f"Device serial '{device_serial}' not found in config file.")

        yubikey = scripting.single()    # Connect to the first YubiKey found
        hsmauth = HsmAuthSession(yubikey.smart_card())

        hsm = YubiHsm.connect(connector_url)
        verify_hsm_device_info(device_serial, hsm)

        auth_key_id = config.find_auth_key(yubikey_slot_label).id
        click.echo(f"Using YubiHSM auth key ID '{hex(auth_key_id)}' authed with local YubiKey slot '{yubikey_slot_label}'")

        try:
            symmetric_auth = hsm.init_session(auth_key_id)
        except YubiHsmDeviceError as e:
            if e.code == ERROR.OBJECT_NOT_FOUND:
                echo(click.style(f"YubiHSM auth key '0x{auth_key_id:04x}' not found. Aborting.", fg='red'))
                exit(1)
            raise

        pwd = yubikey_password or ask_for_password(f"YubiKey HSM slot '{yubikey_slot_label}'")

        echo(f"Authenticating... " + click.style("(Touch your YubiKey if it blinks)", fg='yellow'))
        session_keys = hsmauth.calculate_session_keys_symmetric(
            label=yubikey_slot_label,
            credential_password=pwd,
            context=symmetric_auth.context)

        session = symmetric_auth.authenticate(*session_keys)

        echo(f"Session authenticated Ok.")
        return session

    except yubikit.core.InvalidPinError as e:
        echo(click.style("InvalidPinError", fg='red') + f" for YubiKey HSM slot '{yubikey_slot_label}':")
        echo(click.style(str(e), fg='red'))
        exit(1)

def verify_hsm_device_info(device_serial, hsm):
    info = hsm.get_device_info()
    if int(device_serial) != int(info.serial):
        raise ValueError(f"Device serial mismatch! Connected='{hsm.serial}', Expected='{device_serial}'")


@contextmanager
def open_hsm_session_with_yubikey(ctx: click.Context, device_serial: str|None = None):
    """
    Open a session to the HSM using the first YubiKey found, and authenticate with the YubiKey HSM auth label.

    Args:
        ctx (click.Context): The Click context object
    """
    conf: hscfg.HSMConfig = ctx.obj['config']
    device_serial = device_serial or ctx.obj['devserial']
    passwd = os.environ.get('YUBIKEY_PASSWORD', None)
    if passwd:
        echo("Using YubiKey password from environment variable.")
    session = connect_hsm_and_auth_with_yubikey(conf, ctx.obj['yk_label'], device_serial, passwd)
    try:
        yield conf, session
    finally:
        session.close()


@contextmanager
def open_hsm_session_with_default_admin(ctx: click.Context, device_serial: str|None = None):
    """
    Open a session to the HSM using the first YubiKey found, and authenticate with the YubiKey HSM auth label.

    Args:
        ctx (click.Context): The Click context object
    """
    conf: hscfg.HSMConfig = ctx.obj['config']
    device_serial = device_serial or ctx.obj['devserial']
    assert device_serial, "HSM device serial not provided nor inferred."

    click.echo(click.style(f"Using insecure default admin key to auth on YubiHSM2 {device_serial}.", fg='magenta'))

    connector_url = conf.general.all_devices.get(device_serial)
    if not connector_url:
        raise ValueError(f"Device serial '{device_serial}' not found in config file.")

    hsm = YubiHsm.connect(connector_url)
    verify_hsm_device_info(device_serial, hsm)

    session = None

    try:
        session = hsm.create_session_derived(conf.admin.default_admin_key.id, conf.admin.default_admin_password)
        click.echo(click.style(f"HSM session {session.sid} started.", fg='magenta'))
    except YubiHsmDeviceError as e:
        if e.code == ERROR.OBJECT_NOT_FOUND:
            echo(click.style(f"Default admin key '0x{conf.admin.default_admin_key.id:04x}' not found. Aborting.", fg='red'))
            exit(1)
        raise

    try:
        yield conf, session
    finally:
        click.echo(click.style(f"Closing HSM session {session.sid}.", fg='magenta'))
        session.close()
        hsm.close()


@contextmanager
def open_hsm_session_with_shared_admin(ctx: click.Context, password: str, device_serial: str|None = None):
    """
    Open a session to the HSM using a share admin password (either reconstructed from shares or from backup).
    Args:
        ctx (click.Context): The Click context object
    """
    conf: hscfg.HSMConfig = ctx.obj['config']

    device_serial = device_serial or ctx.obj['devserial']
    assert device_serial, "HSM device serial not provided nor inferred."

    connector_url = conf.general.all_devices.get(device_serial)
    if not connector_url:
        raise ValueError(f"Device serial '{device_serial}' not found in config file.")

    hsm = YubiHsm.connect(connector_url)
    verify_hsm_device_info(device_serial, hsm)

    key = conf.admin.shared_admin_key.id
    click.echo(f"Using shared admin key ID 0x{key:04x}")
    session = hsm.create_session_derived(key, password)
    try:
        yield conf, session
    finally:
        session.close()
        hsm.close()


def encode_capabilities(names: Sequence[hscfg.AsymmetricCapabilityName] | set[hscfg.AsymmetricCapabilityName]) -> CAPABILITY:
    """
    Convert a list of capability names to a bitfield.
    """
    mapping = {
        "get-opaque": CAPABILITY.GET_OPAQUE,
        "put-opaque": CAPABILITY.PUT_OPAQUE,
        "put-authentication-key": CAPABILITY.PUT_AUTHENTICATION_KEY,
        "put-asymmetric-key": CAPABILITY.PUT_ASYMMETRIC,
        "generate-asymmetric-key": CAPABILITY.GENERATE_ASYMMETRIC_KEY,
        "sign-pkcs": CAPABILITY.SIGN_PKCS,
        "sign-pss": CAPABILITY.SIGN_PSS,
        "sign-ecdsa": CAPABILITY.SIGN_ECDSA,
        "sign-eddsa": CAPABILITY.SIGN_EDDSA,
        "decrypt-pkcs": CAPABILITY.DECRYPT_PKCS,
        "decrypt-oaep": CAPABILITY.DECRYPT_OAEP,
        "derive-ecdh": CAPABILITY.DERIVE_ECDH,
        "export-wrapped": CAPABILITY.EXPORT_WRAPPED,
        "import-wrapped": CAPABILITY.IMPORT_WRAPPED,
        "put-wrap-key": CAPABILITY.PUT_WRAP_KEY,
        "generate-wrap-key": CAPABILITY.GENERATE_WRAP_KEY,
        "exportable-under-wrap": CAPABILITY.EXPORTABLE_UNDER_WRAP,
        "set-option": CAPABILITY.SET_OPTION,
        "get-option": CAPABILITY.GET_OPTION,
        "get-pseudo-random": CAPABILITY.GET_PSEUDO_RANDOM,
        "put-mac-key": CAPABILITY.PUT_HMAC_KEY,
        "generate-hmac-key": CAPABILITY.GENERATE_HMAC_KEY,
        "sign-hmac": CAPABILITY.SIGN_HMAC,
        "verify-hmac": CAPABILITY.VERIFY_HMAC,
        "get-log-entries": CAPABILITY.GET_LOG_ENTRIES,
        "sign-ssh-certificate": CAPABILITY.SIGN_SSH_CERTIFICATE,
        "get-template": CAPABILITY.GET_TEMPLATE,
        "put-template": CAPABILITY.PUT_TEMPLATE,
        "reset-device": CAPABILITY.RESET_DEVICE,
        "decrypt-otp": CAPABILITY.DECRYPT_OTP,
        "create-otp-aead": CAPABILITY.CREATE_OTP_AEAD,
        "randomize-otp-aead": CAPABILITY.RANDOMIZE_OTP_AEAD,
        "rewrap-from-otp-aead-key": CAPABILITY.REWRAP_FROM_OTP_AEAD_KEY,
        "rewrap-to-otp-aead-key": CAPABILITY.REWRAP_TO_OTP_AEAD_KEY,
        "sign-attestation-certificate": CAPABILITY.SIGN_ATTESTATION_CERTIFICATE,
        "put-otp-aead-key": CAPABILITY.PUT_OTP_AEAD_KEY,
        "generate-otp-aead-key": CAPABILITY.GENERATE_OTP_AEAD_KEY,
        "wrap-data": CAPABILITY.WRAP_DATA,
        "unwrap-data": CAPABILITY.UNWRAP_DATA,
        "delete-opaque": CAPABILITY.DELETE_OPAQUE,
        "delete-authentication-key": CAPABILITY.DELETE_AUTHENTICATION_KEY,
        "delete-asymmetric-key": CAPABILITY.DELETE_ASYMMETRIC_KEY,
        "delete-wrap-key": CAPABILITY.DELETE_WRAP_KEY,
        "delete-hmac-key": CAPABILITY.DELETE_HMAC_KEY,
        "delete-template": CAPABILITY.DELETE_TEMPLATE,
        "delete-otp-aead-key": CAPABILITY.DELETE_OTP_AEAD_KEY,
        "change-authentication-key": CAPABILITY.CHANGE_AUTHENTICATION_KEY,
        "put-symmetric-key": CAPABILITY.PUT_SYMMETRIC_KEY,
        "generate-symmetric-key": CAPABILITY.GENERATE_SYMMETRIC_KEY,
        "delete-symmetric-key": CAPABILITY.DELETE_SYMMETRIC_KEY,
        "decrypt-ecb": CAPABILITY.DECRYPT_ECB,
        "encrypt-ecb": CAPABILITY.ENCRYPT_ECB,
        "decrypt-cbc": CAPABILITY.DECRYPT_CBC,
        "encrypt-cbc": CAPABILITY.ENCRYPT_CBC,
    }
    names = set(names)
    if 'all' in names:
        return CAPABILITY.ALL
    elif 'none' in names:
        return CAPABILITY.NONE
    else:
        res = CAPABILITY.NONE
        for name in names:
            if name not in mapping:
                raise ValueError(f"Unknown capability name '{name}'")
            res |= mapping[name]
        return res


def encode_algorithm(name_literal: str|hscfg.AsymmetricAlgorithm) -> ALGORITHM:
    mapping = {
        "rsa-pkcs1-sha1": ALGORITHM.RSA_PKCS1_SHA1,
        "rsa-pkcs1-sha256": ALGORITHM.RSA_PKCS1_SHA256,
        "rsa-pkcs1-sha384": ALGORITHM.RSA_PKCS1_SHA384,
        "rsa-pkcs1-sha512": ALGORITHM.RSA_PKCS1_SHA512,
        "rsa-pss-sha1": ALGORITHM.RSA_PSS_SHA1,
        "rsa-pss-sha256": ALGORITHM.RSA_PSS_SHA256,
        "rsa-pss-sha384": ALGORITHM.RSA_PSS_SHA384,
        "rsa-pss-sha512": ALGORITHM.RSA_PSS_SHA512,
        "rsa2048": ALGORITHM.RSA_2048,
        "rsa3072": ALGORITHM.RSA_3072,
        "rsa4096": ALGORITHM.RSA_4096,
        "ecp256": ALGORITHM.EC_P256,
        "ecp384": ALGORITHM.EC_P384,
        "ecp521": ALGORITHM.EC_P521,
        "eck256": ALGORITHM.EC_K256,
        "ecbp256": ALGORITHM.EC_BP256,
        "ecbp384": ALGORITHM.EC_BP384,
        "ecbp512": ALGORITHM.EC_BP512,
        "hmac-sha1": ALGORITHM.HMAC_SHA1,
        "hmac-sha256": ALGORITHM.HMAC_SHA256,
        "hmac-sha384": ALGORITHM.HMAC_SHA384,
        "hmac-sha512": ALGORITHM.HMAC_SHA512,
        "ecdsa-sha1": ALGORITHM.EC_ECDSA_SHA1,
        "ecdh": ALGORITHM.EC_ECDH,
        "rsa-oaep-sha1": ALGORITHM.RSA_OAEP_SHA1,
        "rsa-oaep-sha256": ALGORITHM.RSA_OAEP_SHA256,
        "rsa-oaep-sha384": ALGORITHM.RSA_OAEP_SHA384,
        "rsa-oaep-sha512": ALGORITHM.RSA_OAEP_SHA512,
        "aes128-ccm-wrap": ALGORITHM.AES128_CCM_WRAP,
        "opaque-data": ALGORITHM.OPAQUE_DATA,
        "opaque-x509-certificate": ALGORITHM.OPAQUE_X509_CERTIFICATE,
        "mgf1-sha1": ALGORITHM.RSA_MGF1_SHA1,
        "mgf1-sha256": ALGORITHM.RSA_MGF1_SHA256,
        "mgf1-sha384": ALGORITHM.RSA_MGF1_SHA384,
        "mgf1-sha512": ALGORITHM.RSA_MGF1_SHA512,
        "template-ssh": ALGORITHM.TEMPLATE_SSH,
        "aes128-yubico-otp": ALGORITHM.AES128_YUBICO_OTP,
        "aes128-yubico-authentication": ALGORITHM.AES128_YUBICO_AUTHENTICATION,
        "aes192-yubico-otp": ALGORITHM.AES192_YUBICO_OTP,
        "aes256-yubico-otp": ALGORITHM.AES256_YUBICO_OTP,
        "aes192-ccm-wrap": ALGORITHM.AES192_CCM_WRAP,
        "aes256-ccm-wrap": ALGORITHM.AES256_CCM_WRAP,
        "ecdsa-sha256": ALGORITHM.EC_ECDSA_SHA256,
        "ecdsa-sha384": ALGORITHM.EC_ECDSA_SHA384,
        "ecdsa-sha512": ALGORITHM.EC_ECDSA_SHA512,
        "ed25519": ALGORITHM.EC_ED25519,
        "ecp224": ALGORITHM.EC_P224
    }
    if mapping.get(name_literal.lower(), None) is None:
        raise ValueError(f"Unknown algorithm name '{name_literal}'")
    return mapping[name_literal.lower()]


def create_asymmetric_keys_on_hsm(ses: AuthSession, conf: hscfg.HSMConfig, key_defs: Sequence[hscfg.HSMAsymmetricKey]) -> list[AsymmetricKey]:
    """
    Create a set of asymmetric keys in the HSM, optionally deleting and recreating existing keys.

    Args:
        ses (AuthSession): The authenticated HSM session
        key_defs (Sequence[HSMAsymmetricKey]): The list of key definitions to create
    """

    existing: Sequence[YhsmObject] = ses.list_objects()
    for obj in existing:
        if isinstance(obj, AsymmetricKey) and obj.id in [d.id for d in key_defs]:
            click.echo(f"AsymmetricKey ID '{hex(obj.id)}' already exists")
            if click.confirm("Delete and recreate?"):
                obj.delete()
            else:
                raise click.Abort()

    res = []
    for kdef in key_defs:
        click.echo(f"Creating key '{kdef.label}' ID '{hex(kdef.id)}' ({kdef.algorithm}) ...", nl=False)
        res.append(AsymmetricKey.generate(
                session=ses,
                object_id=kdef.id,
                label=kdef.label,
                domains=conf.get_domain_bitfield(kdef.domains),
                capabilities=encode_capabilities(kdef.capabilities),
                algorithm=encode_algorithm(kdef.algorithm)
            ))
        click.echo("done")

    return res


def print_yubihsm_object(o):
    info = o.get_info()
    domains = hscfg.HSMConfig.domain_bitfield_to_nums(info.domains)
    domains = {"all"} if len(domains) == 16 else domains
    click.echo(f"0x{o.id:04x}")
    click.echo(f"  type:           {o.object_type.name} ({o.object_type})")
    click.echo(f"  label:          {repr(info.label)}")
    click.echo(f"  algorithm:      {info.algorithm.name} ({info.algorithm})")
    click.echo(f"  size:           {info.size}")
    click.echo(f"  origin:         {info.origin.name} ({info.origin})")
    click.echo(f"  domains:        {domains}")
    click.echo(f"  capabilities:   {hscfg.HSMConfig.capability_to_names(info.capabilities)}")
    click.echo(f"  delegated_caps: {hscfg.HSMConfig.capability_to_names(info.delegated_capabilities)}")
