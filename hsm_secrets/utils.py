from dataclasses import dataclass
from enum import Enum
import os
from textwrap import dedent
from typing import Callable, Generator, Optional, Sequence
from contextlib import contextmanager

import click

from yubihsm import YubiHsm     # type: ignore [import]
from yubihsm.core import AuthSession     # type: ignore [import]
from yubihsm.defs import CAPABILITY, ALGORITHM, ERROR, OBJECT     # type: ignore [import]
from yubihsm.objects import AsymmetricKey, HmacKey, SymmetricKey, WrapKey, YhsmObject, AuthenticationKey     # type: ignore [import]
from yubikit.hsmauth import HsmAuthSession     # type: ignore [import]
from yubihsm.exceptions import YubiHsmDeviceError     # type: ignore [import]

from ykman import scripting
import yubikit.core
import yubikit.hsmauth as hsmauth

import hsm_secrets.config as hscfg
import curses
import click

from functools import wraps

class HSMAuthMethod(Enum):
    YUBIKEY = 1
    DEFAULT_ADMIN = 2
    PASSWORD = 3


@dataclass
class HsmSecretsCtx:
    click_ctx: click.Context
    conf: hscfg.HSMConfig
    hsm_serial: str
    yubikey_label: str
    quiet: bool = False
    forced_auth_method: Optional[HSMAuthMethod] = None
    auth_password: Optional[str] = None
    auth_password_id: Optional[int] = None


def pass_common_args(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        click_ctx = click.get_current_context()
        ctx = HsmSecretsCtx(
            click_ctx = click_ctx,
            conf = click_ctx.obj['config'],
            hsm_serial = click_ctx.obj.get('hsmserial'),
            yubikey_label = click_ctx.obj.get('yubikey_label'),
            quiet=click_ctx.obj.get('quiet', False),
            forced_auth_method = click_ctx.obj.get('forced_auth_method'),
            auth_password = click_ctx.obj.get('auth_password'),
            auth_password_id = click_ctx.obj.get('auth_password_id'))

        try:
            return f(ctx, *args, **kwargs)
        except YubiHsmDeviceError as e:
            if e.code == ERROR.OBJECT_NOT_FOUND:
                cli_error(f"Object not found in HSM: {e}")
            elif e.code == ERROR.INSUFFICIENT_PERMISSIONS:
                cli_error(f"Insufficient permissions for HSM operation: {e}")
            elif e.code == ERROR.AUTHENTICATION_FAILED:
                cli_error(f"HSM Authentication failed: {e}")
            else:
                cli_error(f"HSM operation failed: {e}")
            raise click.Abort()

    return wrapper


def cli_info(*args, **kwargs):
    """
    Only print if not in quiet mode.
    """
    if not (click.get_current_context().obj or {}).get('quiet', False):
        click.echo(*args, **kwargs)


def cli_code_info(msg: str):
    """
    Print a message with code formatting, if not in quiet mode.
    Commands are assumed to be enclosed in `backticks` and not span multiple lines.
    """
    lines = msg.split('\n')
    for l in lines:
        parts = l.split('`')
        for i, p in enumerate(parts):
            if i % 2 == 0:
                cli_info(p, nl=False)
            else:
                cli_info(click.style(p, fg='cyan'), nl=False)
        cli_info("")

def cli_result(*args, **kwargs):
    """
    Print a result message to stdout, always
    """
    click.echo(*args, **kwargs)

def cli_ui_msg(*args, **kwargs):
    """
    Print a message to stderr (despite quiet mode)
    """
    click.echo(*args, **kwargs, err=True)

def cli_error(msg: str):
    """
    Print an error message to stderr, colored red
    """
    click.echo(click.style(msg, fg='red'), err=True)

def cli_warn(*args, **kwargs):
    """
    Print a warning message to stderr, colored yellow, if not in quiet mode.
    """
    if not (click.get_current_context().obj or {}).get('quiet', False):
        click.echo(click.style(*args, fg='yellow', **kwargs), err=True)




def pw_check_fromhex(pw: str) -> str|None:
    try:
        _ = bytes.fromhex(pw)
        return None
    except ValueError:
        return "Must be a hex-encoded string."


def prompt_for_secret(
        prompt: str,
        confirm: bool = False,
        default: str|None = None,
        enc_test='utf-8',
        check_fn: Callable|None = None) -> str:
    """
    Prompt the user for a secret string, optionally confirming by typing it again.

    :param prompt: The prompt message to display
    :param confirm: Whether to confirm by typing it again
    :param default: The default to use if the user just presses ENTER (None for no default)
    :param enc_test: The encoding to test with (refuse non-encodable strings)
    :param check_fn: A function to check the input, returning an error message if invalid
    :return: The user-entered secret string
    """
    check_fn = check_fn or (lambda pw: None)
    while True:
        pw = click.prompt(prompt, hide_input=True, default=default, err=True)
        assert isinstance(pw, str)
        try:
            pw.encode(enc_test)
            if error := check_fn(pw):
                cli_error(error)
                continue

            if confirm:
                if click.prompt("Type again to confirm", hide_input=True, default=default, err=True) == pw:
                    return pw
                cli_warn("Mismatch. Try again.")
            else:
                return pw
        except UnicodeEncodeError:
            cli_error(f"Failed to encode into {enc_test.upper()}. Try again.")


def group_by_4(s: str) -> str:
    """
    Group a string into 4-character blocks separated by spaces.
    """
    res = " ".join([s[i:i+4] for i in range(0, len(s), 4)])
    assert s == res.replace(' ', ''), f"Grouping failed: {s} -> {res}"
    return res


def list_yubikey_hsm_creds() -> Sequence[hsmauth.Credential]:
    """
    List the labels of all YubiKey HSM auth credentials.
    """
    yubikey = scripting.single()    # Connect to the first YubiKey found
    auth_ses = hsmauth.HsmAuthSession(connection=yubikey.smart_card())
    return list(auth_ses.list_credentials())


def connect_hsm_and_auth_with_yubikey(config: hscfg.HSMConfig, yubikey_slot_label: str, device_serial: str|None, yubikey_password: Optional[str] = None) -> AuthSession:
    """
    Connects to a YubHSM and authenticates a session using the first YubiKey found.
    YubiHSM auth key ID is read from the config file by label (arg yubikey_slot_label).

    Args:
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
        cli_info(f"Authenticating as YubiHSM key ID '{hex(auth_key_id)}' with local YubiKey ({yubikey.info.serial}) hsmauth slot '{yubikey_slot_label}'")

        try:
            symmetric_auth = hsm.init_session(auth_key_id)
        except YubiHsmDeviceError as e:
            if e.code == ERROR.OBJECT_NOT_FOUND:
                cli_error(f"YubiHSM auth key '0x{auth_key_id:04x}' not found. Aborting.")
                exit(1)
            raise

        pwd = yubikey_password or prompt_for_secret(f"Enter PIN/password for YubiKey HSM slot '{yubikey_slot_label}'")

        cli_ui_msg(f"Authenticating... " + click.style("(Touch your YubiKey if it blinks)", fg='yellow', blink=True))
        session_keys = hsmauth.calculate_session_keys_symmetric(
            label=yubikey_slot_label,
            credential_password=pwd,
            context=symmetric_auth.context)

        session = symmetric_auth.authenticate(*session_keys)

        cli_info(f"Session authenticated Ok.")
        cli_info("")
        return session

    except yubikit.core.InvalidPinError as e:
        cli_error(f"InvalidPinError for YubiKey HSM slot '{yubikey_slot_label}':")
        cli_error(str(e))
        exit(1)


def verify_hsm_device_info(device_serial, hsm):
    info = hsm.get_device_info()
    if int(device_serial) != int(info.serial):
        raise ValueError(f"Device serial mismatch! Connected='{hsm.serial}', Expected='{device_serial}'")

@contextmanager
def open_hsm_session(
        ctx: HsmSecretsCtx,
        default_auth_method: HSMAuthMethod = HSMAuthMethod.YUBIKEY,
        device_serial: str | None = None) -> Generator[AuthSession, None, None]:
    """
    Open a session to the HSM using forced or given default auth method.
    This is an auto-selecting wrapper for the specific session context managers.
    """
    auth_method = ctx.forced_auth_method or default_auth_method
    device_serial = device_serial or ctx.hsm_serial

    if auth_method == HSMAuthMethod.YUBIKEY:
        ctxman = open_hsm_session_with_yubikey(ctx, device_serial)
    elif auth_method == HSMAuthMethod.DEFAULT_ADMIN:
        ctxman = open_hsm_session_with_default_admin(ctx, device_serial)
    elif auth_method == HSMAuthMethod.PASSWORD:
        assert device_serial, "HSM device serial not provided nor inferred. Cannot use shared secret auth."
        assert ctx.auth_password and ctx.auth_password_id
        ctxman = open_hsm_session_with_password(ctx, ctx.auth_password_id, ctx.auth_password, device_serial)
    else:
        raise ValueError(f"Unknown auth method: {auth_method}")
    with ctxman as session:
        yield session


@contextmanager
def open_hsm_session_with_yubikey(ctx: HsmSecretsCtx, device_serial: str|None = None) -> Generator[AuthSession, None, None]:
    """
    Open a session to the HSM using the first YubiKey found, and authenticate with the YubiKey HSM auth label.
    """
    device_serial = device_serial or ctx.hsm_serial
    passwd = os.environ.get('YUBIKEY_PASSWORD', None)
    if passwd:
        cli_info("Using YubiKey password from environment variable.")
    session = connect_hsm_and_auth_with_yubikey(ctx.conf, ctx.yubikey_label, device_serial, passwd)
    try:
        yield session
    finally:
        session.close()


@contextmanager
def open_hsm_session_with_default_admin(ctx: HsmSecretsCtx, device_serial: str|None = None) -> Generator[AuthSession, None, None]:
    """
    Open a session to the HSM using the first YubiKey found, and authenticate with the YubiKey HSM auth label.
    """
    device_serial = device_serial or ctx.hsm_serial
    assert device_serial, "HSM device serial not provided nor inferred."

    cli_info(click.style(f"Using insecure default admin key to auth on YubiHSM2 {device_serial}.", fg='magenta'))

    connector_url = ctx.conf.general.all_devices.get(device_serial)
    if not connector_url:
        raise ValueError(f"Device serial '{device_serial}' not found in config file.")

    hsm = YubiHsm.connect(connector_url)
    verify_hsm_device_info(device_serial, hsm)

    session = None

    try:
        session = hsm.create_session_derived(ctx.conf.admin.default_admin_key.id, ctx.conf.admin.default_admin_password)
        cli_info(click.style(f"HSM session {session.sid} started.", fg='magenta'))
    except YubiHsmDeviceError as e:
        if e.code == ERROR.OBJECT_NOT_FOUND:
            cli_error(f"Default admin key '0x{ctx.conf.admin.default_admin_key.id:04x}' not found. Aborting.")
            exit(1)
        raise

    try:
        yield session
    finally:
        cli_info(click.style(f"Closing HSM session {session.sid}.", fg='magenta'))
        session.close()
        hsm.close()


@contextmanager
def open_hsm_session_with_password(ctx: HsmSecretsCtx, auth_key_id: int, password: str, device_serial: str|None = None) -> Generator[AuthSession, None, None]:
    """
    Open a session to the HSM using a password-derived auth key.
    """
    device_serial = device_serial or ctx.hsm_serial
    assert device_serial, "HSM device serial not provided nor inferred."

    connector_url = ctx.conf.general.all_devices.get(device_serial)
    if not connector_url:
        raise ValueError(f"Device serial '{device_serial}' not found in config file.")

    hsm = YubiHsm.connect(connector_url)
    verify_hsm_device_info(device_serial, hsm)

    cli_info(f"Using password login with key ID 0x{auth_key_id:04x}")
    session = hsm.create_session_derived(auth_key_id, password)
    try:
        yield session
    finally:
        session.close()
        hsm.close()


def encode_capabilities(names: Sequence[hscfg.AsymmetricCapabilityName] | set[hscfg.AsymmetricCapabilityName]) -> CAPABILITY:
    return hscfg.HSMConfig.capability_from_names(set(names))

def encode_algorithm(name_literal: str|hscfg.AsymmetricAlgorithm) -> ALGORITHM:
    return hscfg.HSMConfig.algorithm_from_name(name_literal)   # type: ignore


def hsm_put_wrap_key(ses: AuthSession, hsm_serial: str, conf: hscfg.HSMConfig, key_def: hscfg.HSMWrapKey, key: bytes) -> WrapKey:
    """
    Put a (symmetric) wrap key into the HSM.
    """
    wrap_key = ses.get_object(key_def.id, OBJECT.WRAP_KEY)
    assert isinstance(wrap_key, WrapKey)
    confirm_and_delete_old_yubihsm_object_if_exists(hsm_serial, wrap_key)
    res = wrap_key.put(
        session = ses,
        object_id = key_def.id,
        label = key_def.label,
        algorithm = conf.algorithm_from_name(key_def.algorithm),
        domains = conf.get_domain_bitfield(key_def.domains),
        capabilities = conf.capability_from_names(set(key_def.capabilities)),
        delegated_capabilities = conf.capability_from_names(set(key_def.delegated_capabilities)),
        key = key)
    cli_info(f"Wrap key ID '{hex(res.id)}' stored in YubiHSM device {hsm_serial}")
    return res


def hsm_put_derived_auth_key(ses: AuthSession, hsm_serial: str, conf: hscfg.HSMConfig, key_def: hscfg.HSMAuthKey, password: str) -> AuthenticationKey:
    """
    Put a password-derived authentication key into the HSM.
    """
    auth_key = ses.get_object(key_def.id, OBJECT.AUTHENTICATION_KEY)
    assert isinstance(auth_key, AuthenticationKey)
    confirm_and_delete_old_yubihsm_object_if_exists(hsm_serial, auth_key)
    res = auth_key.put_derived(
        session = ses,
        object_id = key_def.id,
        label = key_def.label,
        domains = conf.get_domain_bitfield(key_def.domains),
        capabilities = conf.capability_from_names(key_def.capabilities),
        delegated_capabilities = conf.capability_from_names(key_def.delegated_capabilities),
        password = password)
    cli_info(f"Auth key ID '{hex(res.id)}' ({key_def.label}) stored in YubiHSM device {hsm_serial}")
    return res


def hsm_put_symmetric_auth_key(ses: AuthSession, hsm_serial: str, conf: hscfg.HSMConfig, key_def: hscfg.HSMAuthKey, key_enc: bytes, key_mac: bytes) -> AuthenticationKey:
    """
    Put a symmetric authentication key into the HSM.
    """
    auth_key = ses.get_object(key_def.id, OBJECT.AUTHENTICATION_KEY)
    assert isinstance(auth_key, AuthenticationKey)
    confirm_and_delete_old_yubihsm_object_if_exists(hsm_serial, auth_key)
    res = auth_key.put(
        session = ses,
        object_id = key_def.id,
        label = key_def.label,
        domains = conf.get_domain_bitfield(key_def.domains),
        capabilities = conf.capability_from_names(key_def.capabilities),
        delegated_capabilities = conf.capability_from_names(key_def.delegated_capabilities),
        key_enc = key_enc,
        key_mac = key_mac)
    cli_info(f"Auth key ID '{hex(res.id)}' ({key_def.label}) stored in YubiHSM device {hsm_serial}")
    return res


def hsm_generate_symmetric_key(ses: AuthSession, hsm_serial: str, conf: hscfg.HSMConfig, key_def: hscfg.HSMSymmetricKey) -> SymmetricKey:
    """
    Generate a symmetric key on the HSM.
    """
    sym_key = ses.get_object(key_def.id, OBJECT.SYMMETRIC_KEY)
    assert isinstance(sym_key, SymmetricKey)
    confirm_and_delete_old_yubihsm_object_if_exists(hsm_serial, sym_key)
    cli_info(f"Generating symmetric key, type '{key_def.algorithm}'...")
    res = sym_key.generate(
        session = ses,
        object_id = key_def.id,
        label = key_def.label,
        domains = conf.get_domain_bitfield(key_def.domains),
        capabilities = conf.capability_from_names(set(key_def.capabilities)),
        algorithm = conf.algorithm_from_name(key_def.algorithm))
    cli_info(f"Symmetric key ID '{hex(res.id)}' ({key_def.label}) generated in YubiHSM device {hsm_serial}")
    return res


def hsm_generate_asymmetric_key(ses: AuthSession, hsm_serial: str, conf: hscfg.HSMConfig, key_def: hscfg.HSMAsymmetricKey) -> AsymmetricKey:
    """
    Generate an asymmetric key on the HSM.
    """
    asym_key = ses.get_object(key_def.id, OBJECT.ASYMMETRIC_KEY)
    assert isinstance(asym_key, AsymmetricKey)
    confirm_and_delete_old_yubihsm_object_if_exists(hsm_serial, asym_key)
    cli_info(f"Generating asymmetric key, type '{key_def.algorithm}'...")
    if 'rsa' in key_def.algorithm.lower():
        cli_warn("  Note! RSA key generation is very slow. Please wait. The YubiHSM2 should blinking rapidly while it works.")
        cli_warn("  If the process aborts / times out, you can rerun this command to resume.")
    res = asym_key.generate(
        session = ses,
        object_id  = key_def.id,
        label = key_def.label,
        domains = conf.get_domain_bitfield(key_def.domains),
        capabilities = conf.capability_from_names(set(key_def.capabilities)),
        algorithm = conf.algorithm_from_name(key_def.algorithm))
    cli_info(f"Symmetric key ID '{hex(res.id)}' ({key_def.label}) stored in YubiHSM device {hsm_serial}")
    return res


def hsm_generate_hmac_key(ses: AuthSession, hsm_serial: str, conf: hscfg.HSMConfig, key_def: hscfg.HSMHmacKey) -> HmacKey:
    """
    Generate an HMAC key on the HSM.
    """
    hmac_key = ses.get_object(key_def.id, OBJECT.HMAC_KEY)
    assert isinstance(hmac_key, HmacKey)
    confirm_and_delete_old_yubihsm_object_if_exists(hsm_serial, hmac_key)
    cli_info(f"Generating HMAC key, type '{key_def.algorithm}'...")
    res = hmac_key.generate(
        session = ses,
        object_id = key_def.id,
        label = key_def.label,
        domains = conf.get_domain_bitfield(key_def.domains),
        capabilities = conf.capability_from_names(set(key_def.capabilities)),
        algorithm = conf.algorithm_from_name(key_def.algorithm))
    cli_info(f"HMAC key ID '{hex(res.id)}' ({key_def.label}) stored in YubiHSM device {hsm_serial}")
    return res


def pretty_fmt_yubihsm_object(o: YhsmObject):
    info = o.get_info()
    domains: set|str = hscfg.HSMConfig.domain_bitfield_to_nums(info.domains)
    domains = "all" if len(domains) == 16 else domains
    return dedent(f"""
    0x{o.id:04x}
        type:           {o.object_type.name} ({o.object_type})
        label:          {repr(info.label)}
        algorithm:      {info.algorithm.name} ({info.algorithm})
        size:           {info.size}
        origin:         {info.origin.name} ({info.origin})
        domains:        {domains}
        capabilities:   {hscfg.HSMConfig.capability_to_names(info.capabilities)}
        delegated_caps: {hscfg.HSMConfig.capability_to_names(info.delegated_capabilities)}
    """).strip()


def hsm_obj_exists(hsm_key_obj: YhsmObject) -> bool:
    """
    Check if a YubiHSM object exists.
    :param hsm_key_obj: The object to check for
    :return: True if the object exists
    """
    try:
        _ = hsm_key_obj.get_info()  # Raises an exception if the key does not exist
        return True
    except YubiHsmDeviceError as e:
        if e.code == ERROR.OBJECT_NOT_FOUND:
            return False
        raise e


def confirm_and_delete_old_yubihsm_object_if_exists(serial: str, obj: YhsmObject, abort=True) -> bool:
    """
    Check if a YubiHSM object exists, and if so, ask the user if they want to replace it.
    :param serial: The serial number of the YubiHSM device
    :param hsm_key_obj: The object to check for
    :param abort: Whether to abort (raise) if the user does not want to delete the object
    :return: True if the object doesn't exist or was deleted, False if the user chose not to delete it
    """
    if hsm_obj_exists(obj):
        cli_ui_msg(f"Object 0x{obj.id:04x} already exists on YubiHSM device {serial}:", err=True)
        cli_ui_msg(pretty_fmt_yubihsm_object(obj))
        cli_info("")
        if click.confirm("Replace the existing key?", default=False, abort=abort, err=True):
            obj.delete()
        else:
            return False
    return True



def secure_display_secret(secret_to_show: str, wipe_char='x'):
    """
    Display a secret on full screen, and then wipe from the screen (and scroll buffer).
    """
    secret = secret_to_show + " "
    def do_it(stdscr):
        stdscr.clear()

        # Create a new window
        height, width = stdscr.getmaxyx()
        win_height = 3
        win_width = len(secret) + 4
        win = curses.newwin(win_height, win_width, height // 2 - 1, width // 2 - win_width // 2)

        # Display the secret
        win.box()
        win.addstr(1, 2, secret)
        win.refresh()

        click.pause("") # Wait for ENTER key

        # Overwrite the secret with wipe_char
        stdscr.clear()
        win.box()
        win.addstr(1, 2, wipe_char * len(secret))
        win.refresh()

    curses.wrapper(do_it)
