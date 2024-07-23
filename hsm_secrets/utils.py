from dataclasses import dataclass
from enum import Enum
import os
from typing import Callable, Generator, Optional, Sequence
from contextlib import _GeneratorContextManager, contextmanager

from click import echo
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
            forced_auth_method = click_ctx.obj.get('forced_auth_method'),
            auth_password = click_ctx.obj.get('auth_password'),
            auth_password_id = click_ctx.obj.get('auth_password_id'))
        return f(ctx, *args, **kwargs)
    return wrapper


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
        pw = click.prompt(prompt, hide_input=True)
        assert isinstance(pw, str)
        try:
            pw.encode(enc_test)
            if error := check_fn(pw):
                echo(click.style(str(error), fg='red'))
                continue

            if confirm:
                if click.prompt("Type again to confirm", hide_input=True, default=default) == pw:
                    return pw
                echo(click.style("Mismatch. Try again.", fg='red'))
            else:
                return pw
        except UnicodeEncodeError:
            echo(click.style(f"Failed to encode into {enc_test.upper()}. Try again.", fg='red'))


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
        click.echo(f"Authenticating as YubiHSM key ID '{hex(auth_key_id)}' with local YubiKey ({yubikey.info.serial}) hsmauth slot '{yubikey_slot_label}'")

        try:
            symmetric_auth = hsm.init_session(auth_key_id)
        except YubiHsmDeviceError as e:
            if e.code == ERROR.OBJECT_NOT_FOUND:
                echo(click.style(f"YubiHSM auth key '0x{auth_key_id:04x}' not found. Aborting.", fg='red'))
                exit(1)
            raise

        pwd = yubikey_password or prompt_for_secret(f"Enter PIN/password for YubiKey HSM slot '{yubikey_slot_label}'")

        echo(f"Authenticating... " + click.style("(Touch your YubiKey if it blinks)", fg='yellow'))
        session_keys = hsmauth.calculate_session_keys_symmetric(
            label=yubikey_slot_label,
            credential_password=pwd,
            context=symmetric_auth.context)

        session = symmetric_auth.authenticate(*session_keys)

        echo(f"Session authenticated Ok.")
        echo("")
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
        echo("Using YubiKey password from environment variable.")
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

    click.echo(click.style(f"Using insecure default admin key to auth on YubiHSM2 {device_serial}.", fg='magenta'))

    connector_url = ctx.conf.general.all_devices.get(device_serial)
    if not connector_url:
        raise ValueError(f"Device serial '{device_serial}' not found in config file.")

    hsm = YubiHsm.connect(connector_url)
    verify_hsm_device_info(device_serial, hsm)

    session = None

    try:
        session = hsm.create_session_derived(ctx.conf.admin.default_admin_key.id, ctx.conf.admin.default_admin_password)
        click.echo(click.style(f"HSM session {session.sid} started.", fg='magenta'))
    except YubiHsmDeviceError as e:
        if e.code == ERROR.OBJECT_NOT_FOUND:
            echo(click.style(f"Default admin key '0x{ctx.conf.admin.default_admin_key.id:04x}' not found. Aborting.", fg='red'))
            exit(1)
        raise

    try:
        yield session
    finally:
        click.echo(click.style(f"Closing HSM session {session.sid}.", fg='magenta'))
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

    click.echo(f"Using password login with key ID 0x{auth_key_id:04x}")
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
    click.echo(f"Wrap key ID '{hex(res.id)}' stored in YubiHSM device {hsm_serial}")
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
    click.echo(f"Auth key ID '{hex(res.id)}' ({key_def.label}) stored in YubiHSM device {hsm_serial}")
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
    click.echo(f"Auth key ID '{hex(res.id)}' ({key_def.label}) stored in YubiHSM device {hsm_serial}")
    return res


def hsm_generate_symmetric_key(ses: AuthSession, hsm_serial: str, conf: hscfg.HSMConfig, key_def: hscfg.HSMSymmetricKey) -> SymmetricKey:
    """
    Generate a symmetric key on the HSM.
    """
    sym_key = ses.get_object(key_def.id, OBJECT.SYMMETRIC_KEY)
    assert isinstance(sym_key, SymmetricKey)
    confirm_and_delete_old_yubihsm_object_if_exists(hsm_serial, sym_key)
    click.echo(f"Generating symmetric key, type '{key_def.algorithm}'...")
    res = sym_key.generate(
        session = ses,
        object_id = key_def.id,
        label = key_def.label,
        domains = conf.get_domain_bitfield(key_def.domains),
        capabilities = conf.capability_from_names(set(key_def.capabilities)),
        algorithm = conf.algorithm_from_name(key_def.algorithm))
    click.echo(f"Symmetric key ID '{hex(res.id)}' ({key_def.label}) generated in YubiHSM device {hsm_serial}")
    return res


def hsm_generate_asymmetric_key(ses: AuthSession, hsm_serial: str, conf: hscfg.HSMConfig, key_def: hscfg.HSMAsymmetricKey) -> AsymmetricKey:
    """
    Generate an asymmetric key on the HSM.
    """
    asym_key = ses.get_object(key_def.id, OBJECT.ASYMMETRIC_KEY)
    assert isinstance(asym_key, AsymmetricKey)
    confirm_and_delete_old_yubihsm_object_if_exists(hsm_serial, asym_key)
    click.echo(f"Generating asymmetric key, type '{key_def.algorithm}'...")
    if 'rsa' in key_def.algorithm.lower():
        click.echo("  Note! RSA key generation is very slow. Please wait. The YubiHSM2 should be blinking while it works.")
        click.echo("  If the process aborts / times out, you can rerun this command to resume.")
    res = asym_key.generate(
        session = ses,
        object_id  = key_def.id,
        label = key_def.label,
        domains = conf.get_domain_bitfield(key_def.domains),
        capabilities = conf.capability_from_names(set(key_def.capabilities)),
        algorithm = conf.algorithm_from_name(key_def.algorithm))
    click.echo(f"Symmetric key ID '{hex(res.id)}' ({key_def.label}) stored in YubiHSM device {hsm_serial}")
    return res


def hsm_generate_hmac_key(ses: AuthSession, hsm_serial: str, conf: hscfg.HSMConfig, key_def: hscfg.HSMHmacKey) -> HmacKey:
    """
    Generate an HMAC key on the HSM.
    """
    hmac_key = ses.get_object(key_def.id, OBJECT.HMAC_KEY)
    assert isinstance(hmac_key, HmacKey)
    confirm_and_delete_old_yubihsm_object_if_exists(hsm_serial, hmac_key)
    click.echo(f"Generating HMAC key, type '{key_def.algorithm}'...")
    res = hmac_key.generate(
        session = ses,
        object_id = key_def.id,
        label = key_def.label,
        domains = conf.get_domain_bitfield(key_def.domains),
        capabilities = conf.capability_from_names(set(key_def.capabilities)),
        algorithm = conf.algorithm_from_name(key_def.algorithm))
    click.echo(f"HMAC key ID '{hex(res.id)}' ({key_def.label}) stored in YubiHSM device {hsm_serial}")
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
        click.echo(f"Object 0x{obj.id:04x} already exists on YubiHSM device {serial}:")
        print_yubihsm_object(obj)
        click.echo("")
        if click.confirm("Replace the existing key?", default=False, abort=abort):
            obj.delete()
        else:
            return False
    return True


def click_echo_colored_commands(msg: str, color: str = 'cyan'):
    """
    Print a message with colored commands.
    Commands are assumed to be enclosed in `backticks` and not span multiple lines.
    """
    lines = msg.split('\n')
    for l in lines:
        parts = l.split('`')
        for i, p in enumerate(parts):
            if i % 2 == 0:
                echo(p, nl=False)
            else:
                echo(click.style(p, fg=color), nl=False)
        echo("")


def secure_display_secret(secret_to_show: str, wipe_char='x'):
    """
    Display a secret on the screen, and then wipe from the screen (and scroll buffer).
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
