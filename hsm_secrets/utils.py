from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
from textwrap import dedent
from typing import Callable, Generator, Optional
from contextlib import _GeneratorContextManager, contextmanager

# YubiHSM 2
import requests
import urllib3
from io import BytesIO

from yubihsm import YubiHsm     # type: ignore [import]
from yubihsm.core import AuthSession     # type: ignore [import]
from yubihsm.defs import ERROR, OBJECT     # type: ignore [import]
from yubihsm.objects import ObjectInfo     # type: ignore [import]
from yubikit.hsmauth import HsmAuthSession     # type: ignore [import]
from yubihsm.exceptions import YubiHsmDeviceError     # type: ignore [import]

# YubiKey
import ykman.device
import ykman.scripting
import ykman
import yubikit.core

import hsm_secrets.config as hscfg
import unicurses as curses   # type: ignore [import]
import click

from functools import wraps

from hsm_secrets.yubihsm import HSMSession, MockHSMSession, RealHSMSession, open_mock_hsms, save_mock_hsms

class HSMAuthMethod(Enum):
    YUBIKEY = 1
    DEFAULT_ADMIN = 2
    PASSWORD = 3


@dataclass
class HsmSecretsCtx:
    """
    Context object to pass around common arguments and configuration.
    """
    click_ctx: click.Context

    conf: hscfg.HSMConfig
    hsm_serial: str
    yubikey_label: str
    quiet: bool = False

    # Authentication method overrides
    forced_auth_method: Optional[HSMAuthMethod] = None
    forced_yubikey_serial: Optional[str] = None         # If set, use this YubiKey for HSM auth
    auth_password: Optional[str] = None
    auth_password_id: Optional[int] = None

    mock_file: Optional[str] = None      # If set, load/save mock HSM objects in this file


def pass_common_args(f):
    """
    Decorator to pass common arguments to a command function, and
    """
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
            forced_yubikey_serial = click_ctx.obj.get('forced_yubikey_serial'),
            auth_password = click_ctx.obj.get('auth_password'),
            auth_password_id = click_ctx.obj.get('auth_password_id'),
            mock_file = click_ctx.obj.get('mock_file'))

        try:
            return f(ctx, *args, **kwargs)
        except YubiHsmDeviceError as e:
            if e.code == ERROR.OBJECT_NOT_FOUND:
                cli_error(f"Object not found in HSM: {e}")
                raise e
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


def cli_debug(msg: str):
    """
    Only print if debug mode is enabled.
    """
    if (click.get_current_context().obj or {}).get('debug', False):
        click.echo(f"DEBUG: {msg}", err=True)


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

def cli_prompt(*args, **kwargs):
    return click.prompt(click.style(*args, fg='bright_blue'), **kwargs, err=True)

def cli_confirm(*args, **kwargs):
    return click.confirm(click.style(*args, fg='bright_blue'), **kwargs, err=True)

def cli_pause(*args):
    return click.pause(click.style(*args, fg='bright_blue'), err=True)

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
    retries = 0
    while retries < 5:
        retries += 1
        pw = click.prompt(click.style(prompt, fg='bright_blue'), hide_input=True, default=default, err=True)
        assert isinstance(pw, str)
        try:
            pw.encode(enc_test)
            if error := check_fn(pw):
                cli_error(error)
                continue

            if confirm:
                if click.prompt(click.style("Type again to confirm", fg='bright_blue'), hide_input=True, default=default, err=True) == pw:
                    return pw
                cli_ui_msg("Mismatch. Try again.")
            else:
                assert isinstance(pw, str)
                return pw
        except UnicodeEncodeError:
            cli_error(f"Failed to encode into {enc_test.upper()}. Try again.")
    raise click.Abort("Too many retries. Aborting.")


def group_by_4(s: str) -> str:
    """
    Group a string into 4-character blocks separated by spaces.
    """
    res = " ".join([s[i:i+4] for i in range(0, len(s), 4)])
    assert s == res.replace(' ', ''), f"Grouping failed: {s} -> {res}"
    return res


def connect_hsm_and_auth_with_yubikey(config: hscfg.HSMConfig, yubikey_slot_label: str|None, device_serial: str|None, yubikey_password: str|None = None, auth_yubikey_serial: str|None = None) -> AuthSession:
    """
    Connects to a YubHSM and authenticates a session using the first YubiKey found.
    YubiHSM auth key ID is read from the config file by label (arg yubikey_slot_label).

    Args:
        config (Config): The configuration object containing the connector URL and user.
        yubikey_slot_label (str): The label of the YubiKey slot to use for authenticating with the HSM.
        device_serial (str): Serial number of the YubiHSM device to connect to.
        yubikey_password (Optional[str]): The password for the YubiKey HSM slot. If None, the user is asked for the password.
        auth_yubikey_serial (Optional[str]): If set, use this YubiKey for HSM auth - overrides require_one_hsmauth

    Returns:
        HsmAuthSession: The authenticated HSM session.
    """
    try:
        assert device_serial, "HSM device serial not provided nor inferred."
        connector_url = config.general.all_devices.get(device_serial)
        if not connector_url:
            raise ValueError(f"HSM device serial '{device_serial}' not found in config file.")

        cli_debug(f"[HSM] connect_hsm_and_auth_with_yubikey: Starting HSM authentication")
        yubikey, _ = scan_local_yubikeys(require_one_hsmauth=True, hsmauth_yk_serial=auth_yubikey_serial)
        assert yubikey
        cli_debug(f"[HSM] Found HSMauth YubiKey: {getattr(yubikey, 'serial', 'unknown')}")
        try:
            sc_hsm = yubikey.smart_card()
            cli_debug(f"[HSM] Opened smartcard connection for HSMauth YubiKey {getattr(yubikey, 'serial', 'unknown')}")
            hsmauth = HsmAuthSession(sc_hsm)
        except yubikit.core.ApplicationNotAvailableError:
            raise click.ClickException("YubiHSM auth not available on this YubiKey")

        if auth_yubikey_serial:
            assert str(yubikey.info.serial) == str(auth_yubikey_serial), f"SANITY CHECK FAILED! HSMauth YubiKey serial mismatch: {yubikey.info.serial} != {auth_yubikey_serial}"

        # Get first Yubikey HSM auth key label from device if not specified
        yubikey_label = yubikey_slot_label
        if not yubikey_label:
            yk_hsm_creds = list(hsmauth.list_credentials())
            if not yk_hsm_creds:
                raise click.ClickException("No YubiKey HSM credentials on device. Cannot authenticate.")
            else:
                yubikey_label = yk_hsm_creds[0].label

        hsm = YubiHsm.connect(connector_url)
        verify_hsm_device_info(device_serial, hsm)

        assert yubikey_label
        auth_key_id = config.find_auth_key(yubikey_label).id
        cli_info(f"Authenticating as YubiHSM key ID {hex(auth_key_id)} with local YubiKey '{yubikey.name} {yubikey.info.serial}' HSM auth slot '{yubikey_label}'")

        try:
            symmetric_auth = hsm.init_session(auth_key_id)
        except YubiHsmDeviceError as e:
            if e.code == ERROR.OBJECT_NOT_FOUND:
                cli_error(f"YubiHSM auth key '0x{auth_key_id:04x}' not found. Aborting.")
                exit(1)
            raise

        pwd = yubikey_password or prompt_for_secret(f"Enter PIN/password for YubiKey HSM slot '{yubikey_label}'")

        cli_ui_msg("Authenticating with YubiKey... " + click.style("(Touch it now if it blinks)", fg='blue', blink=True))
        session_keys = hsmauth.calculate_session_keys_symmetric(
            label=yubikey_label,
            credential_password=pwd,
            context=symmetric_auth.context)

        session = symmetric_auth.authenticate(*session_keys)
        cli_info("")

        # Close the smartcard connection for HSMauth YubiKey to prevent sharing violations
        sc_hsm.close()
        cli_debug(f"[HSM] Closed smartcard connection for HSMauth YubiKey {getattr(yubikey, 'serial', 'unknown')}")

        return session

    except yubikit.core.InvalidPinError as e:
        cli_error("InvalidPinError for YubiKey HSM slot")
        cli_error(str(e))
        exit(1)


def scan_local_yubikeys(require_one_hsmauth = True, require_one_other = False, hsmauth_yk_serial: str|None = None) -> tuple[Optional[ykman.scripting.ScriptingDevice], Optional[ykman.scripting.ScriptingDevice]]:
    """
    Scan for YubiKeys for a) HSM auth and b) other uses (e.g., PIV).
    This allows modifying other YubiKeys while authenticating on the HSM with a different YubiKey.

    If there's only one YubiKey, it will be returned for both uses.

    :param require_one_hsm: Require exactly one YubiKey with HSM credentials
    :param require_other: Require exactly one YubiKey for other uses
    :param hsmauth_yk_serial: If set, use this YubiKey for HSM auth - overrides require_one_hsmauth
    :return: Tuple of (YubiKey with HSM credentials, YubiKey for other uses)
    :raises click.ClickException: If requirements are not met, or if multiple YubiKeys are found for a single use
    """
    n_devices = len(ykman.device.list_all_devices())
    if n_devices == 0:
        if require_one_hsmauth or require_one_other:
            raise click.ClickException("No local YubiKey(s) found")
    elif n_devices == 1:
        # Only one YubiKey => check if it has HSMauth credentials if required
        yk_dev, yk_info = ykman.device.list_all_devices()[0]
        yk = ykman.scripting.ScriptingDevice(yk_dev, yk_info)
        if hsmauth_yk_serial and str(yk_info.serial) != str(hsmauth_yk_serial):
            raise click.ClickException(f"ERROR: YubiKey with serial {hsmauth_yk_serial} not found.")

        # Check if this single YubiKey has HSMauth credentials if required
        if require_one_hsmauth:
            sc = yk.smart_card()
            sc_closed = False
            cli_debug(f"[CONNECTION] Checking single YubiKey {yk_info.serial if yk_info.serial else 'unknown'} for HSMauth credentials")
            try:
                if not HsmAuthSession(connection=sc).list_credentials():
                    raise click.ClickException(f"YubiKey {yk_info.serial if yk_info.serial else 'unknown'} has no HSMauth credentials")
                cli_debug(f"[CONNECTION] Single YubiKey {yk_info.serial if yk_info.serial else 'unknown'} has HSMauth credentials")
            except yubikit.core.ApplicationNotAvailableError:
                raise click.ClickException(f"YubiKey {yk_info.serial if yk_info.serial else 'unknown'} does not support HSMauth")
            except yubikit.core.NotSupportedError:
                raise click.ClickException(f"YubiKey {yk_info.serial if yk_info.serial else 'unknown'} does not support HSMauth")
            finally:
                if not sc_closed and sc:
                    sc.close()
                    cli_debug(f"[CONNECTION] Closed smartcard connection for single YubiKey {yk_info.serial if yk_info.serial else 'unknown'}")

        return yk, yk
    elif n_devices == 2 and hsmauth_yk_serial:
        # Two YubiKeys, but one is forced for HSM auth
        hsm_yubikey, piv_yubikey = None, None
        for yk_dev, yk_info in ykman.device.list_all_devices():
            yk = ykman.scripting.ScriptingDevice(yk_dev, yk_info)
            if str(yk_info.serial) == str(hsmauth_yk_serial):
                hsm_yubikey = yk
            else:
                piv_yubikey = yk
        if not hsm_yubikey:
            raise click.ClickException(f"ERROR: YubiKey with serial {hsmauth_yk_serial} not found.")
        return hsm_yubikey, piv_yubikey

    # Multiple YubiKeys found, decide which one to use for which purpose
    hsm_yubikey, piv_yubikey = None, None
    for yk_dev, yk_info in ykman.device.list_all_devices():
        yk = ykman.scripting.ScriptingDevice(yk_dev, yk_info)
        sc = yk.smart_card()
        sc_closed = False
        cli_debug(f"[CONNECTION] Opened smartcard connection for YubiKey {yk_info.serial if yk_info.serial else 'unknown'}")
        try:
            if HsmAuthSession(connection=sc).list_credentials():
                cli_debug(f"[CONNECTION] Found HSMauth credentials on YubiKey {yk_info.serial if yk_info.serial else 'unknown'}")
                if not hsm_yubikey:
                    hsm_yubikey = yk
                    sc.close()
                    sc_closed = True
                    cli_debug(f"[CONNECTION] Closed smartcard connection for HSM YubiKey {yk_info.serial if yk_info.serial else 'unknown'}")
                    continue
                elif require_one_hsmauth:
                    raise click.ClickException("ERROR: Multiple YubiKeys found with HSM credentials. Can't decide which one to use for HSM auth.")
            else:
                cli_debug(f"[CONNECTION] No HSMauth credentials found on YubiKey {yk_info.serial if yk_info.serial else 'unknown'}")
        except yubikit.core.ApplicationNotAvailableError as e:
            cli_debug(f"[CONNECTION] ApplicationNotAvailableError on YubiKey {yk_info.serial if yk_info.serial else 'unknown'}: {e}")
            pass
        except yubikit.core.NotSupportedError as e:
            cli_debug(f"[CONNECTION] NotSupportedError on YubiKey {yk_info.serial if yk_info.serial else 'unknown'}: {e}")
            pass
        finally:
            # Ensure connection is always closed to prevent sharing violations
            if not sc_closed and sc:
                sc.close()
                cli_debug(f"[CONNECTION] Closed smartcard connection for YubiKey {yk_info.serial if yk_info.serial else 'unknown'} in finally block")
        if not piv_yubikey:
            piv_yubikey = yk
            continue
        elif require_one_other:
            raise click.ClickException("ERROR: Multiple YubiKeys found for other uses. Can't decide which one to return.")

    if not (hsm_yubikey and piv_yubikey):
        raise click.ClickException("ERROR: Initial scan found multiple YubiKeys, but failed to pick one for each use. Bug or unexpected device state change.")

    return hsm_yubikey, piv_yubikey




def verify_hsm_device_info(device_serial, hsm):
    info = hsm.get_device_info()
    if int(device_serial) != int(info.serial):
        raise ValueError(f"Device serial mismatch! Connected='{hsm.serial}', Expected='{device_serial}'")

@contextmanager
def open_hsm_session(
        ctx: HsmSecretsCtx,
        default_auth_method: HSMAuthMethod = HSMAuthMethod.YUBIKEY,
        device_serial: str | None = None) -> Generator[HSMSession, None, None]:
    """
    Open a session to the HSM using forced or given default auth method.
    This is an auto-selecting wrapper for the specific session context managers.
    """
    auth_method = ctx.forced_auth_method or default_auth_method
    device_serial = device_serial or ctx.hsm_serial

    # Mock HSM session for testing
    if ctx.mock_file:
        cli_warn("~🤡~ !! SIMULATED (mock) HSM session !! Authentication skipped. ~🤡~")
        auth_key_id = ctx.conf.admin.default_admin_key.id
        if auth_method == HSMAuthMethod.PASSWORD:
            if not ctx.auth_password_id:
                raise click.UsageError("Auth key ID (user login as) not specified for password auth method.")
            auth_key_id = ctx.auth_password_id
        elif auth_method == HSMAuthMethod.YUBIKEY:
            auth_key_id = ctx.conf.user_keys[0].id  # Mock YubiKey auth key with first user key from config
        open_mock_hsms(ctx.mock_file, int(device_serial), ctx.conf, auth_key_id)
        try:
            yield MockHSMSession(int(device_serial), auth_key_id)
        finally:
            save_mock_hsms(ctx.mock_file)
        return

    # Real HSM session with the selected auth method
    ctxman: _GeneratorContextManager[AuthSession|HSMSession]
    if auth_method == HSMAuthMethod.YUBIKEY:
        ctxman = open_hsm_session_with_yubikey(ctx, device_serial)
    elif auth_method == HSMAuthMethod.DEFAULT_ADMIN:
        ctxman = open_hsm_session_with_default_admin(ctx, device_serial)
    elif auth_method == HSMAuthMethod.PASSWORD:
        assert device_serial, "HSM device serial not provided nor inferred. Cannot use shared secret auth."
        if not ctx.auth_password_id:
            raise click.UsageError("Auth key ID (user login as) not specified for password auth method.")
        if not ctx.auth_password:
            raise click.UsageError("HSM_PASSWORD environment variable not set for password auth method.")
        ctxman = open_hsm_session_with_password(ctx, ctx.auth_password_id, ctx.auth_password, device_serial)
    else:
        raise ValueError(f"Unknown auth method: {auth_method}")
    with ctxman as ses:
        if isinstance(ses, HSMSession):
            yield ses
        else:
            yield RealHSMSession(ctx.conf, session=ses, dev_serial=int(device_serial))



def _close_hsm_session(ses):
    try:
        ses.close()
    except YubiHsmDeviceError as e:
        if e.code == ERROR.INVALID_SESSION:
            cli_warn("YubiHSM session invalidated. Already closed.")
        else:
            raise

@contextmanager
def open_hsm_session_with_yubikey(ctx: HsmSecretsCtx, device_serial: str|None = None) -> Generator[AuthSession, None, None]:
    """
    Open a session to the HSM using the first YubiKey found, and authenticate with the YubiKey HSM auth label.
    """
    device_serial = device_serial or ctx.hsm_serial
    passwd = os.environ.get('YUBIKEY_PASSWORD', None)
    if passwd:
        cli_info("Using YubiKey password from environment variable.")
    session = connect_hsm_and_auth_with_yubikey(ctx.conf, ctx.yubikey_label, device_serial, passwd, auth_yubikey_serial=ctx.forced_yubikey_serial)
    try:
        yield session
    finally:
        _close_hsm_session(session)


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
        _close_hsm_session(session)
        _close_hsm_session(hsm)


@contextmanager
def open_hsm_session_with_password(ctx: HsmSecretsCtx, auth_key_id: int, password: str, device_serial: str|None = None) -> Generator[HSMSession, None, None]:
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
        yield RealHSMSession(ctx.conf, session=session, dev_serial=int(device_serial))
    finally:
        _close_hsm_session(session)
        _close_hsm_session(hsm)


def pretty_fmt_yubihsm_object(info: ObjectInfo) -> str:
    domains: set|str = hscfg.HSMConfig.domain_bitfield_to_nums(info.domains)
    domains = "all" if len(domains) == 16 else domains
    return dedent(f"""
    0x{info.id:04x}
        type:           {info.object_type.name} ({info.object_type})
        label:          {repr(info.label)}
        algorithm:      {info.algorithm.name} ({info.algorithm})
        size:           {info.size}
        origin:         {info.origin.name} ({info.origin})
        domains:        {domains}
        capabilities:   {hscfg.HSMConfig.capability_to_names(info.capabilities)}
        delegated_caps: {hscfg.HSMConfig.capability_to_names(info.delegated_capabilities)}
    """).strip()


def try_post_cert_to_http_endpoint_as_form(file_contents: bytes, file_name: str, url: str, headers: dict[str, str], purpose: str = "monitoring"):
    """
    Post a file to an HTTP endpoint, encoded as form data.
    """
    def save_failed():
        try:
            save_name = f"submit-failed__{file_name}"
            cli_warn( f"   => Saving to file './{save_name}', try submitting it manually")
            with open(Path(save_name), 'wb') as f:
                f.write(file_contents)
        except OSError as e:
            cli_error(f" - File write error: {e}")

    submit_ok = False
    try:
        cli_info(f"HTTP POSTing certificate for {purpose}...")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        files = { "file": (file_name, BytesIO(file_contents)) }
        with requests.post(url, files=files, headers=headers, verify=False) as resp:
            status_num, status_txt = resp.status_code, resp.text

        if status_num == 200:
            cli_info(" - OK")
            submit_ok = True
        else:
            cli_error(f" - Submission failed: {status_num} {status_txt}")
    except requests.exceptions.ConnectionError as e:
        cli_error(f" - Connection error: {e}")
    finally:
        if not submit_ok:
            save_failed()


def confirm_and_delete_old_yubihsm_object_if_exists(ses: HSMSession, obj_id: hscfg.HSMKeyID, object_type: OBJECT, abort=True) -> bool:
    """
    Check if a YubiHSM object exists, and if so, ask the user if they want to replace it.
    :param serial: The serial number of the YubiHSM device
    :param hsm_key_obj: The object to check for
    :param abort: Whether to abort (raise) if the user does not want to delete the object
    :return: True if the object doesn't exist or was deleted, False if user chose not to delete it
    """
    if info := ses.object_exists_raw(obj_id, object_type):
        cli_ui_msg(f"Object 0x{obj_id:04x} already exists on YubiHSM device:")
        cli_ui_msg(pretty_fmt_yubihsm_object(info))
        cli_info("")
        if cli_confirm("Replace the existing object?", default=False, abort=abort):
            ses.delete_object_raw(obj_id, object_type)
        else:
            return False
    return True



def secure_display_secret(secret_to_show: str, wipe_char='x'):
    """
    Display a secret on full screen, and then wipe from the screen (and scroll buffer).
    """
    secret = secret_to_show + " "
    def do_it(stdscr):
        from unicurses import getmaxyx, clear, wclear, box, mvwaddstr, wrefresh, delwin, refresh
        clear()

        # Create a new window
        height, width = getmaxyx(stdscr)
        win_height = 3
        win_width = len(secret) + 4
        win = curses.newwin(win_height, win_width, height // 2 - 1, width // 2 - win_width // 2)

        # Display the secret
        box(win)
        mvwaddstr(win, 1, 2, secret)
        wrefresh(win)

        click.pause("") # Wait for ENTER key

        # Overwrite the secret with wipe_char
        wclear(win)
        box(win)
        mvwaddstr(win, 1, 2, wipe_char * len(secret))
        wrefresh(win)

        clear()
        refresh()
        delwin(win)

    curses.wrapper(do_it)
