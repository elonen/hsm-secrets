from typing import Callable, TypeVar, Union, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from yubikit.piv import PivSession, SLOT, KEY_TYPE, PIN_POLICY, TOUCH_POLICY, MANAGEMENT_KEY_TYPE, OBJECT_ID
from yubikit.core.smartcard import ApduError, SW
import yubikit.core
import yubikit.piv
import ykman.piv, ykman.scripting

from hsm_secrets.utils import HsmSecretsCtx, cli_code_info, cli_confirm, cli_debug, cli_error, cli_info, cli_ui_msg, cli_warn, prompt_for_secret, scan_local_yubikeys

import click


def import_to_yubikey_piv(
    piv: PivSession,
    cert: x509.Certificate,
    private_key: Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]],
    touch_policy: TOUCH_POLICY,
    slot: SLOT = SLOT.AUTHENTICATION,
) -> None:
    """
    Import the certificate and private key into a Yubikey PIV slot.

    :param cert: The X.509 certificate to import
    :param private_key: The private key corresponding to the certificate
    :param slot: The PIV slot to use (default: Authentication slot)
    :param management_key: The management key for the Yubikey PIV application (if None, will prompt)
    """
    cli_info(f"Importing certificate to slot '{slot.name.lower()}' ({slot.value:02x})...")
    piv.put_certificate(slot, cert)
    cli_info(" - Certificate imported")

    if private_key:
        cli_info(f"Importing private key to slot '{slot.name.lower()}' ({slot.value:02x})...")
        cli_info(" - Setting touch requirement 'CACHED'. Touch is a non-standard Yubico PIV extension.")
        if _check_yubikey_bio_support(piv):
            cli_info(" - Biometric support detected. Enabling MATCH_ONCE for PIN policy.")
            piv.put_key(slot, private_key, pin_policy=PIN_POLICY.MATCH_ONCE, touch_policy=touch_policy)
        else:
            cli_info(" - Setting PIN policy to 'ONCE': PIN is needed once per session.")
            piv.put_key(slot, private_key, pin_policy=PIN_POLICY.ONCE, touch_policy=touch_policy)

        cli_info(f" - Key imported.")
    else:
        try:
            md = piv.get_slot_metadata(slot)
            if not md.public_key_encoded:
                raise click.ClickException(f"Slot '{slot.name}' has no key pair, cannot import certificate without key")
        except yubikit.core.NotSupportedError:
            pass  # If firmware doesn't support slot metadata,just skip the check


def confirm_and_reset_yubikey_piv_app(ctx: HsmSecretsCtx, piv_yubikey: ykman.scripting.ScriptingDevice|None = None) -> None:
    """
    Reset a Yubikey PIV slot to its default state.
    """
    if not piv_yubikey:
        _, piv_yubikey = scan_local_yubikeys(require_one_hsmauth=False, require_one_other=True, hsmauth_yk_serial=ctx.forced_yubikey_serial)
        if not piv_yubikey:
            raise click.ClickException("No YubiKey PIV devices found.")

    cli_confirm(f"WIPE previous PIV key/cert from YubiKey '{str(piv_yubikey.name)} serial {str(piv_yubikey.info.serial)}'?", abort=True)

    sc = piv_yubikey.smart_card()
    piv = PivSession(sc)
    cli_info("Resetting YubiKey PIV app...")
    piv.reset()
    cli_info(" - Re-authing with default Management Key")
    piv.authenticate(yubikit.piv.DEFAULT_MANAGEMENT_KEY)
    cli_info(" - Generating new CHUID (Card Holder Unique Identifier)")
    piv.put_object(OBJECT_ID.CHUID, ykman.piv.generate_chuid())
    cli_info(" - Generating new CCC (Card Capability Container)")
    piv.put_object(OBJECT_ID.CAPABILITY, ykman.piv.generate_ccc())
    sc.close()


def set_yubikey_piv_pin_puk_management_key(
    piv: PivSession,
    pin: str,
    puk: str,
    pin_puk_attempts: int,
    new_management_key: bytes) -> str:
    """
    Set the PIN, PUK, and management key for a Yubikey PIV application.
    """
    cli_info("Changing PIN, PUK, and Management Key for YubiKey PIV app...")
    #assert len(new_management_key) == 16, "Management key must be 16 bytes (for AES128)"
    #cli_info(f" - Reseting PIN and PUK to defaults, with max {pin_puk_attempts} attempts")
    piv.set_pin_attempts(pin_puk_attempts, pin_puk_attempts)    # This also resets the PIN and PUK to defaults
    #cli_info(" - Setting new PIN")
    piv.change_pin(YUBIKEY_DEFAULT_PIN, pin)
    #cli_info(" - Setting new PUK")
    piv.change_puk(YUBIKEY_DEFAULT_PUK, puk)
    piv.verify_pin(pin)

    if len(new_management_key) == 16:
        ykman.piv.pivman_set_mgm_key(piv, new_management_key, MANAGEMENT_KEY_TYPE.AES128)
        return "AES128"
    elif len(new_management_key) == 24:
        # Try AES192 first, fallback to TDES if not supported
        try:
            ykman.piv.pivman_set_mgm_key(piv, new_management_key, MANAGEMENT_KEY_TYPE.AES192)
            return "AES192"
        except Exception as e:
            cli_warn(f"Failed to set AES192 management key: {str(e)}")
            cli_info(" - Retrying management key type as TDES")
            ykman.piv.pivman_set_mgm_key(piv, new_management_key, MANAGEMENT_KEY_TYPE.TDES)
            return "3DES"
    elif len(new_management_key) == 32:
        ykman.piv.pivman_set_mgm_key(piv, new_management_key, MANAGEMENT_KEY_TYPE.AES256)
        return "AES256"
    else:
        raise click.ClickException("Invalid management key length (must be 16, 24, or 32 bytes)")


def generate_yubikey_piv_keypair(
    piv: PivSession,
    key_type: KEY_TYPE,
    pin_policy: PIN_POLICY,
    touch_policy: TOUCH_POLICY,
    subject: str,
    slot: SLOT = SLOT.AUTHENTICATION
) -> x509.CertificateSigningRequest:
    """
    Generate a new key pair on a Yubikey PIV slot.

    :param slot: The PIV slot to use (default: Authentication slot)
    :param management_key: The management key for the Yubikey PIV application (if None, will prompt)
    """
    cli_info(f"Generating {key_type} key pair on device, slot '{slot.name.lower()}' ({slot.value:02x})...")
    public_key = piv.generate_key(slot, key_type, pin_policy, touch_policy)
    cli_info("Creating certificate request (CSR) on YubiKey... " + click.style("(Touch it now if it blinks)", fg='blue', blink=True))

    # Ensure public_key is a supported type for generate_csr
    if not isinstance(public_key, (RSAPublicKey, EllipticCurvePublicKey)):
        raise ValueError(f"Unsupported key type for CSR generation: {type(public_key)}")

    hash_algo: type[hashes.SHA384]|type[hashes.SHA256] = hashes.SHA384 if key_type == KEY_TYPE.ECCP384 else hashes.SHA256
    return ykman.piv.generate_csr(piv, slot, public_key, subject, hash_algo)



YUBIKEY_DEFAULT_PIN = "123456"
YUBIKEY_DEFAULT_PUK = "12345678"
YUBIKEY_DEFAULT_MGMT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")

class YubikeyPivManagementSession:
    """
    Context manager for YubiKey PIV management operations.
    """
    def __init__(self, management_key: Optional[bytes] = None, pin: Optional[str] = None, hsm_auth_yk_serial: Optional[str] = None):
        self.management_key = management_key
        self.pin = pin
        self.sc = None
        self.hsmauth_yk_serial = hsm_auth_yk_serial

    def __enter__(self):
        """
        Create PIV session and authenticate with PIV management key + PIN.
        Returns self to allow access to piv, management_key, and pin.
        """
        cli_debug("[PIV] YubikeyPivManagementSession.__enter__: Starting PIV session")
        _, piv_yubikey = scan_local_yubikeys(require_one_hsmauth=False, require_one_other=True, hsmauth_yk_serial=self.hsmauth_yk_serial)
        assert piv_yubikey
        cli_info(f"Device for PIV storage: '{str(piv_yubikey)}'")

        self.sc = piv_yubikey.smart_card()
        cli_debug(f"[PIV] Opened smartcard connection for PIV YubiKey {getattr(piv_yubikey, 'serial', 'unknown')}")
        self.piv = PivSession(self.sc)

        # Verify PIN first
        if self.pin is None:
            self.pin = prompt_for_secret("Enter current YubiKey PIV PIN", default=YUBIKEY_DEFAULT_PIN)
        self.piv.verify_pin(self.pin)

        # Authenticate with management key
        key = self._select_management_key_smart(self.piv)
        try:
            self.management_key = key  # Store the management key used
            self.piv.authenticate(key)
        except yubikit.core.CommandError as e:
            cli_error(f"YubiKey PIV app mgt key authentication failed: {str(e)}")
            cli_warn("(Sometimes this means 'PUK is blocked' in YubiKey GUI. You may need to factory reset the PIV app.)")

        return self  # Return self so that piv, management_key, and pin can be accessed

    def _select_management_key_smart(self, piv: PivSession) -> bytes:
        # Use provided management key if available
        if self.management_key is not None:
            return self.management_key
        try:
            # Check if default management key is set
            mkm = piv.get_management_key_metadata()
            if mkm.default_value:
                return yubikit.piv.DEFAULT_MANAGEMENT_KEY
            else:
                # Not default, prompt user
                return self._prompt_for_management_key()
        except yubikit.core.NotSupportedError:
            # Couldn't figure out if it's default or not, prompt user
            return self._prompt_for_management_key(default=yubikit.piv.DEFAULT_MANAGEMENT_KEY)

    def _prompt_for_management_key(self, default: Optional[bytes] = None) -> bytes:
        """
        Prompt user for a PIV management key.
        """
        while True:
            mkey_str = prompt_for_secret("Enter PIV management key (in hex)", default=default.hex() if default else None)
            try:
                mkey = bytes.fromhex(mkey_str)
                if len(mkey) not in (16, 24, 32):
                    cli_error("Management key must be 16, 24, or 32 bytes (32, 48 or 64 hex digits) -- AES128, TDES, or AES256.")
                    continue
                return mkey
            except ValueError:
                cli_error("Invalid hex string. Try again.")

    def __exit__(self, exc_type, exc_val, exc_tb):
        cli_debug(f"[PIV] YubikeyPivManagementSession.__exit__: Closing PIV session (exc_type={exc_type})")
        if self.sc:
            self.sc.close()
            cli_debug("[PIV] Closed smartcard connection for PIV YubiKey")

        if isinstance(exc_val, ApduError):
            if exc_val.sw == SW.AUTH_METHOD_BLOCKED:
                cli_error("YubiKey error: PIN is blocked" + f"\n({str(exc_val)})")
            elif exc_val.sw == SW.INCORRECT_PARAMETERS:
                cli_error("YubiKey error: Incorrect PIN or management key" + f"\n({str(exc_val)})")
            elif exc_val.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                cli_error("YubiKey error: Security condition not satisfied." + f"\n({str(exc_val)})")
            elif exc_val.sw == SW.COMMAND_NOT_ALLOWED:
                cli_error("YubiKey error: Command not allowed. The YubiKey may be in a state that doesn't allow this operation." + f"\n({str(exc_val)})")
            else:
                cli_error(f"YubiKey error: {str(exc_val)}")
            raise click.ClickException("Failed to perform PIV operation")
        elif exc_val:
            cli_error(f"Error: {str(exc_val)}")
            raise click.ClickException("Failed to perform PIV operation")
        return True



def _check_yubikey_bio_support(piv: PivSession) -> bool:
    try:
        piv.get_bio_metadata()
        return True
    except yubikit.core.NotSupportedError:
        return False
