from typing import Callable, TypeVar, Union, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509

from yubikit.piv import PivSession, SLOT, PIN_POLICY, TOUCH_POLICY
from yubikit.core.smartcard import ApduError, SW
import yubikit.core
import yubikit.piv

from hsm_secrets.utils import cli_info, cli_warn, scan_local_yubikeys

import click


def import_to_yubikey_piv(
    cert: x509.Certificate,
    private_key: Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]],
    slot: SLOT = SLOT.AUTHENTICATION,
    management_key: Optional[bytes] = None
) -> None:
    """
    Import the certificate and private key into a Yubikey PIV slot.

    :param cert: The X.509 certificate to import
    :param private_key: The private key corresponding to the certificate
    :param slot: The PIV slot to use (default: Authentication slot)
    :param management_key: The management key for the Yubikey PIV application (if None, will prompt)
    """
    def _import_key_cert_op(piv: PivSession, slot: SLOT):
        if private_key:
            cli_info(f"Importing private key to slot '{slot.name.lower()}' ({slot.value:02x})...")
            cli_info(" - Setting touch requirement 'CACHED'. Touch is a non-standard Yubico PIV extension.")
            if _check_yubikey_bio_support(piv):
                cli_info(" - Biometric support detected. Enabling MATCH_ONCE for PIN policy.")
                piv.put_key(slot, private_key, pin_policy=PIN_POLICY.MATCH_ONCE, touch_policy=TOUCH_POLICY.CACHED)
            else:
                cli_info(" - Setting PIN policy to 'ONCE': PIN is needed once per session.")
                piv.put_key(slot, private_key, pin_policy=PIN_POLICY.ONCE, touch_policy=TOUCH_POLICY.CACHED)
        else:
            md = piv.get_slot_metadata(slot)
            if not md.public_key_encoded:
                raise click.ClickException(f"Slot '{slot.name}' has not key pair, cannot import certificate without key")

        # Import certificate
        piv.put_certificate(slot, cert, compress=True)
        cli_info("OK")

    _yubikey_piv_operation(slot, _import_key_cert_op, management_key)


'''
# TODO: This would be slightly more secure than generating a RAM-stored key on the Python side and importing,
# but it's not a huge difference. It's feasible but would require writing KeyAdapter classes for YubiKey-stored RSA/ECC keys,
# to make CSRs for the HSM-backed CA to sign.

def _generate_on_yubikey_piv(slot: SLOT, key_type: yubikit.piv.KEY_TYPE, management_key: Optional[bytes] = None) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
    """
    Generate a key pair on YubiKey, returning the public key.
    """
    def _generate_keypair_op(piv: PivSession, slot: SLOT) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
        bio_supported = _check_yubikey_bio_support(piv)
        pin_policy = PIN_POLICY.MATCH_ONCE if bio_supported else PIN_POLICY.ONCE
        cli_info(f"Generating {key_type.name} key pair in slot '{slot.name}' ({slot.value:02x})")
        cli_info("- Setting touch requirement 'CACHED': needed if last touched over 15 seconds ago.")
        cli_info(f"- Setting PIN policy to '{pin_policy.name}'")
        return piv.generate_key(slot, key_type, pin_policy=pin_policy, touch_policy=TOUCH_POLICY.CACHED)
    return _yubikey_piv_operation(slot, _generate_keypair_op, management_key)
'''

T = TypeVar('T')
def _yubikey_piv_operation(slot: SLOT, op_func: Callable[[PivSession, SLOT], T], management_key: Optional[bytes] = None) -> T:
    try:
        _, piv_yubikey = scan_local_yubikeys(require_one_hsmauth=False, require_one_other=True)
        assert piv_yubikey

        cli_info(f"Device for PIV storage: '{str(piv_yubikey)}'")
        piv = PivSession(piv_yubikey.smart_card())

        _yubikey_auth_with_piv_mgm_key(piv, management_key)
        return op_func(piv, slot)

    except ApduError as e:
        if e.sw == SW.AUTH_METHOD_BLOCKED:
            click.echo("Error: PIN is blocked")
        elif e.sw == SW.INCORRECT_PARAMETERS:
            click.echo("Error: Incorrect PIN or management key")
        elif e.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
            click.echo("Error: Security condition not satisfied. Ensure you have the correct permissions.")
        elif e.sw == SW.COMMAND_NOT_ALLOWED:
            click.echo("Error: Command not allowed. The YubiKey may be in a state that doesn't allow this operation.")
        else:
            click.echo(f"Error: {str(e)}")
    except Exception as e:
        click.echo(f"Error: {str(e)}")
    raise click.ClickException("Failed to perform PIV operation")


def _check_yubikey_bio_support(piv: PivSession) -> bool:
    try:
        piv.get_bio_metadata()
        return True
    except yubikit.core.NotSupportedError:
        return False


def _yubikey_auth_with_piv_mgm_key(piv: PivSession, management_key: Optional[bytes]) -> None:
    """
    Authenticate with PIV management key.
    :param piv: The PIV session to authenticate
    :param management_key: The management key for the YubiKey PIV application. If None, will use default key or prompt user.
    """
    mkm = piv.get_management_key_metadata()
    if management_key is None:
        if mkm.default_value:
            cli_warn("WARNING! Using default management key. Change it immediately after import!")
            management_key = yubikit.piv.DEFAULT_MANAGEMENT_KEY
        else:
            mkey_str = click.prompt("Enter PIV management key (hex)", hide_input=True)
            if mkey_str is None:
                raise click.ClickException("Management key is required")
            management_key = bytes.fromhex(mkey_str)
    piv.authenticate(mkm.key_type, management_key)
