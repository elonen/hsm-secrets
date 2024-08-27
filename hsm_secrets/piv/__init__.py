from ipaddress import ip_address
import re
import enum
import datetime
from typing_extensions import Literal
import click

from pathlib import Path
from typing import Callable, Union, List, Tuple, BinaryIO, Optional, cast, get_args

from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509

import ykman.device
import ykman.scripting
import ykman
from yubikit.piv import PivSession, SLOT, PIN_POLICY, TOUCH_POLICY
from yubikit.core.smartcard import ApduError, SW
import yubikit.core
import yubikit.piv
from yubikit.hsmauth import HsmAuthSession     # type: ignore [import]

from hsm_secrets.config import HSMConfig, HSMKeyID, HSMOpaqueObject, X509Cert, X509NameType
from hsm_secrets.piv.piv_cert_checks import PIVDomainControllerCertificateChecker, PIVUserCertificateChecker
from hsm_secrets.utils import HsmSecretsCtx, cli_info, cli_warn, open_hsm_session, pass_common_args
from hsm_secrets.x509.cert_builder import X509CertBuilder
from hsm_secrets.x509.def_utils import find_cert_def, merge_x509_info_with_defaults
from hsm_secrets.yubihsm import HSMSession


@click.group()
@click.pass_context
def cmd_piv(ctx: click.Context):
    """PIV commands (Yubikey Windows login)"""
    ctx.ensure_object(dict)


class PivKeyType(enum.Enum):
    RSA2048 = "rsa2048"
    ECP256 = "ecp256"
    ECP384 = "ecp384"


@cmd_piv.command('user-cert')
@pass_common_args
@click.option('--user', '-u', required=True, help="User identifier (username for Windows, email for macOS/Linux)")
@click.option('--template', '-t', required=False, help="Template label, default: first template")
@click.option('--subject', '-s', required=False, help="Cert subject (DN), default: from config")
@click.option('--validity', '-v', type=int, help="Validity period in days, default: from config")
@click.option('--key-type', '-k', type=click.Choice(['RSA2048', 'ECP256', 'ECP384']), default='ECP384', help="Key type, default: same as CA")
@click.option('--csr', type=click.Path(exists=True, dir_okay=False, resolve_path=True), help="Path to existing CSR file")
@click.option('--ca', '-c', required=False, help="CA ID (hex) or label, default: from config")
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=False), help="Output filename stem, default: ./<user>-piv[.key/.cer]")
@click.option('--os-type', type=click.Choice(['windows', 'other']), default='windows', help="Target operating system")
@click.option('--san', multiple=True, help="AdditionalSANs, e.g., 'DNS:example.com', 'IP:10.0.0.2', etc.")
def create_piv_cert(ctx: HsmSecretsCtx, user: str, template: str|None, subject: str, validity: int, key_type: Literal['RSA2048', 'ECP256', 'ECP384'], csr: str|None, ca: str, out: str, os_type: Literal["windows", "other"], san: List[str]):
    """Create or sign a PIV user certificate

    If a CSR is provided, sign it with a CA certificate.
    Otherwise generate a new key pair and signs a certificate for it.

    Example SAN types:
    - RFC822:alice@example.com
    - UPN:alice@example.com
    - DIRECTORY:/C=US/O=Example/CN=example.com
    - OID:1.2.3.4.5=myValue
    """
    # Set up default output filenames
    out = out or f"{_sanitize_username(user)}-piv"
    key_file = Path(out).with_suffix('.key.pem')
    csr_file = Path(out).with_suffix('.csr.pem')
    cer_file = Path(out).with_suffix('.cer.pem')

    # Get template
    if template:
        if template not in ctx.conf.piv.user_cert_templates:
            raise click.ClickException(f"Template '{template}' not found in configuration")
        cert_template = ctx.conf.piv.user_cert_templates[template]
    else:
        # Use first template if not specified
        cert_template = next(iter(ctx.conf.piv.user_cert_templates.values()))
        assert cert_template, "No user certificate templates found in configuration"

    # Merge template with defaults
    x509_info = merge_x509_info_with_defaults(cert_template, ctx.conf)
    assert x509_info, "No user certificate templates found in configuration"
    assert x509_info.attribs, "No user certificate attributes found in configuration"

    # Override template values with command-line options
    if validity:
        x509_info.validity_days = validity

    # Generate subject DN if not explicitly provided
    if not subject:
        subject = f"CN={user}"
        if x509_info.attribs:
            for k,v in {
                'O': x509_info.attribs.organization,
                'L': x509_info.attribs.locality,
                'ST': x509_info.attribs.state,
                'C': x509_info.attribs.country,
            }.items():
                if v:
                    subject += f",{k}={v}"

    # Handle CSR or key generation
    if csr:
        with open(csr, 'rb') as f:
            csr_obj = x509.load_pem_x509_csr(f.read())
        private_key = None
    else:
        _, private_key = _generate_piv_key_pair(PivKeyType[key_type])
        csr_obj = None

    # Add explicitly provided SANs
    x509_info.subject_alt_name = x509_info.subject_alt_name or x509_info.SubjectAltName()
    valid_san_types = get_args(X509NameType)
    for san_entry in san:
        try:
            san_type, san_value = san_entry.split(':', 1)
        except ValueError:
            raise click.ClickException(f"Invalid SAN: '{san_entry}'. Must be in the form 'type:value', where type is one of: {', '.join(valid_san_types)}")
        san_type_lower = san_type.lower()
        if san_type_lower not in valid_san_types:
            raise click.ClickException(f"Provided '{san_type.lower()}' is not a supported X509NameType. Must be one of: {', '.join(valid_san_types)}")
        x509_info.subject_alt_name.names.setdefault(san_type_lower, []).append(san_value)    # type: ignore [arg-type]

    # Add UPN or email to SANs based on OS type
    if os_type == 'windows':
        x509_info.subject_alt_name.names.setdefault('upn', []).append(user)
    else:
        x509_info.subject_alt_name.names.setdefault('rfc822', []).append(user)

    # Create X509CertBuilder
    key_or_csr = private_key or csr_obj
    assert key_or_csr
    cert_builder = X509CertBuilder(ctx.conf, x509_info, key_or_csr, dn_subject_override=subject)

    # Sign the certificate with CA
    ca_id = ca or ctx.conf.piv.default_ca_id
    issuer_cert_def = ctx.conf.find_def(ca_id, HSMOpaqueObject)

    with open_hsm_session(ctx) as ses:
        issuer_x509_def = find_cert_def(ctx.conf, issuer_cert_def.id)
        assert issuer_x509_def, f"CA cert ID not found: 0x{issuer_cert_def.id:04x}"
        issuer_cert = ses.get_certificate(issuer_cert_def)
        issuer_key = ses.get_private_key(issuer_x509_def.key)
        signed_cert = cert_builder.build_and_sign(issuer_cert, issuer_key)

    PIVUserCertificateChecker(signed_cert, os_type).check_and_show_issues()

   # Save files
    if private_key:
        key_file.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        cli_info(f"Private key saved to: {key_file}")

        csr_obj = cert_builder.generate_csr()
        csr_file.write_bytes(csr_obj.public_bytes(serialization.Encoding.PEM))
        cli_info(f"CSR saved to: {csr_file}")
    elif csr:
        cli_info(f"Using provided CSR: {csr}")

    _save_pem_certificate(signed_cert, cer_file.open('wb'))
    cli_info(f"Certificate saved to: {cer_file}")



@cmd_piv.command('sign-dc-cert')
@pass_common_args
@click.argument('csr', required=True, type=click.File(), default=click.get_text_stream('stdin'))
@click.option('--validity', '-v', type=int, help="Validity period in days, default: from config")
@click.option('--ca', '-c', required=False, help="CA ID (hex) or label, default: from config")
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=False), help="Output filename, default: deduced from input")
@click.option('--san', multiple=True, help="Additional (GeneralName) SANs")
@click.option('--hostname', '-h', required=True, help="Hostname (CommonName) for the DC certificate")
@click.option('--template', '-t', required=False, help="Template label, default: first template")
def sign_dc_cert(ctx: HsmSecretsCtx, csr: click.File, validity: int, ca: str, out: str|None, san: List[str], hostname: str, template: str|None):
    """Sign a DC Kerberos PKINIT certificate for PIV"""
    csr_path = Path(csr.name)
    with csr_path.open('rb') as f:
        csr_obj: x509.CertificateSigningRequest = x509.load_pem_x509_csr(f.read())

    out_path: Path = Path(out) if out else csr_path.with_suffix('.cer.pem')

    # Get CA (issuer)
    ca_id = ca or ctx.conf.piv.default_ca_id
    issuer_cert_def = ctx.conf.find_def(ca_id, HSMOpaqueObject)
    issuer_x509_def = find_cert_def(ctx.conf, issuer_cert_def.id)
    assert issuer_x509_def, f"CA cert ID not found: 0x{issuer_cert_def.id:04x}"

    # Get template
    if template:
        if template not in ctx.conf.piv.dc_cert_templates:
            raise click.ClickException(f"Template '{template}' not found in configuration")
        cert_template = ctx.conf.piv.dc_cert_templates[template]
    else:
        # Use first template if not specified
        cert_template = next(iter(ctx.conf.piv.dc_cert_templates.values()))
        assert cert_template, "No DC certificate templates found in configuration"

    # Merge cert template with global defaults
    x509_info = merge_x509_info_with_defaults(cert_template, ctx.conf)
    assert x509_info.attribs, "No user certificate attributes found in configuration"
    if validity:
        x509_info.validity_days = validity

    x509_info.attribs.common_name = hostname     # Override CN

    # Add explicitly provided SANs
    x509_info.subject_alt_name = x509_info.subject_alt_name or x509_info.SubjectAltName()
    for san_entry in san:
        san_type, san_value = san_entry.split(':', 1)
        san_type_lower = san_type.lower()
        if san_type_lower not in get_args(X509NameType):
            raise click.ClickException(f"Provided '{san_type.lower()}' is not a supported X509NameType")
        x509_info.subject_alt_name.names.setdefault(san_type_lower, []).append(san_value)  # type: ignore [arg-type]

    # Add hostname to DNS SANs if not already there
    if hostname not in (x509_info.subject_alt_name.names['dns'] or []):
        x509_info.subject_alt_name.names['dns'] = [hostname] + list(x509_info.subject_alt_name.names['dns'] or [])

    # Create X509CertBuilder
    cert_builder = X509CertBuilder(ctx.conf, x509_info, csr_obj)

    # Sign the certificate
    with open_hsm_session(ctx) as ses:
        issuer_cert = ses.get_certificate(issuer_cert_def)
        issuer_key = ses.get_private_key(issuer_x509_def.key)
        signed_cert = cert_builder.build_and_sign(issuer_cert, issuer_key)

    PIVDomainControllerCertificateChecker(signed_cert).check_and_show_issues()

    # Save the signed certificate
    _save_pem_certificate(signed_cert, out_path.open('wb'))
    cli_info(f"Signed certificate saved to: {out_path}")



@cmd_piv.command('yubikey-import')
@click.argument('cert', required=True, type=click.Path(exists=True, dir_okay=False, resolve_path=True, allow_dash=False))
@click.argument('key', required=True, type=click.Path(exists=True, dir_okay=False, resolve_path=True, allow_dash=False))
@click.option('--slot', '-s', type=click.Choice(['AUTHENTICATION', 'SIGNATURE', 'KEY_MANAGEMENT', 'CARD_AUTH']), default='AUTHENTICATION', help="PIV slot to import to")
@click.option('--management-key', '-m', help="PIV management key (hex), default: prompt")
def import_to_yubikey_piv_cmd(cert: click.Path, key: click.Path, slot: str, management_key: str|None):
    """Import a certificate and private key to a YubiKey PIV slot"""
    # Load certificate and private key
    cert_path = Path(str(cert))
    key_path = Path(str(key))

    with cert_path.open('rb') as f:
        cert_data = f.read()
        certificate = x509.load_pem_x509_certificate(cert_data)

    with key_path.open('rb') as f:
        key_data = f.read()
        private_key = serialization.load_pem_private_key(key_data, password=None)
        if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise click.ClickException("Unsupported private key type. Only RSA and EC keys are supported for YubiKey PIV.")

    cli_info("PEM files loaded:")
    cli_info(f"- certificate: {cert_path}")
    cli_info(f"- private key: {key_path}")

    # Convert slot string to SLOT enum
    from yubikit.piv import SLOT
    slot_enum = getattr(SLOT, slot)

    _import_to_yubikey_piv(
        cert=certificate,
        private_key=private_key,
        slot=slot_enum,
        management_key=bytes.fromhex(management_key) if management_key else None
    )



def _generate_piv_key_pair(key_type: PivKeyType) -> Tuple[Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey], Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]]:
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    if key_type == PivKeyType.RSA2048:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == PivKeyType.ECP256:
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif key_type == PivKeyType.ECP384:
        private_key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    public_key = private_key.public_key()
    return public_key, private_key


def _save_pem_certificate(cert: x509.Certificate, output_file: BinaryIO) -> None:
    pem_data = cert.public_bytes(encoding=serialization.Encoding.PEM)
    output_file.write(pem_data)

def _sanitize_username(user: str) -> str:
    user = re.sub(r'@.*', '', user)         # Remove anything after '@'
    user = re.sub(r'[^\w]', '_', user)      # Replace special characters with underscores
    return user or "user"


def _import_to_yubikey_piv(
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
    def _import_op(piv: PivSession, slot: SLOT):
        # Check for biometric support
        bio_supported = True
        try:
            piv.get_bio_metadata()
        except yubikit.core.NotSupportedError:
            bio_supported = False

        # Import key if provided
        if private_key:
            cli_info(f"Importing private key to slot '{slot.name}' ({slot.value:02x})")
            cli_info("- Setting touch requirement 'CACHED': needed if last touched over 15 seconds ago. Touch is a non-standard PIV extension.")
            if bio_supported:
                cli_info("- Biometric support detected. Enabling MATCH_ONCE for PIN policy.")
                piv.put_key(slot, private_key, pin_policy=PIN_POLICY.MATCH_ONCE, touch_policy=TOUCH_POLICY.CACHED)
            else:
                cli_info("- Setting PIN policy to 'ONCE': PIN is needed once per session.")
                piv.put_key(slot, private_key, pin_policy=PIN_POLICY.ONCE, touch_policy=TOUCH_POLICY.CACHED)
        else:
            md = piv.get_slot_metadata(slot)
            if not md.public_key_encoded:
                raise click.ClickException(f"Slot '{slot.name}' has not key pair, cannot import certificate without key")

        # Import certificate
        piv.put_certificate(slot, cert, compress=True)
        cli_info("OK")

    _yubikey_piv_operation(slot, _import_op, management_key)



def _yubikey_piv_operation(slot: SLOT, op_func: Callable[[PivSession, SLOT], None], management_key: Optional[bytes] = None):
    try:
        hsm_yubikey, piv_yubikey = _scan_for_hsm_and_piv_yubikeys()
        piv_yubikey = piv_yubikey or hsm_yubikey
        if not piv_yubikey:
            raise click.ClickException("No YubiKey found storing PIV credentials")

        if hsm_yubikey and piv_yubikey != hsm_yubikey:
            cli_warn(f"Found YubiKey with HSM credentials: {hsm_yubikey} - skipping it for PIV operation.")
        cli_info(f"Performing PIV operation on device: {str(piv_yubikey)}")
        piv = PivSession(piv_yubikey.smart_card())

        _yubikey_auth_with_piv_mgm_key(piv, management_key)
        op_func(piv, slot)

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


def _scan_for_hsm_and_piv_yubikeys() -> Tuple[Optional[ykman.scripting.ScriptingDevice], Optional[ykman.scripting.ScriptingDevice]]:
    """
    Scan for YubiKeys for a) HSM auth and b) PIV import.

    If there are multiple YubiKeys, select the one without HSM support for PIV import.
    If there's only one, return it for both HSM and PIV.

    :return: Tuple of (device for HSM, device for PIV)
    """
    hsm_yubikey, piv_yubikey = None, None
    for yk_dev, yk_info in ykman.device.list_all_devices():
        yk = ykman.scripting.ScriptingDevice(yk_dev, yk_info)
        sc = yk.smart_card()
        try:
            if HsmAuthSession(connection=sc).list_credentials():
                sc.close()
                if hsm_yubikey:
                    raise click.ClickException("ERROR: Multiple YubiKeys found with HSM credentials. Heuristic is to pick the one without HSM credentials for PIV import, but this is ambiguous in this case.")
                hsm_yubikey = yk
                continue
        except yubikit.core.NotSupportedError:
            pass
        sc.close()
        if piv_yubikey:
            raise click.ClickException("ERROR: Multiple YubiKeys found without HSM auth. Can't decide which one to use for PIV import.")
        piv_yubikey = yk
        if hsm_yubikey:
            break
    return hsm_yubikey, piv_yubikey


def _yubikey_auth_with_piv_mgm_key(piv: PivSession, management_key: Optional[bytes]) -> None:
    """
    Authenticate with PIV management key.
    :param piv: The PIV session to authenticate
    :param management_key: The management key for the YubiKey PIV application
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
