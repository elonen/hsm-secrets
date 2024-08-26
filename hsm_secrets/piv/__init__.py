from ipaddress import ip_address
import re
import enum
import datetime
from typing_extensions import Literal
import click

from pathlib import Path
from typing import Union, List, Tuple, BinaryIO, Optional, cast, get_args

from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509

import ykman.device
import ykman.scripting
import ykman
from yubikit.piv import PivSession, SLOT, PIN_POLICY, TOUCH_POLICY
from yubikit.core.smartcard import ApduError, SW

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


def import_to_yubikey_piv(
    cert: x509.Certificate,
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    slot: SLOT = SLOT.AUTHENTICATION,
    pin: Optional[str] = None,
    management_key: Optional[bytes] = None
) -> None:
    """
    Import the certificate and private key into a Yubikey PIV slot.

    :param cert: The X.509 certificate to import
    :param private_key: The private key corresponding to the certificate
    :param slot: The PIV slot to use (default: Authentication slot)
    :param pin: The PIN for the Yubikey PIV application (if None, will prompt)
    :param management_key: The management key for the Yubikey PIV application (if None, will prompt)
    """
    try:
        yubikey = ykman.scripting.single()    # Connect to the first Yubikey found, prompt user to insert one if not found
        sc = yubikey.smart_card()
        piv = PivSession(sc)

        if pin is None:
            pin = click.prompt("Enter PIN", hide_input=True)
            if pin is None:
                raise click.ClickException("PIN is required")
        piv.verify_pin(pin)

        if management_key is None:
            mkey_str = click.prompt("Enter management key (hex)", hide_input=True)
            if mkey_str is None:
                raise click.ClickException("Management key is required")
            management_key = bytes.fromhex(mkey_str)
        mkm = piv.get_management_key_metadata()
        piv.authenticate(mkm.key_type, management_key)

        cli_info(f"Importing private key to slot {slot.name}.")
        cli_warn("Setting touch_policy=CACHED. Touch is not in PIV standard, so if this doesn't work, maybe try touch_policy=NEVER.")
        piv.put_key(slot, private_key, pin_policy=PIN_POLICY.MATCH_ONCE, touch_policy=TOUCH_POLICY.CACHED)

        # Import certificate
        piv.put_certificate(slot, cert, compress=True)

        click.echo(f"OK. Certificate and private key imported to YubiKey slot '{slot.name}' (0x{slot.value:x}).")

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



@cmd_piv.command('user-cert')
@pass_common_args
@click.option('--user', '-u', required=True, help="User identifier (username for Windows, email for macOS/Linux)")
@click.option('--template', '-t', required=False, help="Template label, default: first template")
@click.option('--subject', '-s', required=False, help="Cert subject (DN), default: from config")
@click.option('--validity', '-v', type=int, help="Validity period in days, default: from config")
@click.option('--key-type', '-k', type=click.Choice(['RSA2048', 'ECP256', 'ECP384']), default='RSA2048', help="Key type, default: same as CA")
@click.option('--ca', '-c', required=False, help="CA ID (hex) or label, default: from config")
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=False), help="Output filename stem, default: ./<user>-piv[.key/.cer]")
@click.option('--os-type', type=click.Choice(['windows', 'other']), default='windows', help="Target operating system")
@click.option('--san', multiple=True, help="AdditionalSANs, e.g., 'DNS:example.com', 'IP:10.0.0.2', etc.")
def create_piv_cert(ctx: HsmSecretsCtx, user: str, template: str|None, subject: str, validity: int, key_type: str, ca: str, out: str, os_type: Literal["windows", "other"], san: List[str]):
    """Create a PIV user certificate

    This command generates a new PIV user certificate and key pair, and signs it with a CA certificate.

    Example SAN types:
    - RFC822:alice@example.com
    - UPN:alice@example.com
    - DIRECTORY:/C=US/O=Example/CN=example.com
    - OID:1.2.3.4.5=myValue
    """
    # Set up default output filenames
    if not out:
        out = f"{user}-piv"
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

    # Generate key pair
    key_type_enum = PivKeyType[key_type]
    _public_key, private_key = _generate_piv_key_pair(key_type_enum)

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
    cert_builder = X509CertBuilder(ctx.conf, x509_info, private_key, dn_subject_override=subject)

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
    key_file.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

    csr = cert_builder.generate_csr()
    csr_file.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    _save_pem_certificate(signed_cert, cer_file.open('wb'))

    cli_info(f"Private key saved to: {key_file}")
    cli_info(f"CSR saved to: {csr_file}")
    cli_info(f"Certificate saved to: {cer_file}")



@cmd_piv.command('sign-dc-cert')
@pass_common_args
@click.argument('csr', required=True, type=click.File(), default=click.get_text_stream('stdin'))
@click.option('--validity', '-v', type=int, help="Validity period in days, default: from config")
@click.option('--ca', '-c', required=False, help="CA ID (hex) or label, default: from config")
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=False), help="Output filename, default: deduced from input")
@click.option('--san', multiple=True, help="Additional (GeneralName) SANs")
@click.option('--template', '-t', required=False, help="Template label, default: first template")
def sign_dc_cert(ctx: HsmSecretsCtx, csr: click.File, validity: int, ca: str, out: str|None, san: List[str], template: str|None):
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

    # Add explicitly provided SANs
    x509_info.subject_alt_name = x509_info.subject_alt_name or x509_info.SubjectAltName()
    for san_entry in san:
        san_type, san_value = san_entry.split(':', 1)
        san_type_lower = san_type.lower()
        if san_type_lower not in get_args(X509NameType):
            raise click.ClickException(f"Provided '{san_type.lower()}' is not a supported X509NameType")
        x509_info.subject_alt_name.names.setdefault(san_type_lower, []).append(san_value)  # type: ignore [arg-type]

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
@click.option('--pin', '-p', help="PIV PIN, default: prompt")
@click.option('--management-key', '-m', help="PIV management key (hex), default: prompt")
def import_to_yubikey_piv_cmd(cert, key, slot, pin, management_key):
    """Import a certificate and private key to a YubiKey PIV slot"""
    # Load certificate and private key
    cert_path = Path(cert)
    key_path = Path(key)

    with cert_path.open('rb') as f:
        cert_data = f.read()
        certificate = x509.load_pem_x509_certificate(cert_data)

    with key_path.open('rb') as f:
        key_data = f.read()
        private_key = serialization.load_pem_private_key(key_data, password=None)
        if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise click.ClickException("Unsupported private key type. Only RSA and EC keys are supported for YubiKey PIV.")

    # Convert slot string to SLOT enum
    from yubikit.piv import SLOT
    slot_enum = getattr(SLOT, slot)

    # Import to YubiKey
    import_to_yubikey_piv(
        cert=certificate,
        private_key=private_key,
        slot=slot_enum,
        pin=pin,
        management_key=bytes.fromhex(management_key) if management_key else None
    )

    cli_info(f"Certificate and private key imported to YubiKey PIV slot {slot}")
