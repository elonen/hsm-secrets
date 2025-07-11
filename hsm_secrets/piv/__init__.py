from datetime import datetime
import re
from typing_extensions import Literal
import click
import secrets

from pathlib import Path
from typing import get_args

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509

import asn1crypto.core  # type: ignore

import yubikit.piv

from hsm_secrets.config import HSMOpaqueObject, X509NameType
from hsm_secrets.piv.piv_cert_checks import PIVDomainControllerCertificateChecker
from hsm_secrets.piv.piv_cert_utils import PivKeyTypeName, make_signed_piv_user_cert
from hsm_secrets.piv.yubikey_piv import YUBIKEY_DEFAULT_PIN, YubikeyPivManagementSession, generate_yubikey_piv_keypair, import_to_yubikey_piv, confirm_and_reset_yubikey_piv_app, set_yubikey_piv_pin_puk_management_key
from hsm_secrets.utils import HsmSecretsCtx, cli_code_info, cli_debug, cli_error, cli_info, cli_warn, open_hsm_session, pass_common_args, scan_local_yubikeys, try_post_cert_to_http_endpoint_as_form
from hsm_secrets.x509.cert_builder import CsrAmendMode, X509CertBuilder
from hsm_secrets.x509.def_utils import find_ca_def, merge_x509_info_with_defaults


@click.group()
@click.pass_context
def cmd_piv(ctx: click.Context):
    """PIV commands (Yubikey Windows login)"""
    ctx.ensure_object(dict)

@cmd_piv.group('yubikey')
def cmd_piv_yubikey():
    """YubiKey PIV slot management"""
    pass


@cmd_piv.command('sign-dc-cert')
@pass_common_args
@click.argument('csr', required=True, type=click.File(), default=click.get_text_stream('stdin'))
@click.option('--validity', '-v', type=int, help="Validity period in days, default: from config")
@click.option('--ca', '-c', required=False, help="CA ID (hex) or label, default: from config")
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=False), help="Output filename, default: deduced from input")
@click.option('--san', multiple=True, help="Additional (GeneralName) SANs")
@click.option('--template', '-t', required=False, help="Template label, default: first template")
def sign_dc_cert(ctx: HsmSecretsCtx, csr: click.File, validity: int, ca: str, out: str|None, san: list[str], template: str|None):
    """Sign a DC Kerberos PKINIT certificate for PIV

    Usage: create a PKINIT CSR on the Domain Controller first, then sign it with this command.
    """
    csr_path = Path(csr.name)
    with csr_path.open('rb') as f:
        csr_obj: x509.CertificateSigningRequest = x509.load_pem_x509_csr(f.read())

    out_path: Path = Path(out) if out else csr_path.with_suffix('.cer.pem')

    # Get CA (issuer)
    issuer_cert_def = ctx.conf.find_def(ca or ctx.conf.piv.default_ca_id, HSMOpaqueObject)
    issuer_x509_ca = find_ca_def(ctx.conf, issuer_cert_def.id)
    assert issuer_x509_ca, f"CA cert ID not found: 0x{issuer_cert_def.id:04x}"

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
        issuer_key = ses.get_private_key(issuer_x509_ca.key)
        signed_cert = cert_builder.amend_and_sign_csr(
            issuer_cert,
            issuer_key,
            issuer_x509_ca.crl_distribution_points,
            validity_days=x509_info.validity_days,
            amend_subject=CsrAmendMode.REPLACE,
            amend_sans=CsrAmendMode.ADD,
            amend_extended_key_usage=CsrAmendMode.ADD,
            amend_key_usage=CsrAmendMode.ADD,
        )

    PIVDomainControllerCertificateChecker(signed_cert).check_and_show_issues()

    # Save the signed certificate
    with open(out_path, 'wb') as f:
        f.write(signed_cert.public_bytes(encoding=serialization.Encoding.PEM))
    cli_info(f"Signed certificate saved to: {out_path}")
    cli_code_info(f"View it with: `openssl x509 -in {out_path} -text`")


@cmd_piv.command('user-cert')
@pass_common_args
@click.option('--user', '-u', required=True, help="User identifier (username for Windows, email for macOS/Linux)")
@click.option('--template', '-t', required=False, help="Template label, default: first template")
@click.option('--subject', '-s', required=False, help="Cert subject (DN), default: from config")
@click.option('--multi', is_flag=False, help="Multi-account mode (no UPN/email SAN)")
@click.option('--validity', '-v', type=int, help="Validity period in days, default: from config")
@click.option('--key-type', '-k', type=click.Choice(['rsa2048', 'ecp256', 'ecp384']), default='rsa2048', help="Key type")
@click.option('--csr', type=click.Path(exists=True, dir_okay=False, resolve_path=True), help="Path to existing CSR file")
@click.option('--ca', '-c', required=False, help="CA ID (hex) or label, default: from config")
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=False), help="Output filename stem, default: ./<user>-piv[.key/.cer]")
@click.option('--os-type', type=click.Choice(['windows', 'other']), default='windows', help="Target operating system")
@click.option('--san', multiple=True, help="AdditionalSANs, e.g., 'DNS:example.com', 'IP:10.0.0.2', etc.")
def save_user_cert(ctx: HsmSecretsCtx, user: str, template: str|None, subject: str, multi: bool, validity: int, key_type: PivKeyTypeName, csr: str|None, ca: str, out: str, os_type: Literal["windows", "other"], san: list[str]):
    """Create or sign PIV user certificate, save to files

    If a CSR is provided, sign it with a CA certificate.
    Otherwise generate a new key pair and signs a certificate for it.

    Example SAN types:
    - RFC822:alice@example.com
    - UPN:alice@example.com
    - DIRECTORY:/C=US/O=Example/CN=example.com
    - OID:1.2.3.4.5=myValue
    """
    csr_obj = None
    if csr:
        with open(csr, 'rb') as fi:
            csr_pem = fi.read().decode()
            csr_obj = x509.load_pem_x509_csr(csr_pem.encode())

    private_key, csr_obj, signed_cert = make_signed_piv_user_cert(ctx, user, template, subject, validity, key_type, csr_obj, ca, os_type, san, multi)
    _show_piv_cert_summary(signed_cert)

   # Save files
    def _sanitize_username(user: str) -> str:
        user = re.sub(r'@.*', '', user)         # Remove anything after '@'
        user = re.sub(r'[^\w]', '_', user)      # Replace special characters with underscores
        return user or "user"
    out = out or f"{_sanitize_username(user)}-piv"
    key_file = Path(out).with_suffix('.key.pem')
    #csr_file = Path(out).with_suffix('.csr.pem')
    cer_file = Path(out).with_suffix('.cer.pem')

    if private_key:
        key_file.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        cli_info(f"Private key saved to: {key_file}")
        #csr_file.write_bytes(csr_obj.public_bytes(serialization.Encoding.PEM))
        #cli_info(f"CSR saved to: {csr_file}")

    # Submit the certificate to the configured URL, if set
    if post_url := ctx.conf.general.cert_submit_url:
        cert_bytes = signed_cert.public_bytes(encoding=serialization.Encoding.PEM)
        try_post_cert_to_http_endpoint_as_form(cert_bytes, cer_file.name, str(post_url), {})

    with open(cer_file, 'wb') as fo:
        fo.write(signed_cert.public_bytes(encoding=serialization.Encoding.PEM))
    cli_info(f"Certificate saved to: {cer_file}")
    cli_code_info(f"View it with: `openssl x509 -in {cer_file} -text`")

    _display_ad_strong_mapping(signed_cert)


@cmd_piv_yubikey.command('import')
@pass_common_args
@click.argument('key', required=True, type=click.Path(exists=True, dir_okay=False, resolve_path=True, allow_dash=False), metavar='<KEYFILE>')
@click.argument('cert', required=True, type=click.Path(exists=True, dir_okay=False, resolve_path=True, allow_dash=False), metavar='<CERTFILE>')
@click.option('--no-touch', is_flag=True, help="Do not require touch for key use")
@click.option('--slot', '-s', type=click.Choice(['AUTHENTICATION', 'SIGNATURE', 'KEY_MANAGEMENT', 'CARD_AUTH']), default='AUTHENTICATION', help="PIV slot to import to")
@click.option('--management-key', '-m', help="PIV management key (hex), default: prompt")
def import_to_yubikey_piv_cmd(ctx: HsmSecretsCtx, cert: click.Path, no_touch: bool, key: click.Path, slot: str, management_key: str|None):
    """Import cert and key from files to YubiKey PIV slot

    If two YubiKeys are connected, the one _without_ HSM auth will be used.
    """
    # Load cert PEM
    with Path(str(cert)).open('rb') as f:
        certificate = x509.load_pem_x509_certificate(f.read())

    # Load key PEM
    with Path(str(key)).open('rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise click.ClickException("Unsupported private key type. Only RSA and EC keys are supported for YubiKey PIV.")

    # Convert slot string to SLOT enum
    slot_enum = getattr(yubikit.piv.SLOT, slot)
    mgt_key_bytes = bytes.fromhex(management_key) if management_key else None

    with YubikeyPivManagementSession(mgt_key_bytes) as ses:
        tp = yubikit.piv.TOUCH_POLICY.NEVER if no_touch else yubikit.piv.TOUCH_POLICY.CACHED
        import_to_yubikey_piv(ses.piv, certificate, private_key, touch_policy=tp, slot=slot_enum)

    cli_info('')
    _show_piv_cert_summary(certificate)
    _display_ad_strong_mapping(certificate)


@cmd_piv_yubikey.command('generate')
@pass_common_args
@click.argument('user', required=True)
@click.option('--slot', type=click.Choice(['AUTHENTICATION', 'SIGNATURE', 'KEY_MANAGEMENT', 'CARD_AUTH']), default='AUTHENTICATION', help="PIV slot to import to")
@click.option('--no-reset', is_flag=True, help="Do not reset PIV app before generating key")
@click.option('--no-touch', is_flag=True, help="Do not require touch for key use")
@click.option('--multi', is_flag=True, help="Multi-account mode (no UPN/email SAN)")
@click.option('--management-key', '-m', help="PIV management key (hex), default: prompt")
@click.option('--template', '-t', required=False, help="Template label, default: first template")
@click.option('--subject', '-s', required=False, help="Cert subject (DN), default: from config")
@click.option('--validity', '-v', type=int, help="Validity period in days, default: from config")
@click.option('--key-type', '-k', type=click.Choice(['rsa2048', 'ecp256', 'ecp384']), default='rsa2048', help="Key type")
@click.option('--ca', '-c', required=False, help="CA ID (hex) or label, default: from config")
@click.option('--os-type', type=click.Choice(['windows', 'other']), default='windows', help="Target operating system")
@click.option('--san', multiple=True, help="AdditionalSANs, e.g., 'DNS:example.com', 'IP:10.0.0.2', etc.")
@click.option('--no-submit', is_flag=True, help="Do not submit the certificate to the configured URL")
def yubikey_gen_user_cert(ctx: HsmSecretsCtx, user: str, slot: str, no_reset: bool, no_touch: bool, multi: bool, management_key: str|None, template: str|None, subject: str, validity: int|None, key_type: PivKeyTypeName, ca: str, os_type: Literal["windows", "other"], san: list[str], no_submit: bool):
    """Generate a PIV key + cert and store directly in YubiKey

    User argument should be a AD username for Windows or email for macOS/Linux.

    If two YubiKeys are connected, the one _without_ HSM auth will be used for PIV.
    """
    slot_enum = getattr(yubikit.piv.SLOT, slot)
    assert slot_enum, f"Invalid slot: {slot}"
    yk_key_type =  {'rsa2048': yubikit.piv.KEY_TYPE.RSA2048, 'ecp256': yubikit.piv.KEY_TYPE.ECCP256, 'ecp384': yubikit.piv.KEY_TYPE.ECCP384}[key_type]

    mgt_key_bytes = bytes.fromhex(management_key) if management_key else None
    pin = None

    if not no_reset:
        confirm_and_reset_yubikey_piv_app()
        pin = YUBIKEY_DEFAULT_PIN
        mgt_key_bytes = None

    # Validate HSM credentials exist first, before generating PIV key
    cli_info("Checking for HSM authentication credentials...")
    cli_debug(f"[PIV] Pre-validating HSMauth credentials exist before PIV key generation")
    try:
        hsm_yubikey, _ = scan_local_yubikeys(require_one_hsmauth=True, require_one_other=False)
        if not hsm_yubikey:
            raise click.ClickException("No YubiKey with HSMauth credentials found")
        cli_debug(f"[PIV] Found HSMauth credentials on YubiKey {getattr(hsm_yubikey, 'serial', 'unknown')}")
        cli_info("HSM authentication credentials found.")
    except Exception as e:
        cli_error(f"HSM authentication validation failed: {e}")
        cli_error("Cannot proceed with PIV certificate generation without HSM access")
        exit(1)

    tp = yubikit.piv.TOUCH_POLICY.NEVER if no_touch else yubikit.piv.TOUCH_POLICY.CACHED

    # Generate PIV key and CSR (after HSM validation)
    with YubikeyPivManagementSession(mgt_key_bytes, pin) as ses:
        pin, mgt_key_bytes = ses.pin, ses.management_key
        csr = generate_yubikey_piv_keypair(
            ses.piv,
            yk_key_type,
            yubikit.piv.PIN_POLICY.ONCE,
            tp,
            f'CN={user}',
            slot_enum)
    
    cli_debug(f"[PIV] PIV key generation completed, now proceeding to HSM signing")
    
    # HSM signing (with no PIV session open to avoid sharing violations)
    cli_info('')
    cli_info("Signing the certificate on HSM...")
    cli_debug(f"[PIV] About to call make_signed_piv_user_cert for certificate signing")
    _, _, signed_cert = make_signed_piv_user_cert(ctx, user, template, subject, validity, None, csr, ca, os_type, san, multi)
    cli_debug(f"[PIV] Certificate signing completed successfully")

    # Submit the certificate to the configured URL, if set
    if post_url := ctx.conf.general.cert_submit_url:
        if not no_submit:
            cert_bytes = signed_cert.public_bytes(encoding=serialization.Encoding.PEM)
            today = datetime.now().strftime('%Y-%m-%d')
            cert_name = f"{user}-piv-{today}.pem"
            try_post_cert_to_http_endpoint_as_form(cert_bytes, cert_name, str(post_url), {})

    cli_debug(f"[PIV] Opening second PIV session to import certificate to YubiKey")
    with YubikeyPivManagementSession(mgt_key_bytes, pin) as ses:
        import_to_yubikey_piv(ses.piv, signed_cert, private_key=None, touch_policy=tp, slot=slot_enum)
        if not no_reset:
            new_pin = str(secrets.randbelow(900000) + 100000)
            new_puk = str(secrets.randbelow(90000000) + 10000000)
            new_mgt_key = secrets.token_bytes(24)
            cli_info('')
            new_key_type = set_yubikey_piv_pin_puk_management_key(ses.piv, new_pin, new_puk, 5, new_mgt_key)
            cli_code_info(f"- New PIN: `{new_pin}` (give this to the user)")
            cli_code_info(f"- New PUK: `{new_puk}`")
            cli_code_info(f"- New PIV Management Key ({new_key_type}): `{new_mgt_key.hex()}`")

    cli_info('')
    _show_piv_cert_summary(signed_cert)
    _display_ad_strong_mapping(signed_cert)


def _show_piv_cert_summary(signed_cert: x509.Certificate):
    cli_info("PIV certificate summary:")
    cli_code_info(f" - Serial:   `{signed_cert.serial_number:x}`")
    cli_code_info(f" - Subject:  {signed_cert.subject.rfc4514_string()}")
    cli_code_info(f" - Key type: {signed_cert.public_key().__class__.__name__}")
    for i, san in enumerate(signed_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value):
        if isinstance(san, x509.OtherName):
            type_str = 'UPN' if san.type_id == x509.ObjectIdentifier('1.3.6.1.4.1.311.20.2.3') else f'OID {san.type_id.dotted_string}'
            san_str = f"{type_str}: {asn1crypto.core.UTF8String.load(san.value).native.strip()}"
        elif isinstance(san, x509.RFC822Name):
            san_str = f"RFC822: {san.value}"
        else:
            san_str = str(san)
        cli_code_info(f" - SAN {i+1}:    {san_str}")
    cli_code_info(f" - Issuer:   {signed_cert.issuer.rfc4514_string()}")


def _display_ad_strong_mapping(signed_cert):
    ski_hex = signed_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex().lower()
    cli_info("")
    cli_info("For Strong Certificate Mapping (KB5014754), add this attribute to the AD User object:")
    cli_code_info(f'altSecurityIdentities = `X509:<SKI>{ski_hex}`')
