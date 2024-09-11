import re
from typing_extensions import Literal
import click

from pathlib import Path
from typing import cast, get_args

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509

import asn1crypto.core  # type: ignore

import yubikit.piv

from hsm_secrets.config import HSMOpaqueObject, X509Info, X509NameType
from hsm_secrets.piv.piv_cert_checks import PIVDomainControllerCertificateChecker
from hsm_secrets.piv.piv_cert_utils import PivKeyTypeName, make_signed_piv_user_cert
from hsm_secrets.piv.yubikey_piv import import_to_yubikey_piv
from hsm_secrets.utils import HsmSecretsCtx, cli_code_info, cli_info, open_hsm_session, pass_common_args
from hsm_secrets.x509.cert_builder import CsrAmendMode, X509CertBuilder
from hsm_secrets.x509.def_utils import find_cert_def, merge_x509_info_with_defaults


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
@click.option('--hostname', '-n', required=True, help="Hostname (CommonName) for the DC certificate")
@click.option('--template', '-t', required=False, help="Template label, default: first template")
def sign_dc_cert(ctx: HsmSecretsCtx, csr: click.File, validity: int, ca: str, out: str|None, san: list[str], hostname: str, template: str|None):
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

    # Add hostname to DNS SANs if not already there
    if hostname not in (x509_info.subject_alt_name.names.get('dns') or []):
        x509_info.subject_alt_name.names['dns'] = [hostname] + list(x509_info.subject_alt_name.names.get('dns') or [])

    # Create X509CertBuilder
    cert_builder = X509CertBuilder(ctx.conf, x509_info, csr_obj, dn_subject_override=f'CN={hostname}')

    # Sign the certificate
    with open_hsm_session(ctx) as ses:
        issuer_cert = ses.get_certificate(issuer_cert_def)
        issuer_key = ses.get_private_key(issuer_x509_def.key)
        signed_cert = cert_builder.amend_and_sign_csr(
            issuer_cert,
            issuer_key,
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
@click.option('--validity', '-v', type=int, help="Validity period in days, default: from config")
@click.option('--key-type', '-k', type=click.Choice(['rsa2048', 'ecp256', 'ecp384']), default='ecp384', help="Key type, default: same as CA")
@click.option('--csr', type=click.Path(exists=True, dir_okay=False, resolve_path=True), help="Path to existing CSR file")
@click.option('--ca', '-c', required=False, help="CA ID (hex) or label, default: from config")
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=False), help="Output filename stem, default: ./<user>-piv[.key/.cer]")
@click.option('--os-type', type=click.Choice(['windows', 'other']), default='windows', help="Target operating system")
@click.option('--san', multiple=True, help="AdditionalSANs, e.g., 'DNS:example.com', 'IP:10.0.0.2', etc.")
def save_user_cert(ctx: HsmSecretsCtx, user: str, template: str|None, subject: str, validity: int, key_type: PivKeyTypeName, csr: str|None, ca: str, out: str, os_type: Literal["windows", "other"], san: list[str]):
    """Create or sign PIV user certificate, save to files

    If a CSR is provided, sign it with a CA certificate.
    Otherwise generate a new key pair and signs a certificate for it.

    Example SAN types:
    - RFC822:alice@example.com
    - UPN:alice@example.com
    - DIRECTORY:/C=US/O=Example/CN=example.com
    - OID:1.2.3.4.5=myValue
    """
    csr_pem: str|None = None
    if csr:
        with open(csr, 'rb') as fi:
            csr_pem = fi.read().decode()

    private_key, csr_obj, signed_cert = make_signed_piv_user_cert(ctx, user, template, subject, validity, key_type, csr_pem, ca, os_type, san)
    _show_piv_cert_summary(signed_cert)

   # Save files
    def _sanitize_username(user: str) -> str:
        user = re.sub(r'@.*', '', user)         # Remove anything after '@'
        user = re.sub(r'[^\w]', '_', user)      # Replace special characters with underscores
        return user or "user"
    out = out or f"{_sanitize_username(user)}-piv"
    key_file = Path(out).with_suffix('.key.pem')
    csr_file = Path(out).with_suffix('.csr.pem')
    cer_file = Path(out).with_suffix('.cer.pem')

    if private_key:
        key_file.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        cli_info(f"Private key saved to: {key_file}")
        csr_file.write_bytes(csr_obj.public_bytes(serialization.Encoding.PEM))
        cli_info(f"CSR saved to: {csr_file}")

    with open(cer_file, 'wb') as fo:
        fo.write(signed_cert.public_bytes(encoding=serialization.Encoding.PEM))
    cli_info(f"Certificate saved to: {cer_file}")
    cli_code_info(f"View it with: `openssl x509 -in {cer_file} -text`")

    _display_ad_strong_mapping(signed_cert)


@cmd_piv_yubikey.command('import')
@pass_common_args
@click.argument('cert', required=True, type=click.Path(exists=True, dir_okay=False, resolve_path=True, allow_dash=False))
@click.argument('key', required=True, type=click.Path(exists=True, dir_okay=False, resolve_path=True, allow_dash=False))
@click.option('--slot', '-s', type=click.Choice(['AUTHENTICATION', 'SIGNATURE', 'KEY_MANAGEMENT', 'CARD_AUTH']), default='AUTHENTICATION', help="PIV slot to import to")
@click.option('--management-key', '-m', help="PIV management key (hex), default: prompt")
def import_to_yubikey_piv_cmd(ctx: HsmSecretsCtx, cert: click.Path, key: click.Path, slot: str, management_key: str|None):
    """Import cert and key from files to YubiKey PIV slot

    If two YubiKeys are connected, the one _without_ HSM auth will be used.
    """
    cert_path = Path(str(cert))
    with cert_path.open('rb') as f:
        cert_data = f.read()
        certificate = x509.load_pem_x509_certificate(cert_data)

    key_path = Path(str(key))
    with key_path.open('rb') as f:
        key_data = f.read()
        private_key = serialization.load_pem_private_key(key_data, password=None)
        if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise click.ClickException("Unsupported private key type. Only RSA and EC keys are supported for YubiKey PIV.")

    cli_info("PEM files loaded:")
    cli_code_info(f" - certificate: `{cert_path.name}`")
    cli_code_info(f" - private key: `{key_path.name}`")

    _show_piv_cert_summary(certificate)

    # Convert slot string to SLOT enum
    from yubikit.piv import SLOT
    slot_enum = getattr(SLOT, slot)

    import_to_yubikey_piv(
        cert=certificate,
        private_key=private_key,
        slot=slot_enum,
        management_key=bytes.fromhex(management_key) if management_key else None
    )
    _display_ad_strong_mapping(certificate)


@cmd_piv_yubikey.command('generate')
@pass_common_args
@click.argument('user', required=True)
@click.option('--slot', '-s', type=click.Choice(['AUTHENTICATION', 'SIGNATURE', 'KEY_MANAGEMENT', 'CARD_AUTH']), default='AUTHENTICATION', help="PIV slot to import to")
@click.option('--management-key', '-m', help="PIV management key (hex), default: prompt")
@click.option('--template', '-t', required=False, help="Template label, default: first template")
@click.option('--subject', '-s', required=False, help="Cert subject (DN), default: from config")
@click.option('--validity', '-v', type=int, help="Validity period in days, default: from config")
@click.option('--key-type', '-k', type=click.Choice(['rsa2048', 'ecp256', 'ecp384']), default='ecp384', help="Key type, default: same as CA")
@click.option('--ca', '-c', required=False, help="CA ID (hex) or label, default: from config")
@click.option('--os-type', type=click.Choice(['windows', 'other']), default='windows', help="Target operating system")
@click.option('--san', multiple=True, help="AdditionalSANs, e.g., 'DNS:example.com', 'IP:10.0.0.2', etc.")
def yubikey_gen_user_cert(ctx: HsmSecretsCtx, user: str, slot: str, management_key: str|None, template: str|None, subject: str, validity: int, key_type: PivKeyTypeName, ca: str, os_type: Literal["windows", "other"], san: list[str]):
    """Generate a PIV key + cert and store directly in YubiKey

    User argument should be a AD username for Windows or email for macOS/Linux.

    If two YubiKeys are connected, the one _without_ HSM auth will be used for PIV.
    """
    slot_enum: yubikit.piv.SLOT = getattr(yubikit.piv.SLOT, slot)
    private_key, _csr_obj, signed_cert = make_signed_piv_user_cert(ctx, user, template, subject, validity, key_type, None, ca, os_type, san)
    _show_piv_cert_summary(signed_cert)
    import_to_yubikey_piv(
        cert = signed_cert,
        private_key = private_key,
        slot = slot_enum,
        management_key = bytes.fromhex(management_key) if management_key else None
    )
    _display_ad_strong_mapping(signed_cert)



def _show_piv_cert_summary(signed_cert: x509.Certificate):
    cli_info(f"PIV certificate summary:")
    cli_code_info(f" - Serial:  `{signed_cert.serial_number:x}` (❗️store for revocation❗️)")
    cli_code_info(f" - Subject: {signed_cert.subject.rfc4514_string()}")
    for i, san in enumerate(signed_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value):
        if isinstance(san, x509.OtherName):
            type_str = 'UPN' if san.type_id == x509.ObjectIdentifier('1.3.6.1.4.1.311.20.2.3') else f'OID {san.type_id.dotted_string}'
            san_str = f"{type_str}: {asn1crypto.core.UTF8String.load(san.value).native.strip()}"
        elif isinstance(san, x509.RFC822Name):
            san_str = f"RFC822: {san.value}"
        else:
            san_str = str(san)
        cli_code_info(f" - SAN {i+1}:   {san_str}")
    cli_code_info(f" - Issuer:  {signed_cert.issuer.rfc4514_string()}")


def _display_ad_strong_mapping(signed_cert):
    ski_hex = signed_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex().lower()
    cli_info("")
    cli_info(f"For Strong Certificate Mapping (KB5014754), add this attribute to the AD User object:")
    cli_code_info(f'altSecurityIdentities = `"X509:<SKI>{ski_hex}"`')


'''
def generate_on_yubikey_piv_cmd(slot: str, key_type: str, management_key: Optional[str], subject: str, validity: int):
    """Generate a PIV key on YubiKey and make a certificate for it"""
    # Convert slot string to SLOT enum
    slot_enum = getattr(SLOT, slot)

    # Convert key type string to PivKeyType enum
    key_type_enum = PivKeyType[key_type]
    public_key = _generate_on_yubikey_piv(slot_enum, KEY_TYPE[key_type], bytes.fromhex(management_key) if management_key else None)

    # Create a dummy certificate
    x509_info = X509CertBuilder.get_default_x509_info()
    x509_info.validity_days = validity
    x509_info.attribs.common_name = subject
    x509_info.subject_alt_name = x509_info.SubjectAltName()
    cert_builder = X509CertBuilder(HSMConfig(), x509_info, public_key, dn_subject_override=subject)
    dummy_cert = cert_builder.build_self_signed()

    _import_to_yubikey_piv(
        cert=dummy_cert,
        private_key=None,
        slot=slot_enum,
        management
'''
