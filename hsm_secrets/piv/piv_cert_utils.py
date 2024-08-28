from typing_extensions import Literal
import click

from typing import Union, Optional, get_args

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509

from hsm_secrets.config import HSMOpaqueObject, X509NameType
from hsm_secrets.piv.piv_cert_checks import PIVUserCertificateChecker
from hsm_secrets.utils import HsmSecretsCtx, open_hsm_session
from hsm_secrets.x509.cert_builder import X509CertBuilder
from hsm_secrets.x509.def_utils import find_cert_def, merge_x509_info_with_defaults


PivKeyTypeName = Literal['rsa2048', 'ecp256', 'ecp384']


def make_signed_piv_user_cert(
        ctx: HsmSecretsCtx,
        user: str,
        template: str|None,
        subject: str,
        validity: int,
        key_type: PivKeyTypeName,
        csr_pem: str|None,
        ca: str,
        os_type: Literal["windows", "other"],
        san: list[str]) -> tuple[
            Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]],
            x509.CertificateSigningRequest,
            x509.Certificate]:
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
    if csr_pem:
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode())
        private_key = None
    else:
        _, private_key = _generate_piv_key_pair(key_type)
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
    if '@' in user:
        username = user
    elif domain := ctx.conf.piv.default_piv_domain.strip():
        username = user + '@' + domain.lstrip('@')
    else:
        username = user

    if os_type == 'windows':
        x509_info.subject_alt_name.names.setdefault('upn', []).append(username)
    else:
        x509_info.subject_alt_name.names.setdefault('rfc822', []).append(username)

    # Create X509CertBuilder
    key_or_csr = private_key or csr_obj
    assert key_or_csr
    cert_builder = X509CertBuilder(ctx.conf, x509_info, key_or_csr, dn_subject_override=subject)

    csr_obj = cert_builder.generate_csr() if private_key else csr_obj
    assert csr_obj  # Should be set by now

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
    return private_key, csr_obj, signed_cert



def _generate_piv_key_pair(key_type: PivKeyTypeName) -> tuple[Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey], Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]]:
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    if key_type == 'rsa2048':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == 'ecp256':
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif key_type == 'ecp384':
        private_key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    public_key = private_key.public_key()
    return public_key, private_key

