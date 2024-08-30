from typing_extensions import Literal
import click

from typing import Union, Optional, cast, get_args

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509

from hsm_secrets.config import HSMKeyID, HSMOpaqueObject, X509Info, X509NameType
from hsm_secrets.key_adapters import PrivateKeyOrAdapter
from hsm_secrets.piv.piv_cert_checks import PIVUserCertificateChecker
from hsm_secrets.utils import HsmSecretsCtx, open_hsm_session
from hsm_secrets.x509.cert_builder import CsrAmendMode, X509CertBuilder, get_issuer_cert_and_key
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
        extra_san_strings: list[str]
    )-> tuple[
        Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]],
        x509.CertificateSigningRequest,
        x509.Certificate]:

    # Get and merge template with defaults
    cert_template = ctx.conf.piv.user_cert_templates[template] if template else next(iter(ctx.conf.piv.user_cert_templates.values()))
    x509_info = merge_x509_info_with_defaults(cert_template, ctx.conf)

    # Set explicit values to the merged cert template
    if validity:
        x509_info.validity_days = validity
    subject = subject or _make_dn_subject(user, x509_info.attribs)
    _parse_and_add_explicit_sans(x509_info, extra_san_strings)
    _add_upn_or_email_to_sans(x509_info, user, os_type, ctx.conf.piv.default_piv_domain)

    # Either load CSR or generate new key pair
    csr_obj, private_key = None, None
    if csr_pem:
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode())
    else:
        _, private_key = _generate_piv_key_pair(key_type)

    # Create X509CertBuilder, amend CSR (if provided), sign and return
    csr_or_key = csr_obj or private_key
    assert csr_or_key
    cert_builder = X509CertBuilder(ctx.conf, x509_info, csr_or_key, dn_subject_override=subject)

    with open_hsm_session(ctx) as ses:
        issuer_cert, issuer_key = get_issuer_cert_and_key(ctx, ses, ca or ctx.conf.piv.default_ca_id)
        if csr_obj:
            signed_cert = cert_builder.amend_and_sign_csr(
                issuer_cert=issuer_cert,
                issuer_key=issuer_key,
                amend_subject=CsrAmendMode.REPLACE,
                amend_sans=CsrAmendMode.ADD,
                amend_key_usage=CsrAmendMode.REPLACE,
                amend_extended_key_usage=CsrAmendMode.REPLACE,
                amend_basic_constraints=CsrAmendMode.REPLACE,
                validity_days=x509_info.validity_days
            )
        else:
            signed_cert = cert_builder.build_and_sign(issuer_cert, issuer_key)

    PIVUserCertificateChecker(signed_cert, os_type).check_and_show_issues()
    return private_key, csr_obj or cert_builder.generate_csr(), signed_cert


def _make_dn_subject(user: str, attribs: Optional[X509Info.CertAttribs]) -> str:
    subject = f"CN={user}"
    if attribs:
        for k, v in {'O': attribs.organization, 'L': attribs.locality, 'ST': attribs.state, 'C': attribs.country}.items():
            if v:
                subject += f",{k}={v}"
    return subject


def _parse_and_add_explicit_sans(x509_info: X509Info, san_strings: list[str]):
    x509_info.subject_alt_name = x509_info.subject_alt_name or x509_info.SubjectAltName()

    # Add explicitly provided SANs
    valid_san_types = get_args(X509NameType)
    for san_str in san_strings:
        try:
            san_type, san_value = san_str.split(':', 1)
        except ValueError:
            raise click.ClickException(f"Invalid SAN: '{san_str}'. Must be in the form 'type:value', where type is one of: {', '.join(valid_san_types)}")
        san_type_lower = san_type.lower()
        if san_type_lower not in valid_san_types:
            raise click.ClickException(f"Provided '{san_type.lower()}' is not a supported X509NameType. Must be one of: {', '.join(valid_san_types)}")
        x509_info.subject_alt_name.names.setdefault(san_type_lower, []).append(san_value)    # type: ignore [arg-type]


def _add_upn_or_email_to_sans(x509_info: X509Info, user: str, os_type: str, default_domain: str|None):
    # Add UPN or email to SANs based on OS type
    if '@' in user:
        username = user
    elif domain := default_domain:
        username = user + '@' + domain.lstrip('@')
    else:
        username = user

    x509_info.subject_alt_name = x509_info.subject_alt_name or x509_info.SubjectAltName()
    if os_type == 'windows':
        x509_info.subject_alt_name.names.setdefault('upn', []).append(username)
    else:
        x509_info.subject_alt_name.names.setdefault('rfc822', []).append(username)


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

