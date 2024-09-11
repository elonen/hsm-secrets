from datetime import datetime, timedelta
from pathlib import Path
import click

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec, ed448
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
import cryptography.x509.oid as x509_oid

import ipaddress

import yubihsm          # type: ignore [import]
import yubihsm.defs     # type: ignore [import]
import yubihsm.objects  # type: ignore [import]

from hsm_secrets.config import HSMOpaqueObject, X509Info, X509KeyUsageName
from hsm_secrets.key_adapters import PrivateKeyOrAdapter
from hsm_secrets.utils import HsmSecretsCtx, cli_code_info, cli_info, cli_warn, open_hsm_session, pass_common_args
from hsm_secrets.x509.cert_builder import CsrAmendMode, X509CertBuilder, get_issuer_cert_and_key
from hsm_secrets.x509.cert_checker import BaseCertificateChecker, IssueSeverity
from hsm_secrets.x509.def_utils import find_cert_def, merge_x509_info_with_defaults

@click.group()
@click.pass_context
def cmd_tls(ctx: click.Context):
    """TLS certificate commands"""
    ctx.ensure_object(dict)

@cmd_tls.command('server-cert')
@pass_common_args
@click.option('--out', '-o', required=True, type=click.Path(exists=False, dir_okay=False, resolve_path=True), help="Output filename")
@click.option('--common-name', '-c', required=True, help="CN, e.g. public DNS name")
@click.option('--san-dns', '-d', multiple=True, help="DNS SAN (Subject Alternative Name)")
@click.option('--san-ip', '-i', multiple=True, help="IP SAN (Subject Alternative Name)")
@click.option('--validity', '-v', default=365, help="Validity period in days")
@click.option('--keyfmt', '-f', type=click.Choice(['rsa4096', 'ed25519', 'ecp256', 'ecp384']), default='ecp384', help="Key format")
@click.option('--sign-ca', '-s', type=str, required=False, help="CA ID (hex) or label to sign with, or 'self'. Default: use config", default=None)
def server_cert(ctx: HsmSecretsCtx, out: click.Path, common_name: str, san_dns: list[str], san_ip: list[str], validity: int, keyfmt: str, sign_ca: str):
    """Create a TLS server certificate + key

    TYPICAL USAGE:

        $ hsm-secrets tls server-cert -o wiki.example.com.pem -c wiki.example.com -d intraweb.example.com

    Create a new TLS server certificate for the given CN and (optional) SANs.
    Basic name fields are read from the config file (country, org, etc.)

    If --sign-ca is 'self', the certificate will be self-signed instead
    of signing with a HSM-backed CA.

    The --out option is used as a base filename, and the key, csr, and cert files
    written with the extensions '.key.pem', '.csr.pem', and '.cer.pem' respectively.
    """
    # Find the issuer CA definition
    issuer_x509_def = None
    issuer_cert_def = None
    if (sign_ca or '').strip().lower() != 'self':
        issuer_cert_def = ctx.conf.find_def(sign_ca or ctx.conf.tls.default_ca_id, HSMOpaqueObject)
        issuer_x509_def = find_cert_def(ctx.conf, issuer_cert_def.id)
        assert issuer_x509_def, f"CA cert ID not found: 0x{issuer_cert_def.id:04x}"

    info = X509Info()
    info.attribs = X509Info.CertAttribs(common_name = common_name)
    info.attribs.common_name = common_name

    ku: set[X509KeyUsageName] = set(['digitalSignature', 'keyEncipherment', 'keyAgreement'])
    info.key_usage = X509Info.KeyUsage(usages = ku, critical = True)

    info.extended_key_usage = X509Info.ExtendedKeyUsage(usages = set(['serverAuth']), critical = False)
    info.validity_days = validity
    if common_name not in (san_dns or []):
        san_dns = [common_name] + list(san_dns or [])   # Add CN to DNS SANs if not already there
    if san_dns or san_ip:
        info.subject_alt_name = X509Info.SubjectAltName(names = {'dns': [], 'ip': []}, critical = False)
        for n in san_dns or []:
            info.subject_alt_name.names['dns'].append(n)
        for n in san_ip or []:
            info.subject_alt_name.names['ip'].append(n)

    merged_info = merge_x509_info_with_defaults(info, ctx.conf)
    merged_info.basic_constraints = X509Info.BasicConstraints(ca=False, path_len=None, critical=False) # end-entity cert

    priv_key: PrivateKeyOrAdapter
    if keyfmt == 'rsa4096':
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif keyfmt == 'ed25519':
        priv_key = ed25519.Ed25519PrivateKey.generate()
    elif keyfmt == 'ecp256':
        priv_key = ec.generate_private_key(ec.SECP256R1())
    elif keyfmt == 'ecp384':
        priv_key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise click.ClickException(f"Unsupported key format: {keyfmt}")

    key_file = Path(str(out)).with_suffix('.key.pem')
    csr_file = Path(str(out)).with_suffix('.csr.pem')
    cer_file = Path(str(out)).with_suffix('.cer.pem')
    chain_file = Path(str(out)).with_suffix('.chain.pem')

    existing_files = [file for file in [key_file, csr_file, cer_file, chain_file] if file.exists()]
    if existing_files:
        file_names = ", ".join( click.style(str(file), fg='cyan') for file in existing_files)
        click.confirm(f"Files {file_names} already exist. Overwrite?", abort=True, err=True)

    builder = X509CertBuilder(ctx.conf, merged_info, priv_key)
    issuer_cert = None
    if issuer_x509_def:
         assert issuer_cert_def
         with open_hsm_session(ctx) as ses:
            issuer_cert = ses.get_certificate(issuer_cert_def)
            issuer_key = ses.get_private_key(issuer_x509_def.key)
            signed_cert = builder.build_and_sign(issuer_cert, issuer_key)
            cli_info(f"Signed with CA cert 0x{issuer_cert_def.id:04x}: {issuer_cert.subject}")
    else:
        signed_cert = builder.generate_and_self_sign()
        cli_warn("WARNING: Self-signed certificate, please sign the CSR manually")
        cli_info("")

    TLSServerCertificateChecker(signed_cert).check_and_show_issues()

    key_pem = priv_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    csr_pem = builder.generate_csr().public_bytes(encoding=serialization.Encoding.PEM)
    crt_pem = signed_cert.public_bytes(encoding=serialization.Encoding.PEM)
    chain_pem = (crt_pem.strip() + b'\n' + issuer_cert.public_bytes(encoding=serialization.Encoding.PEM)) if issuer_cert else None

    key_file.write_bytes(key_pem)
    csr_file.write_bytes(csr_pem)
    cer_file.write_bytes(crt_pem)

    cli_info(f"Key written to: {key_file}")
    cli_info(f"CSR written to: {csr_file}")
    cli_info(f"Cert written to: {cer_file}")

    if issuer_cert and chain_pem:
        chain_file.write_bytes(chain_pem)
        cli_info(f"Chain (bundle) written to: {chain_file}")

    cli_info("")
    cli_code_info(f"To view certificate, use:\n`openssl crl2pkcs7 -nocrl -certfile {cer_file} | openssl  pkcs7 -print_certs | openssl x509 -text -noout`")

# ----- Sign CSR -----

@cmd_tls.command('sign')
@pass_common_args
@click.argument('csr', type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=True), default='-', required=True, metavar='<csr-file>')
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True), help="Output filename (default: deduce from input)", default=None)
@click.option('--ca', '-c', type=str, required=False, help="CA ID (hex) or label to sign with. Default: use config", default=None)
@click.option('--validity', '-v', default=365, help="Validity period in days")
def sign_csr(ctx: HsmSecretsCtx, csr: click.Path, out: click.Path|None, ca: str|None, validity: int):
    """Sign a CSR with a CA key

    Sign a Certificate Signing Request (CSR) with a CA key from the HSM.
    The output is a signed certificate in PEM format.
    """
    csr_data = click.get_text_stream('stdin').read().encode() if (csr == '-') else Path(str(csr)).read_bytes()
    csr_obj = x509.load_pem_x509_csr(csr_data)

    # Make fields to amend the CSR with
    template = X509Info(
        basic_constraints = X509Info.BasicConstraints(ca=False, path_len=None, critical=False), # end-entity cert
        key_usage = X509Info.KeyUsage(usages = {'digitalSignature', 'keyEncipherment', 'keyAgreement'}, critical = True),
        extended_key_usage = X509Info.ExtendedKeyUsage(usages = {'serverAuth'}, critical = False),
        validity_days = validity
    )

    # Add DNS SAN from CN
    if cn := csr_obj.subject.get_attributes_for_oid(x509_oid.NameOID.COMMON_NAME):
        template.subject_alt_name = X509Info.SubjectAltName(names = {'dns': [str(cn[0].value)]}, critical = False)
    else:
        cli_warn("WARNING: CSR does not contain a Common Name (CN) field. SubjectAltName will be empty")


    # Sign the CSR with HSM-backed CA
    with open_hsm_session(ctx) as ses:
        issuer_cert, issuer_key = get_issuer_cert_and_key(ctx, ses, ca or ctx.conf.tls.default_ca_id)
        builder = X509CertBuilder(ctx.conf, template, csr_obj)
        signed_cert = builder.amend_and_sign_csr(
            issuer_cert, issuer_key,
            validity_days = validity,
            amend_sans = CsrAmendMode.ADD,
            amend_extended_key_usage = CsrAmendMode.ADD,
            amend_key_usage = CsrAmendMode.REPLACE
        )

    TLSServerCertificateChecker(signed_cert).check_and_show_issues()

    # Save the signed certificate
    out_path = Path(str(out)) if out else Path(str(csr)).with_suffix('.cer.pem')
    if out_path.exists():
        click.confirm(f"Output file '{out_path}' already exists. Overwrite?", abort=True, err=True)
    out_path.write_bytes(signed_cert.public_bytes(encoding=serialization.Encoding.PEM))

    cli_info(f"Signed certificate saved to: {out_path}")
    cli_code_info(f"To view certificate details, use:\n`openssl crl2pkcs7 -nocrl -certfile {out_path} | openssl  pkcs7 -print_certs | openssl x509 -text -noout`")


# ----- Helpers -----
from cryptography.x509.oid import ExtendedKeyUsageOID

class TLSServerCertificateChecker(BaseCertificateChecker):
    def _check_specific_key_usage(self, key_usage: x509.KeyUsage):
        if not key_usage.digital_signature:
            self._add_issue("KeyUsage does not include digitalSignature", IssueSeverity.ERROR)

        public_key = self.certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if not key_usage.key_encipherment:
                self._add_issue("RSA certificate KeyUsage does not include keyEncipherment", IssueSeverity.ERROR)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if not key_usage.key_agreement:
                self._add_issue("ECC certificate KeyUsage does not include keyAgreement", IssueSeverity.ERROR)

    def _check_specific_extended_key_usage(self, ext_key_usage: x509.ExtendedKeyUsage):
        if ExtendedKeyUsageOID.SERVER_AUTH not in ext_key_usage:
            self._add_issue("ExtendedKeyUsage does not include serverAuth", IssueSeverity.ERROR)

    def _check_specific_subject_alternative_name(self, san: x509.SubjectAlternativeName):
        if not san:
            self._add_issue("SubjectAlternativeName extension is empty", IssueSeverity.ERROR)
        else:
            for name in san:
                if not isinstance(name, (x509.DNSName, x509.IPAddress)):
                    self._add_issue(f"Unauthorized SAN type for TLS server cert: {type(name)}", IssueSeverity.WARNING)

    def _check_specific_subject_common_name_consistency(self, cn_value: str, san: x509.SubjectAlternativeName):
        san_dns_names = [name.value for name in san if isinstance(name, x509.DNSName)]
        if cn_value not in san_dns_names:
            self._add_issue(f"Subject CN '{cn_value}' not found in SubjectAlternativeName", IssueSeverity.WARNING)

    def _check_subject_and_issuer(self):
        super()._check_subject_and_issuer()
        if self.certificate.subject.rfc4514_string() == "":
            san_ext = self.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            if not san_ext.critical:
                self._add_issue("Empty Subject DN requires SubjectAlternativeName extension to be set critical", IssueSeverity.ERROR)
