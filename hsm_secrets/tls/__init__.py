import datetime
from pathlib import Path
import click

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import cryptography.x509

import yubihsm          # type: ignore [import]
import yubihsm.defs     # type: ignore [import]
import yubihsm.objects  # type: ignore [import]

from hsm_secrets.config import HSMOpaqueObject, X509CertAttribs, X509Info
from hsm_secrets.key_adapters import PrivateKeyOrAdapter, make_private_key_adapter
from hsm_secrets.utils import HsmSecretsCtx, cli_code_info, cli_info, cli_warn, open_hsm_session, pass_common_args
from hsm_secrets.x509.cert_builder import X509CertBuilder
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
@click.option('--sign-crt', '-s', type=str, required=False, help="CA ID (hex) or label to sign with, or 'self'. Default: use config", default=None)
def server_cert(ctx: HsmSecretsCtx, out: click.Path, common_name: str, san_dns: list[str], san_ip: list[str], validity: int, keyfmt: str, sign_crt: str):
    """Create a TLS server certificate + key

    TYPICAL USAGE:

        $ hsm-secrets tls server-cert -o wiki.example.com.pem -c wiki.example.com -d intraweb.example.com

    Create a new TLS server certificate for the given CN and (optional) SANs.
    Basic name fields are read from the config file (country, org, etc.)

    If --sign-crt is 'self', the certificate will be self-signed instead
    of signing with a HSM-backed CA.

    The --out option is used as a base filename, and the key, csr, and cert files
    written with the extensions '.key.pem', '.csr.pem', and '.cer.pem' respectively.
    """
    # Find the issuer CA definition
    issuer_x509_def = None
    issuer_cert_def = None
    if (sign_crt or '').strip().lower() != 'self':
        issuer_cert_def = ctx.conf.find_def(sign_crt or ctx.conf.tls.default_ca_id, HSMOpaqueObject)
        issuer_x509_def = find_cert_def(ctx.conf, issuer_cert_def.id)
        assert issuer_x509_def, f"CA cert ID not found: 0x{issuer_cert_def.id:04x}"

    info = X509Info()
    info.attribs = X509CertAttribs(common_name = common_name)
    info.attribs.common_name = common_name
    info.key_usage = set(['digitalSignature', 'keyEncipherment', 'keyAgreement'])
    info.extended_key_usage = set(['serverAuth'])
    info.validity_days = validity
    if san_dns or san_ip:
        info.attribs.subject_alt_names = {'dns': [], 'ip': []}
        for n in san_dns or []:
            info.attribs.subject_alt_names['dns'].append(n)
        for n in san_ip or []:
            info.attribs.subject_alt_names['ip'].append(n)

    merged_info = merge_x509_info_with_defaults(info, ctx.conf)
    merged_info.path_len = None
    merged_info.ca = False

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
            assert isinstance(issuer_cert_def, HSMOpaqueObject)
            issuer_cert = ses.get_certificate(issuer_cert_def)
            issuer_key = ses.get_private_key(issuer_x509_def.key)
            signed_cert = builder.generate_cross_signed_intermediate_cert([issuer_cert], [issuer_key])[0]
            cli_info(f"Signed with CA cert 0x{issuer_cert_def.id:04x}: {issuer_cert.subject}")
    else:
        signed_cert = builder.generate_self_signed_cert()
        cli_warn("WARNING: Self-signed certificate, please sign the CSR manually")
        cli_info("")

    key_pem = priv_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
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
    cli_code_info(f"To view certificate details, use:\n`openssl crl2pkcs7 -nocrl -certfile {cer_file} | openssl  pkcs7 -print_certs | openssl x509 -text -noout`")

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
    if csr == '-':
        cli_info("Reading CSR from stdin...")
        csr_path = Path('-')
        csr_data = click.get_text_stream('stdin').read().encode()
    else:
        csr_path = Path(str(csr))
        csr_data = csr_path.read_bytes()

    csr_obj = cryptography.x509.load_pem_x509_csr(csr_data)

    # Find the issuer CA definition
    issuer_cert_def = ctx.conf.find_def(ca or ctx.conf.tls.default_ca_id, HSMOpaqueObject)
    issuer_x509_def = find_cert_def(ctx.conf, issuer_cert_def.id)
    assert issuer_x509_def, f"CA cert ID not found: 0x{issuer_cert_def.id:04x}"

    if out:
        out_path = Path(str(out))
    else:
        out_path = Path(str(csr_path).replace('.csr.', '.')).with_suffix('.cer.pem')
    if out_path.exists():
        click.confirm(f"Output file '{out_path}' already exists. Overwrite?", abort=True, err=True)

    with open_hsm_session(ctx) as ses:
        assert isinstance(issuer_cert_def, HSMOpaqueObject)
        issuer_cert = ses.get_certificate(issuer_cert_def)
        issuer_key = ses.get_private_key(issuer_x509_def.key)

        builder = cryptography.x509.CertificateBuilder(
            issuer_name = issuer_cert.subject,
            subject_name = csr_obj.subject,
            public_key = csr_obj.public_key(),
            serial_number = cryptography.x509.random_serial_number(),
            not_valid_before = datetime.datetime.utcnow(),
            not_valid_after = datetime.datetime.utcnow() + datetime.timedelta(days=validity))

        for ext in csr_obj.extensions:
            builder = builder.add_extension(ext.value, critical=ext.critical)

        hash_algo = issuer_cert.signature_hash_algorithm
        if not isinstance(hash_algo, (hashes.SHA224, hashes.SHA256, hashes.SHA384, hashes.SHA512, hashes.SHA3_224, hashes.SHA3_256, hashes.SHA3_384, hashes.SHA3_512)):
            cli_warn(f"WARNING: Unsupported hash algorithm: {hash_algo}. Falling back to SHA-256")
            hash_algo = hashes.SHA256()

        signed_cer = builder.sign(private_key=issuer_key, algorithm=hash_algo)
        cli_info(f"Signed with CA cert 0x{issuer_cert_def.id:04x}: {issuer_cert.subject}")

        crt_pem = signed_cer.public_bytes(encoding=serialization.Encoding.PEM)
        out_path.write_bytes(crt_pem)

        cli_info(f"Cert written to: {out_path}")
        cli_code_info(f"To view certificate details, use:\n`openssl crl2pkcs7 -nocrl -certfile {out_path} | openssl  pkcs7 -print_certs | openssl x509 -text -noout`")
