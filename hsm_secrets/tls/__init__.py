from datetime import datetime, timedelta
from pathlib import Path
from typing import cast
import click

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec, ed448, dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
import cryptography.x509.oid as x509_oid
from cryptography.x509.oid import ExtendedKeyUsageOID

import ipaddress

import yubihsm          # type: ignore [import]
import yubihsm.defs     # type: ignore [import]
import yubihsm.objects  # type: ignore [import]

from hsm_secrets.config import HSMKeyID, HSMOpaqueObject, X509CertInfo, X509KeyUsageName
from hsm_secrets.key_adapters import PrivateKeyOrAdapter
from hsm_secrets.utils import HsmSecretsCtx, cli_code_info, cli_confirm, cli_info, cli_warn, open_hsm_session, pass_common_args, submit_cert_for_monitoring
from hsm_secrets.x509.cert_builder import CsrAmendMode, X509CertBuilder, get_issuer_cert_and_key
from hsm_secrets.x509.cert_checker import BaseCertificateChecker, IssueSeverity
from hsm_secrets.x509.def_utils import find_ca_def, merge_x509_info_with_defaults

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
@click.option('--keyfmt', '-f', type=click.Choice(['rsa2048', 'rsa3072', 'rsa4096', 'ed25519', 'ecp256', 'ecp384']), default='ecp384', help="Key format")
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
    issuer_ca_def = None
    issuer_cert_def = None
    if (sign_ca or '').strip().lower() != 'self':
        issuer_cert_def = ctx.conf.find_def(sign_ca or ctx.conf.tls.default_ca_id, HSMOpaqueObject)
        issuer_ca_def = find_ca_def(ctx.conf, issuer_cert_def.id)
        assert issuer_ca_def, f"CA cert ID not found: 0x{issuer_cert_def.id:04x}"

    info = X509CertInfo()
    info.attribs = X509CertInfo.CertAttribs(common_name = common_name)
    info.attribs.common_name = common_name

    ku: set[X509KeyUsageName] = set(['digitalSignature', 'keyEncipherment', 'keyAgreement'])
    info.key_usage = X509CertInfo.KeyUsage(usages = ku, critical = True)

    info.extended_key_usage = X509CertInfo.ExtendedKeyUsage(usages = set(['serverAuth']), critical = False)
    info.validity_days = validity
    if common_name not in (san_dns or []):
        san_dns = [common_name] + list(san_dns or [])   # Add CN to DNS SANs if not already there
    if san_dns or san_ip:
        info.subject_alt_name = X509CertInfo.SubjectAltName(names = {'dns': [], 'ip': []}, critical = False)
        for n in san_dns or []:
            info.subject_alt_name.names['dns'].append(n)
        for n in san_ip or []:
            info.subject_alt_name.names['ip'].append(n)

    merged_info = merge_x509_info_with_defaults(info, ctx.conf)
    merged_info.basic_constraints = X509CertInfo.BasicConstraints(ca=False, path_len=None, critical=False) # end-entity cert

    priv_key: PrivateKeyOrAdapter
    if keyfmt == 'rsa4096':
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif keyfmt == 'rsa3072':
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    elif keyfmt == 'rsa2048':
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
        cli_confirm(f"Files {file_names} already exist. Overwrite?", abort=True)

    builder = X509CertBuilder(ctx.conf, merged_info, priv_key)
    issuer_cert = None
    if issuer_ca_def:
         assert issuer_cert_def
         with open_hsm_session(ctx) as ses:
            issuer_cert = ses.get_certificate(issuer_cert_def)
            issuer_key = ses.get_private_key(issuer_ca_def.key)
            signed_cert = builder.build_and_sign(issuer_cert, issuer_key, issuer_ca_def.crl_distribution_points)
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

    # Submit the certificate to the configured URL, if set (only after successful write)
    submit_cert_for_monitoring(ctx, crt_pem, f"{common_name}-tls-server", "tls")

    if issuer_cert and chain_pem:
        chain_file.write_bytes(chain_pem)
        cli_info(f"Chain (bundle) written to: {chain_file}")

    cli_info("")
    cli_code_info(f"To view certificate, use:\n`openssl crl2pkcs7 -nocrl -certfile {cer_file} | openssl  pkcs7 -print_certs | openssl x509 -text -noout`")

# ----- CSR from TLS -----

@cmd_tls.command('recreate-from-tls')
@pass_common_args
@click.argument('url', type=str, required=True, metavar='<https://host:port or tls://host:port>')
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True), help="Output CSR filename (default: <hostname>.csr.pem)")
@click.option('--keyfmt', '-f', type=click.Choice(['rsa2048', 'rsa3072', 'rsa4096', 'ed25519', 'ecp256', 'ecp384']), default='ecp384', help="Key format for new CSR")
@click.option('--validity', '-v', default=365, help="Validity period in days for signing command")
def recreate_from_tls(ctx: HsmSecretsCtx, url: str, out: str|None, keyfmt: str, validity: int):
    """Recreate a certificate by extracting fields from a TLS server

    TYPICAL USAGE:

        $ hsm-secrets tls recreate-from-tls https://example.com -o example.com.csr.pem

    Connects to a TLS server, extracts the certificate fields (CN, SANs, etc.),
    generates a NEW private key and CSR with the same fields, and prints out
    signing instructions. This creates a completely new certificate with a
    new private key.

    The URL can be either https://host:port or tls://host:port format.
    If port is not specified, defaults to 443.
    """
    import ssl
    import socket
    from urllib.parse import urlparse

    # Parse the URL
    if url.startswith('tls://'):
        url = url.replace('tls://', 'https://', 1)

    if not url.startswith('https://'):
        url = 'https://' + url

    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443

    if not host:
        raise click.ClickException("Invalid URL: could not extract hostname")

    cli_info(f"Connecting to {host}:{port} to retrieve certificate...")

    # Connect to the server and get certificate
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                peer_cert_der = ssock.getpeercert(binary_form=True)  # Get the leaf certificate in DER format
                if peer_cert_der is None:
                    raise click.ClickException(f"Could not retrieve certificate from {host}:{port}")
                server_cert = x509.load_der_x509_certificate(peer_cert_der)
    except Exception as e:
        raise click.ClickException(f"Failed to connect to {host}:{port}: {e}")

    cli_info(f"Retrieved certificate for: {server_cert.subject.rfc4514_string()}")

    # Extract certificate fields
    cn = None
    san_dns = []
    san_ip = []

    # Get CN from subject
    for attr in server_cert.subject:
        if attr.oid == x509_oid.NameOID.COMMON_NAME:
            cn = attr.value
            break

    # Get SANs
    try:
        san_ext = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for san in san_ext.value:
            if isinstance(san, x509.DNSName):
                san_dns.append(san.value)
            elif isinstance(san, x509.IPAddress):
                san_ip.append(str(san.value))
    except x509.ExtensionNotFound:
        pass

    if not cn and not san_dns:
        raise click.ClickException("Certificate has no Common Name or DNS Subject Alternative Names")

    # Determine output filename
    out_path = Path(out) if out else Path(f"{host}.csr.pem")
    key_path = out_path.with_suffix('.key.pem')

    # Check for existing files
    existing_files = [file for file in [out_path, key_path] if file.exists()]
    if existing_files:
        file_names = ", ".join(click.style(str(file), fg='cyan') for file in existing_files)
        cli_confirm(f"Files {file_names} already exist. Overwrite?", abort=True)

    # Generate new private key
    priv_key: PrivateKeyOrAdapter
    if keyfmt == 'rsa4096':
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif keyfmt == 'rsa3072':
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    elif keyfmt == 'rsa2048':
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif keyfmt == 'ed25519':
        priv_key = ed25519.Ed25519PrivateKey.generate()
    elif keyfmt == 'ecp256':
        priv_key = ec.generate_private_key(ec.SECP256R1())
    elif keyfmt == 'ecp384':
        priv_key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise click.ClickException(f"Unsupported key format: {keyfmt}")

    # Build certificate info for CSR
    info = X509CertInfo()
    info.attribs = X509CertInfo.CertAttribs(common_name=cn or san_dns[0])

    # Set key usage for TLS server cert
    ku: set[X509KeyUsageName] = set(['digitalSignature', 'keyEncipherment', 'keyAgreement'])
    info.key_usage = X509CertInfo.KeyUsage(usages=ku, critical=True)
    info.extended_key_usage = X509CertInfo.ExtendedKeyUsage(usages=set(['serverAuth']), critical=False)

    # Add all DNS names to SANs (including CN if not already present)
    all_dns = list(san_dns)
    if cn and cn not in all_dns:
        all_dns.insert(0, cn)

    if all_dns or san_ip:
        info.subject_alt_name = X509CertInfo.SubjectAltName(names={'dns': all_dns, 'ip': san_ip}, critical=False)

    # Merge with defaults and generate CSR
    merged_info = merge_x509_info_with_defaults(info, ctx.conf)
    merged_info.basic_constraints = X509CertInfo.BasicConstraints(ca=False, path_len=None, critical=False)

    builder = X509CertBuilder(ctx.conf, merged_info, priv_key)
    csr = builder.generate_csr()

    # Write key and CSR files
    key_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

    key_path.write_bytes(key_pem)
    out_path.write_bytes(csr_pem)

    cli_info(f"Private key written to: {key_path}")
    cli_info(f"CSR written to: {out_path}")

    # Show certificate details
    cli_info("")
    cli_info("Certificate details extracted:")
    if cn:
        cli_info(f"  Common Name: {cn}")
    if san_dns:
        cli_info(f"  DNS SANs: {', '.join(san_dns)}")
    if san_ip:
        cli_info(f"  IP SANs: {', '.join(san_ip)}")

    cli_info("")
    cli_code_info(f"To view the CSR details, use:\n`openssl req -in {out_path} -text -noout`")

    # Generate tls sign command
    sign_cmd_parts = ['hsm-secrets', 'tls', 'sign', str(out_path)]
    sign_cmd_parts.extend(['--validity', str(validity)])
    sign_cmd_parts.extend(['--out', str(out_path.with_suffix('.cer.pem'))])

    sign_cmd = ' '.join(sign_cmd_parts)

    cli_info("")
    cli_code_info(f"To sign this CSR with your CA, run:\n`{sign_cmd}`")
    cli_info("")
    cli_info("⚠️  Remember to install BOTH the new certificate AND the new private key:")
    cli_info(f"   Certificate: {out_path.with_suffix('.cer.pem')}")
    cli_info(f"   Private key: {key_path}")

# ----- Resign from TLS -----

@cmd_tls.command('resign-from-tls')
@pass_common_args
@click.argument('url', type=str, required=True, metavar='<https://host:port or tls://host:port>')
@click.option('--out', '-o', required=False, type=click.Path(exists=False, dir_okay=False, resolve_path=True), help="Output certificate filename (default: <hostname>.cer.pem)")
@click.option('--validity', '-v', default=365, help="Validity period in days")
def resign_from_tls(ctx: HsmSecretsCtx, url: str, out: str|None, validity: int):
    """Create a signed certificate by extracting everything from a TLS server

    TYPICAL USAGE:

        $ hsm-secrets tls resign-from-tls https://example.com -o new.cer.pem

    Connects to a TLS server, extracts BOTH the public key and certificate fields
    (CN, SANs, etc.), and creates a signed certificate directly with your HSM CA.
    This reuses the server's existing public key but signs it with your CA.

    The URL can be either https://host:port or tls://host:port format.
    If port is not specified, defaults to 443.

    NOTE: This reuses the server's existing public key - perfect for re-signing
    an existing certificate with your own CA without needing private key access.
    """
    import ssl
    import socket
    import ipaddress
    from urllib.parse import urlparse

    # Parse the URL
    if url.startswith('tls://'):
        url = url.replace('tls://', 'https://', 1)

    if not url.startswith('https://'):
        url = 'https://' + url

    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443

    if not host:
        raise click.ClickException("Invalid URL: could not extract hostname")

    cli_info(f"Connecting to {host}:{port} to retrieve certificate and public key...")

    # Connect to the server and get certificate
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                peer_cert_der = ssock.getpeercert(binary_form=True)
                if peer_cert_der is None:
                    raise click.ClickException(f"Could not retrieve certificate from {host}:{port}")
                server_cert = x509.load_der_x509_certificate(peer_cert_der)
    except Exception as e:
        raise click.ClickException(f"Failed to connect to {host}:{port}: {e}")

    cli_info(f"Retrieved certificate from: {server_cert.subject.rfc4514_string()}")

    # Extract the public key from the server's certificate
    server_public_key = server_cert.public_key()
    cli_info(f"Extracted public key: {type(server_public_key).__name__}")

    # Extract certificate fields from server
    cn = None
    san_dns = []
    san_ip = []

    # Get CN from server cert subject
    for attr in server_cert.subject:
        if attr.oid == x509_oid.NameOID.COMMON_NAME:
            cn = attr.value
            break

    # Get SANs from server cert
    try:
        san_ext = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for san in san_ext.value:
            if isinstance(san, x509.DNSName):
                san_dns.append(san.value)
            elif isinstance(san, x509.IPAddress):
                san_ip.append(str(san.value))
    except x509.ExtensionNotFound:
        pass

    if not cn and not san_dns:
        raise click.ClickException("Server certificate has no Common Name or DNS Subject Alternative Names")

    # Determine output filename
    out_path = Path(out) if out else Path(f"{host}.cer.pem")

    # Check for existing files
    if out_path.exists():
        cli_confirm(f"Output file '{out_path}' already exists. Overwrite?", abort=True)

    # Build certificate info using server's certificate fields exactly
    info = X509CertInfo()

    # Use server's original subject (preserving all fields)
    info.attribs = X509CertInfo.CertAttribs(common_name=cn or san_dns[0])
    # Copy additional subject attributes from server certificate
    for attr in server_cert.subject:
        if attr.oid == x509_oid.NameOID.ORGANIZATION_NAME:
            info.attribs.organization = attr.value
        elif attr.oid == x509_oid.NameOID.LOCALITY_NAME:
            info.attribs.locality = attr.value
        elif attr.oid == x509_oid.NameOID.STATE_OR_PROVINCE_NAME:
            info.attribs.state = attr.value
        elif attr.oid == x509_oid.NameOID.COUNTRY_NAME:
            info.attribs.country = attr.value

    # Set key usage for TLS server cert
    ku: set[X509KeyUsageName] = set(['digitalSignature', 'keyEncipherment', 'keyAgreement'])
    info.key_usage = X509CertInfo.KeyUsage(usages=ku, critical=True)
    info.extended_key_usage = X509CertInfo.ExtendedKeyUsage(usages=set(['serverAuth']), critical=False)
    info.validity_days = validity

    # Use server's exact SANs
    if san_dns or san_ip:
        info.subject_alt_name = X509CertInfo.SubjectAltName(names={'dns': san_dns, 'ip': san_ip}, critical=False)

    # Build certificate directly using server's public key
    info.basic_constraints = X509CertInfo.BasicConstraints(ca=False, path_len=None, critical=False)

    # Find default CA
    ca_cert_id = ctx.conf.tls.default_ca_id
    ca_def = find_ca_def(ctx.conf, ca_cert_id)
    if not ca_def:
        raise click.ClickException(f"Default CA '{ca_cert_id}' not found in config")

    # Sign with HSM-backed CA using server's public key directly
    with open_hsm_session(ctx) as ses:
        issuer_cert, issuer_key = get_issuer_cert_and_key(ctx, ses, ca_cert_id)

        # Build certificate directly using cryptography library
        from datetime import datetime, timedelta, timezone
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(server_cert.subject)  # Use server's exact subject
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.public_key(server_public_key)  # Use server's exact public key
        builder = builder.serial_number(x509.random_serial_number())
        now = datetime.now(timezone.utc)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=validity))

        # Add Subject Alternative Names from server
        if san_dns or san_ip:
            san_names: list[x509.GeneralName] = []
            for dns_name in san_dns:
                san_names.append(x509.DNSName(dns_name))
            for ip_addr in san_ip:
                try:
                    san_names.append(x509.IPAddress(ipaddress.ip_address(ip_addr)))
                except ValueError:
                    san_names.append(x509.IPAddress(ipaddress.ip_network(ip_addr, strict=False)))
            builder = builder.add_extension(x509.SubjectAlternativeName(san_names), critical=False)

        # Add standard TLS server certificate extensions
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509_oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)

        # Add Subject Key Identifier and Authority Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_public_key), critical=False)
        issuer_pubkey = cast('rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey | dsa.DSAPublicKey', issuer_cert.public_key())
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pubkey), critical=False)

        # Add CRL distribution points if configured
        if ca_def.crl_distribution_points:
            dps = [x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            ) for url in ca_def.crl_distribution_points]
            builder = builder.add_extension(x509.CRLDistributionPoints(dps), critical=False)

        # Sign the certificate
        from hsm_secrets.x509.cert_builder import sign_hash_algo_for_key
        signed_cert = builder.sign(issuer_key, sign_hash_algo_for_key(issuer_key))

    TLSServerCertificateChecker(signed_cert).check_and_show_issues()

    # Save the signed certificate
    cert_pem = signed_cert.public_bytes(encoding=serialization.Encoding.PEM)
    out_path.write_bytes(cert_pem)

    cli_info(f"Signed certificate saved to: {out_path}")

    # Submit the certificate to the configured URL, if set (only after successful write)
    submit_cert_for_monitoring(ctx, cert_pem, f"{host}-tls-resign", "tls")

    # Show certificate details
    cli_info("")
    cli_info("Server certificate details copied:")
    cli_info(f"  Subject: {server_cert.subject.rfc4514_string()}")
    if san_dns:
        cli_info(f"  DNS SANs: {', '.join(san_dns)}")
    if san_ip:
        cli_info(f"  IP SANs: {', '.join(san_ip)}")
    cli_info(f"  Public key: {type(server_public_key).__name__}")

    cli_info("")
    cli_code_info(f"To view the certificate details, use:\n`openssl x509 -in {out_path} -text -noout`")
    cli_info("")
    cli_info("✅ Certificate ready - contains server's exact public key and subject")

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
    template = X509CertInfo(
        basic_constraints = X509CertInfo.BasicConstraints(ca=False, path_len=None, critical=False), # end-entity cert
        key_usage = X509CertInfo.KeyUsage(usages = {'digitalSignature', 'keyEncipherment', 'keyAgreement'}, critical = True),
        extended_key_usage = X509CertInfo.ExtendedKeyUsage(usages = {'serverAuth'}, critical = False),
        validity_days = validity
    )

    # Add DNS SAN from CN
    if cn := csr_obj.subject.get_attributes_for_oid(x509_oid.NameOID.COMMON_NAME):
        template.subject_alt_name = X509CertInfo.SubjectAltName(names = {'dns': [str(cn[0].value)]}, critical = False)
    else:
        cli_warn("WARNING: CSR does not contain a Common Name (CN) field. SubjectAltName will be empty")

    # Find issuer def
    ca_cert_id = ctx.conf.find_def(ca or ctx.conf.tls.default_ca_id, HSMOpaqueObject).id
    ca_def = find_ca_def(ctx.conf, ca_cert_id)
    if not ca_def:
        raise click.ClickException(f"CA '{ca_cert_id}' not found in config")

    # Sign the CSR with HSM-backed CA
    with open_hsm_session(ctx) as ses:
        issuer_cert, issuer_key = get_issuer_cert_and_key(ctx, ses, ca_cert_id)
        builder = X509CertBuilder(ctx.conf, template, csr_obj)
        signed_cert = builder.amend_and_sign_csr(
            issuer_cert, issuer_key,
            validity_days = validity,
            crl_urls = ca_def.crl_distribution_points,
            amend_sans = CsrAmendMode.ADD,
            amend_extended_key_usage = CsrAmendMode.ADD,
            amend_key_usage = CsrAmendMode.REPLACE
        )

    TLSServerCertificateChecker(signed_cert).check_and_show_issues()

    # Save the signed certificate
    out_path = Path(str(out)) if out else Path(str(csr)).with_suffix('.cer.pem')
    if out_path.exists():
        cli_confirm(f"Output file '{out_path}' already exists. Overwrite?", abort=True)

    cert_pem = signed_cert.public_bytes(encoding=serialization.Encoding.PEM)
    out_path.write_bytes(cert_pem)

    cli_info(f"Signed certificate saved to: {out_path}")

    # Submit the certificate to the configured URL, if set (only after successful write)
    csr_path = Path(str(csr))
    submit_cert_for_monitoring(ctx, cert_pem, f"{csr_path.stem}-tls-signed", "tls")
    cli_code_info(f"To view certificate details, use:\n`openssl crl2pkcs7 -nocrl -certfile {out_path} | openssl  pkcs7 -print_certs | openssl x509 -text -noout`")


# ----- Helpers -----

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
