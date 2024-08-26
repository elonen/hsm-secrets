# csr_utils.py
import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from typing import Union, Optional
from pathlib import Path

from hsm_secrets.config import HSMConfig, HSMOpaqueObject
from hsm_secrets.utils import HsmSecretsCtx, cli_info, cli_warn, open_hsm_session
from hsm_secrets.x509.def_utils import find_cert_def
from hsm_secrets.yubihsm import HSMSession


def load_csr(csr_path: click.Path|str) -> x509.CertificateSigningRequest:
    """Load and validate a CSR from a file or stdin."""
    if csr_path == '-':
        cli_info("Reading CSR from stdin...")
        csr_data = click.get_text_stream('stdin').read().encode()
    else:
        csr_data = Path(str(csr_path)).read_bytes()
    return x509.load_pem_x509_csr(csr_data)


def sign_csr_with_ca(
    ctx: HsmSecretsCtx,
    csr: x509.CertificateSigningRequest,
    ca_id: Union[str, int],
    validity_days: int,
    hash_algorithm: Optional[hashes.HashAlgorithm] = None
) -> x509.Certificate:
    """Sign a CSR with a CA key from the HSM."""
    issuer_cert_def = ctx.conf.find_def(ca_id, HSMOpaqueObject)
    issuer_x509_def = find_cert_def(ctx.conf, issuer_cert_def.id)
    assert issuer_x509_def, f"CA cert ID not found: 0x{issuer_cert_def.id:04x}"

    with open_hsm_session(ctx) as ses:
        issuer_cert = ses.get_certificate(issuer_cert_def)
        issuer_key = ses.get_private_key(issuer_x509_def.key)

        builder = x509.CertificateBuilder(
            issuer_name=issuer_cert.subject,
            subject_name=csr.subject,
            public_key=csr.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.now(),
            not_valid_after=datetime.now() + timedelta(days=validity_days)
        )

        for ext in csr.extensions:
            builder = builder.add_extension(ext.value, critical=ext.critical)

        if hash_algorithm is None:
            hash_algorithm = issuer_cert.signature_hash_algorithm
        if not isinstance(hash_algorithm, (hashes.SHA224, hashes.SHA256, hashes.SHA384, hashes.SHA512)):
            cli_warn(f"WARNING: Unsupported hash algorithm: {hash_algorithm}. Falling back to SHA-256")
            hash_algorithm = hashes.SHA256()

        return builder.sign(private_key=issuer_key, algorithm=hash_algorithm)
