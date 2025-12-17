from pathlib import Path
import click
import subprocess
from asn1crypto import cms, algos, x509, core, pem   # type: ignore [import]
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from hsm_secrets.config import HSMOpaqueObject
from hsm_secrets.utils import (
    HsmSecretsCtx,
    cli_code_info,
    cli_info,
    open_hsm_session,
    pass_common_args,
)
from hsm_secrets.x509.cert_builder import get_issuer_cert_and_key

from typing import Any, Optional, List, Tuple, Union, cast

SZ_OID_CTL = '1.3.6.1.4.1.311.10.1' # PKCS #7 ContentType OID for Certificate Trust List (CTL) szOID_CTL
SPC_INDIRECT_DATA_OBJID = '1.3.6.1.4.1.311.2.1.4'  # SpcIndirectDataContent OID
SPC_STATEMENT_TYPE_OBJID = '1.3.6.1.4.1.311.2.1.11'  # SpcStatementType OID
SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID = '1.3.6.1.4.1.311.2.1.21'  # Individual Code Signing OID


@click.group()
@click.pass_context
def cmd_codesign(ctx: click.Context) -> None:
    """Code signing operations"""
    ctx.ensure_object(dict)


def _sign_authenticode_hash(ctx: HsmSecretsCtx, hashfile: str, out: Optional[str], ca: Optional[str]) -> None:
    """Core implementation of Authenticode hash signing.

    This function signs a hash file extracted by osslsigncode and writes the signed result.
    """
    # Read and parse the input data
    content_info: cms.ContentInfo = _read_input_data(hashfile)

    # Extract the spcIndirectDataContent
    spc_indirect_data: core.Sequence = _extract_spc_indirect_data(content_info)

    # Extract the digest algorithm and compute the digest
    digest_info_der: bytes = spc_indirect_data[1].dump()
    digest_info: algos.DigestInfo = algos.DigestInfo.load(digest_info_der)
    digest_algorithm_oid: core.ObjectIdentifier = digest_info['digest_algorithm']['algorithm']  # type: ignore

    digest_value, hash_algorithm = _compute_digest(spc_indirect_data, digest_algorithm_oid)
    signing_time: datetime = datetime.now(timezone.utc)

    # Build the signed attributes
    signed_attrs: cms.CMSAttributes = _build_signed_attributes(digest_value, signing_time)

    # Connect HSM and sign
    ca_cert_id = ctx.conf.find_def(ca or ctx.conf.codesign.default_cert_id, HSMOpaqueObject).id
    with open_hsm_session(ctx) as ses:
        signer_cert_orig, signer_private_key = get_issuer_cert_and_key(ctx, ses, ca_cert_id)

        ca_der = signer_cert_orig.public_bytes(serialization.Encoding.DER)
        signer_cert: x509.Certificate = x509.Certificate.load(ca_der)

        if not isinstance(signer_private_key, rsa.RSAPrivateKey):
            raise click.ClickException("Only RSA private keys are supported for code signing for now")

        # Build the SignerInfo structure
        signer_info: cms.SignerInfo = _build_signer_info(
            signer_cert,
            signer_private_key,
            signed_attrs,
            digest_algorithm_oid,
            hash_algorithm,
        )

    # Assemble the SignedData structure
    certificates: List[x509.Certificate] = [signer_cert]
    signed_data: cms.SignedData = _assemble_signed_data(
        spc_indirect_data,
        digest_algorithm_oid,
        certificates,
        signer_info,
    )

    # Wrap in ContentInfo
    content_info = cms.ContentInfo({'content_type': 'signed_data', 'content': signed_data})

    _write_output(content_info, hashfile, out)


@cmd_codesign.command('sign-osslsigncode-hash')
@pass_common_args
@click.argument('hashfile', type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=True), default='-', required=True, metavar='<HASHFILE>')
@click.option('--out', '-o', required=False, type=click.Path(dir_okay=False, resolve_path=True), help="Output filename (default: deduce from input)", default=None)
@click.option('--ca', '-c', type=str, required=False, help="CA ID (hex) or label to sign with. Default: use config", default=None)
def sign_osslsigncode_hash(
    ctx: HsmSecretsCtx,
    hashfile: str,
    out: Optional[str],
    ca: Optional[str]
) -> None:
    """Sign a Microsoft Authenticode hash from `osslsigncode`

    Usage:

    1) Generate the hashfile with osslsigncode: `osslsigncode extract-data -h sha256 -in <bin.exe> -out <bin.req>`

    2) Sign the request with this command

    3) Embed the signature: `osslsigncode attach-signature -sigin <bin.req.signed> -CAfile <cert.chain> -in <bin.exe> -out <bin-signed.exe>`

    The `cert.chain` file should contain the full certificate chain, from issuer up to the root CA.
    Both input and output are ASN.1 structures. Input can be DER or PEM encoded, output is DER.
    """
    _sign_authenticode_hash(ctx, hashfile, out, ca)


# ----- Helper functions -----


def _get_hash_algorithm(
    digest_algorithm_oid: core.ObjectIdentifier,
) -> hashes.HashAlgorithm:
    """Map OID to hash algorithm."""
    oid: str = digest_algorithm_oid.dotted
    if oid == '1.3.14.3.2.26':
        return hashes.SHA1()
    elif oid == '2.16.840.1.101.3.4.2.1':
        return hashes.SHA256()
    elif oid == '2.16.840.1.101.3.4.2.2':
        return hashes.SHA384()
    elif oid == '2.16.840.1.101.3.4.2.3':
        return hashes.SHA512()
    else:
        raise ValueError(f"Unsupported digest algorithm OID: {oid}")


def _read_input_data(hashfile: str) -> cms.ContentInfo:
    """Read and parse the input data."""
    if hashfile == '-':
        data: bytes = click.get_binary_stream('stdin').read()
    else:
        data = Path(hashfile).read_bytes()

    # Detect and handle PEM encoding, or assume DER
    if pem.detect(data):
        _type_name, _headers, der_bytes = pem.unarmor(data)
    else:
        der_bytes = data

    return cms.ContentInfo.load(der_bytes)


def _extract_spc_indirect_data(content_info: cms.ContentInfo) -> core.Sequence:
    """Extract the spcIndirectDataContent from ContentInfo."""
    if content_info['content_type'].native != 'signed_data':
        raise click.ClickException("Input data is not a PKCS#7 SignedData structure")

    signed_data: cms.SignedData = cast(cms.SignedData, content_info['content'])
    encap_content_info = cast(cms.EncapsulatedContentInfo, signed_data['encap_content_info'])

    if cast(core.ObjectIdentifier, encap_content_info['content_type']).dotted != SPC_INDIRECT_DATA_OBJID:
        raise click.ClickException("Encapsulated content is not SPC_INDIRECT_DATA_OBJID")

    spc_indirect_data: core.Sequence = encap_content_info['content'].parsed     # type: ignore
    if spc_indirect_data is None:
        raise click.ClickException("Encapsulated content is missing or cannot be parsed")

    return spc_indirect_data


def _compute_digest(
    spc_indirect_data: core.Asn1Value, digest_algorithm_oid: core.ObjectIdentifier
) -> Tuple[bytes, hashes.HashAlgorithm]:
    """Compute the digest over the DER-encoded data field."""
    assert spc_indirect_data.contents is not None
    spc_data_der: bytes = spc_indirect_data.contents
    hash_algorithm: hashes.HashAlgorithm = _get_hash_algorithm(digest_algorithm_oid)
    digest = hashes.Hash(hash_algorithm)
    digest.update(spc_data_der)
    digest_value: bytes = digest.finalize()
    return digest_value, hash_algorithm


def _build_signed_attributes(digest_value: bytes, signing_time: datetime) -> cms.CMSAttributes:
    """Build the signed attributes for the SignerInfo."""
    class OIDSequence(core.Sequence):
        _fields = [('oid', core.ObjectIdentifier)]

    content_type_attr = cms.CMSAttribute(
        {
            'type': 'content_type',
            'values': cms.SetOfContentType([cms.ContentType(SZ_OID_CTL)]),
        }
    )
    signing_time_attr = cms.CMSAttribute(
        {
            'type': 'signing_time',
            'values': cms.SetOfTime([cms.Time({'utc_time': signing_time})]),
        }
    )
    ms_crypto_attr = cms.CMSAttribute(
        {
            'type': SPC_STATEMENT_TYPE_OBJID,
            'values': cms.SetOfAny(
                [OIDSequence({'oid': SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID})]
            ),
        }
    )
    message_digest_attr = cms.CMSAttribute(
        {
            'type': 'message_digest',
            'values': cms.SetOfOctetString([core.OctetString(digest_value)]),
        }
    )
    signed_attrs = cms.CMSAttributes(
        [content_type_attr, signing_time_attr, ms_crypto_attr, message_digest_attr]
    )
    return signed_attrs


def _build_signer_info(
    signer_cert: x509.Certificate,
    signer_private_key: rsa.RSAPrivateKey,
    signed_attrs: cms.CMSAttributes,
    digest_algorithm_oid: core.ObjectIdentifier,
    hash_algorithm: hashes.HashAlgorithm,
) -> cms.SignerInfo:
    """Build the SignerInfo structure."""
    issuer_and_serial = cms.IssuerAndSerialNumber(
        {'issuer': signer_cert.issuer, 'serial_number': signer_cert.serial_number}
    )

    signature: bytes = signer_private_key.sign(
        signed_attrs.dump(),
        padding.PKCS1v15(),
        hash_algorithm
    )

    signer_info = cms.SignerInfo(
        {
            'version': 'v1',
            'sid': cms.SignerIdentifier(
                {'issuer_and_serial_number': issuer_and_serial}
            ),
            'digest_algorithm': {
                'algorithm': digest_algorithm_oid,
                'parameters': core.Null(),
            },
            'signed_attrs': signed_attrs,
            'signature_algorithm': {
                'algorithm': 'rsassa_pkcs1v15',
                'parameters': core.Null(),
            },
            'signature': cms.OctetString(signature),
            'unsigned_attrs': None,
        }
    )
    return signer_info


def _assemble_signed_data(
    spc_indirect_data: core.Asn1Value,
    digest_algorithm_oid: core.ObjectIdentifier,
    certificates: List[x509.Certificate],
    signer_info: cms.SignerInfo,
) -> cms.SignedData:
    """Assemble the SignedData structure."""
    signed_data = cms.SignedData(
        {
            'version': 'v1',
            'digest_algorithms': [
                {'algorithm': digest_algorithm_oid, 'parameters': core.Null()}
            ],
            'encap_content_info': {
                'content_type': SPC_INDIRECT_DATA_OBJID,
                'content': spc_indirect_data,
            },
            'certificates': certificates,
            'signer_infos': [signer_info],
        }
    )
    return signed_data


def _write_output(content_info: cms.ContentInfo, hashfile: str, out: Optional[str]) -> None:
    """Write the signed data to the output file."""
    if out:
        out_path = Path(out)
    else:
        out_path = Path(hashfile).with_suffix(".signed" + Path(hashfile).suffix)

    out_path.write_bytes(content_info.dump())

    cli_code_info(f"Signed code signature (ASN1 DER) saved to: `{out_path}`")
    cli_info("Attach it to your PE executable with:")
    cli_code_info(
        f"  `osslsigncode attach-signature -sigin '{out_path.name}' -CAfile MYCERT.chain.pem -in MYBIN.exe -out MYBIN.signed.exe`"
    )


@cmd_codesign.command('sign')
@pass_common_args
@click.argument('binary', type=click.Path(exists=True, dir_okay=False, resolve_path=True), metavar='<BINARY>')
@click.option('--out', '-o', required=False, type=click.Path(dir_okay=False, resolve_path=True), help="Output filename (default: deduce from input)", default=None)
@click.option('--ca', '-c', type=str, required=False, help="CA ID (hex) or label to sign with. Default: use config", default=None)
@click.option('--cert-chain', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=False, help="Certificate chain file (PEM format). If not provided, will be extracted from HSM", metavar='<CERT_CHAIN>')
@click.option('--crl-file', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=False, help="CRL file (PEM format, optional)", metavar='<CRL_FILE>')
@click.option('--hash-alg', type=click.Choice(['sha256', 'sha384', 'sha512', 'sha1'], case_sensitive=False), default='sha256', help="Hash algorithm to use")
@click.option('--timestamp', type=str, required=False, help="Timestamp server URL (optional)")
def sign_complete(
    ctx: HsmSecretsCtx,
    binary: str,
    out: Optional[str],
    ca: Optional[str],
    cert_chain: Optional[str],
    crl_file: Optional[str],
    hash_alg: str,
    timestamp: Optional[str]
) -> None:
    """Sign a PE executable end-to-end with automatic hash extraction and signature integration

    This command orchestrates the complete code signing workflow:

    1) Extract the hash from the binary using osslsigncode
    2) Sign the hash using the HSM
    3) Attach the signature back to the binary

    Required: osslsigncode must be installed and in your PATH

    If --cert-chain is not provided, the certificate chain will be automatically
    extracted from the HSM (signing cert + its issuer).
    """
    binary_path = Path(binary)
    out_path = Path(out) if out else binary_path.with_stem(f"{binary_path.stem}.signed")

    # Check if cert chain is provided
    if not cert_chain:
        # Get the codesign certificate definition
        ca_cert_def = ctx.conf.find_def(ca or ctx.conf.codesign.default_cert_id, HSMOpaqueObject)

        # Find the issuer certificate by looking up who signed this cert
        from hsm_secrets.x509.def_utils import find_ca_def
        ca_x509_def = find_ca_def(ctx.conf, ca_cert_def.id)

        if not ca_x509_def:
            raise click.ClickException(f"Could not find CA definition for certificate {hex(ca_cert_def.id)}")

        # Find the issuer cert ID from the signed_certs list
        issuer_cert_id = None
        for cert_entry in ca_x509_def.signed_certs:
            if cert_entry.id == ca_cert_def.id and hasattr(cert_entry, 'sign_by'):
                issuer_cert_id = cert_entry.sign_by
                break

        if not issuer_cert_id:
            raise click.ClickException(f"Could not determine issuer for certificate {ca_cert_def.label}")

        # Generate chain filename from the cert label
        chain_file = f"{ca_cert_def.label}.chain.pem"

        cli_info("Certificate chain not provided. Extract it first with:")
        cli_code_info(f"  `hsm-secrets x509 cert get {hex(ca_cert_def.id)} {hex(issuer_cert_id)} --bundle {chain_file}`")
        cli_info("")
        cli_info("Then run the sign command again with --cert-chain:")

        # Build the command to show the user
        cmd_parts = ["hsm-secrets", "codesign", "sign", str(binary)]
        cmd_parts.extend(["--cert-chain", chain_file])
        if ca:
            cmd_parts.extend(["--ca", ca])
        if out:
            cmd_parts.extend(["--out", out])
        if crl_file:
            cmd_parts.extend(["--crl-file", crl_file])
        if hash_alg != 'sha256':
            cmd_parts.extend(["--hash-alg", hash_alg])
        if timestamp:
            cmd_parts.extend(["--timestamp", timestamp])

        cli_code_info(f"  `{' '.join(cmd_parts)}`")
        return

    cert_chain_path = Path(cert_chain)

    # Remove output file if it exists (osslsigncode won't overwrite)
    if out_path.exists():
        out_path.unlink()

    # Use local intermediate files
    hash_file_path = Path(f"{binary_path.stem}.req")
    signed_hash_file_path = Path(f"{binary_path.stem}.signed.req")

    # Remove intermediate files from previous runs (osslsigncode won't overwrite)
    hash_file_path.unlink(missing_ok=True)
    signed_hash_file_path.unlink(missing_ok=True)

    try:
        # Step 1: Extract hash from binary
        cli_info(f"Step 1/3: Extracting hash from binary '{binary_path.name}' using {hash_alg}...")
        try:
            subprocess.run(
                ['osslsigncode', 'extract-data', '-h', hash_alg, '-in', str(binary_path), '-out', str(hash_file_path)],
                check=True,
                capture_output=True,
                text=True
            )
            cli_code_info(f"  Hash extracted to temporary file")
        except subprocess.CalledProcessError as e:
            raise click.ClickException(
                f"osslsigncode extract-data failed: {e.stderr}\n"
                "Make sure osslsigncode is installed and the input is a valid PE executable"
            )
        except FileNotFoundError:
            raise click.ClickException(
                "osslsigncode not found in PATH. Please install osslsigncode to use this command"
            )

        # Step 2: Sign the hash
        cli_info("Step 2/3: Signing hash with HSM...")
        try:
            # Use the core signing logic
            _sign_authenticode_hash(ctx, str(hash_file_path), str(signed_hash_file_path), ca)
            cli_code_info(f"  Hash signed successfully")
        except click.ClickException:
            raise
        except Exception as e:
            raise click.ClickException(f"Hash signing failed: {str(e)}")

        # Step 3: Attach signature to binary
        cli_info("Step 3/3: Attaching signature to binary...")
        try:
            attach_cmd = [
                'osslsigncode', 'attach-signature',
                '-sigin', str(signed_hash_file_path),
                '-CAfile', str(cert_chain_path),
                '-in', str(binary_path),
                '-out', str(out_path)
            ]

            # Add CRL file if provided
            # Otherwise, osslsigncode will attempt to download CRL from URL embedded in certificate
            if crl_file:
                attach_cmd.extend(['-CRLfile', str(crl_file)])

            if timestamp:
                attach_cmd.extend(['-t', timestamp])

            subprocess.run(
                attach_cmd,
                check=True,
                capture_output=True,
                text=True
            )
            cli_code_info(f"  Signature attached to binary")
        except subprocess.CalledProcessError as e:
            raise click.ClickException(f"osslsigncode attach-signature failed: {e.stderr}")

        # Clean up intermediate files on success
        hash_file_path.unlink(missing_ok=True)
        signed_hash_file_path.unlink(missing_ok=True)

        cli_code_info(f"Signed executable saved to: `{out_path}`")

    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(f"Code signing failed: {str(e)}")
