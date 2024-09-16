from pathlib import Path
import click
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
