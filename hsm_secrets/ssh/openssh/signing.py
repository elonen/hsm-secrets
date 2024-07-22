import struct
from typing import Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
import cryptography.hazmat.primitives.asymmetric.padding as paddings
import cryptography.hazmat.primitives.serialization.ssh as ssh
import cryptography.exceptions

from hsm_secrets.ssh.openssh.ssh_certificate import ECDSACertificate, ED25519Certificate, RSACertificate, OpenSSHCertificate, cert_for_ssh_pub_id
from hsm_secrets.ssh.openssh.ssh_data_types import SSHDataType


PrivateKey = Union[rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey]

def sign_ssh_cert(cert: OpenSSHCertificate, private_key: PrivateKey) -> None:
    """
    Sign an SSH certificate with a private key.
    Stores the signature in the certificate object.

    :param cert: The SSH certificate to sign
    :param private_key: The private key to sign the certificate with
    """
    issuer: OpenSSHCertificate|None = None
    if isinstance(private_key, rsa.RSAPrivateKey):
        issuer = RSACertificate(private_key)
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        issuer = ED25519Certificate(private_key)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        issuer = ECDSACertificate(private_key)
    else:
        raise ValueError(f"Unsupported private key type: {type(private_key)}")

    cert.signature_key = SSHDataType.encode_string(issuer.key_cipher_string()) + issuer.encode_public_key()
    data_to_sign = cert.make_signing_request()

    signature = None
    sig_format = None

    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(data_to_sign, paddings.PKCS1v15(), hashes.SHA512())
        sig_format =  b"rsa-sha2-512"

    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(data_to_sign)
        sig_format = b"ssh-ed25519"

    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        hash_func: hashes.HashAlgorithm|None = None
        if isinstance(private_key.curve, ec.SECP256R1):
            hash_func = hashes.SHA256()
            sig_format = b"ecdsa-sha2-nistp256"
        elif isinstance(private_key.curve, ec.SECP384R1):
            hash_func = hashes.SHA384()
            sig_format = b"ecdsa-sha2-nistp384"
        elif isinstance(private_key.curve, ec.SECP521R1):
            hash_func = hashes.SHA512()
            sig_format = b"ecdsa-sha2-nistp521"
        else:
            raise ValueError(f"Unsupported ECDSA curve: {type(private_key.curve)}")

        signature_ec = private_key.sign(data_to_sign, ec.ECDSA(hash_func))
        # ECDSA signatures are encoded as two integers (r, s)
        from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
        r, s = asym_utils.decode_dss_signature(signature_ec)
        signature = SSHDataType.encode_mpint(r) + SSHDataType.encode_mpint(s)
    else:
        raise ValueError(f"Unsupported private key type: {type(private_key)}")

    # Encode the signature according to the SSH protocol
    encoded_signature = SSHDataType.encode_bytes(sig_format) + SSHDataType.encode_bytes(signature)

    cert.signature = encoded_signature

# ----------

def verify_ssh_cert(cert: OpenSSHCertificate) -> bool:
    """
    Verify an SSH certificate with a public key.

    :param cert: The SSH certificate to verify
    :param encoded_public_key: The public key to verify the certificate with (in OpenSSH format: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB...")
    :return: True if the certificate is verified, False otherwise
    """
    try:
        if not cert.signature_key:
            raise ValueError("Certificate has no signature key")
        if not cert.signature:
            raise ValueError("Certificate has no signature")

        data_to_verify = cert.make_signing_request()

        encoded_sig_key = cert.encode_signature_key_as_string()
        issuer = cert_for_ssh_pub_id(encoded_sig_key, cert_id=cert.cert_id, cert_type=ssh.SSHCertificateType.USER)

        # Parse the signature format and signature data
        sig_data = cert.signature
        sig_format, sig_data = SSHDataType.decode_string(sig_data)
        signature, sig_data = SSHDataType.decode_bytes(sig_data)

        if isinstance(issuer, RSACertificate):
            rsa_pub_key = rsa.RSAPublicNumbers(issuer.e, issuer.n).public_key()
            rsa_hash_algo: hashes.HashAlgorithm
            if sig_format == "rsa-sha2-512":
                rsa_hash_algo = hashes.SHA512()
            elif sig_format == "rsa-sha2-256":
                rsa_hash_algo = hashes.SHA256()
            else:
                raise ValueError(f"Unsupported RSA signature format for verification: {sig_format}")
            rsa_pub_key.verify(signature, data_to_verify, paddings.PKCS1v15(), rsa_hash_algo)

        elif isinstance(issuer, ED25519Certificate):
            if sig_format != "ssh-ed25519":
                raise ValueError(f"Invalid signature format for Ed25519: {sig_format}")
            ed_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(issuer.pk)
            ed_pub_key.verify(signature, data_to_verify)

        elif isinstance(issuer, ECDSACertificate):
            ec_curve: ec.EllipticCurve
            ec_sig_algo: hashes.HashAlgorithm
            if issuer.curve == "nistp256":
                ec_curve = ec.SECP256R1()
                ec_sig_algo = hashes.SHA256()
            elif issuer.curve == "nistp384":
                ec_curve = ec.SECP384R1()
                ec_sig_algo = hashes.SHA384()
            elif issuer.curve == "nistp521":
                ec_curve = ec.SECP521R1()
                ec_sig_algo = hashes.SHA512()
            else:
                raise ValueError(f"Unsupported ECDSA signature format: {sig_format}")

            ec_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec_curve, issuer.ec_point)
            assert isinstance(ec_pub_key, ec.EllipticCurvePublicKey)

            import cryptography.hazmat.primitives.asymmetric.utils as asym_utils
            r, data = SSHDataType.decode_mpint(signature)
            s, data = SSHDataType.decode_mpint(data)
            computed_sig = asym_utils.encode_dss_signature(r, s)

            ec_pub_key.verify(computed_sig, data_to_verify, ec.ECDSA(ec_sig_algo))

        else:
            raise ValueError(f"Unsupported issuer (CA) type: {type(issuer)}")

        return True

    except cryptography.exceptions.InvalidSignature as e:
        return False

