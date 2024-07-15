from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat

from typing import Any, Union

from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives import hashes

import yubihsm.objects
import yubihsm.defs

"""
Classes that wrap YubiHSM-stored keys in the cryptography.hazmat.primitives.asymmetric interfaces.

This allows the keys to be used in the same way as regular keys in the `cryptography` library,
but all crypto operations are delegated to the HSM.
"""


PrivateKeyHSMAdapter = Union['RSAPrivateKeyHSMAdapter', 'Ed25519PrivateKeyHSMAdapter', 'ECPrivateKeyHSMAdapter']


# ----- RSA -----

class RSAPrivateKeyHSMAdapter(rsa.RSAPrivateKey):
    """
    A wrapper around a YubiHSM-stored RSA private key object.
    This delegates all crypto operations to the device without exposing the key material.
    """
    def __init__(self, hsm_key: yubihsm.objects.AsymmetricKey):
        self.hsm_obj = hsm_key

    def sign(self, data: bytes, padding: AsymmetricPadding, algorithm: Any) -> bytes:
        assert padding.name == "EMSA-PKCS1-v1_5", f"Unsupported padding: {padding.name}"
        assert algorithm.name == "sha256", f"Unsupported algorithm: {algorithm.name}"
        return self.hsm_obj.sign_pkcs1v1_5(data, hashes.SHA256())

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        assert padding.name == "EMSA-PKCS1-v1_5", f"Unsupported padding: {padding.name}"
        return self.hsm_obj.decrypt_pkcs1v1_5(ciphertext)

    def public_key(self) -> rsa.RSAPublicKey:
        res = self.hsm_obj.get_public_key()
        assert isinstance(res, rsa.RSAPublicKey), f"Unexpected public key type: {type(res)}"
        return res

    @property
    def key_size(self) -> int:
        return self.public_key().key_size

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        raise NotImplementedError("HSM-backed key: private_numbers() not implemented")

    def private_bytes(self, encoding: Encoding, format: PrivateFormat, encryption_algorithm: serialization.KeySerializationEncryption) -> bytes:
        raise NotImplementedError("HSM-backed key: private_bytes() not implemented")


# ----- Ed25519 -----


class Ed25519PrivateKeyHSMAdapter(ed25519.Ed25519PrivateKey):
    """
    A wrapper around a YubiHSM-stored Ed25519 private key object.
    This delegates all crypto operations to the device without exposing the key material.
    """
    def __init__(self, hsm_key: yubihsm.objects.AsymmetricKey):
        self.hsm_obj = hsm_key

    def sign(self, data: bytes) -> bytes:
        return self.hsm_obj.sign_eddsa(data)

    def public_key(self) -> ed25519.Ed25519PublicKey:
        res = self.hsm_obj.get_public_key()
        assert isinstance(res, ed25519.Ed25519PublicKey), f"Unexpected public key type: {type(res)}"
        return res

    def private_bytes_raw(self) -> bytes:
         raise NotImplementedError("HSM-backed key: private_bytes_raw() not implemented")

    def private_bytes(self, encoding: Any, format: Any, encryption_algorithm: Any) -> bytes:
        raise NotImplementedError("HSM-backed key: private_bytes() not implemented")


# ----- EC -----


class ECPrivateKeyHSMAdapter(ec.EllipticCurvePrivateKey):
    def __init__(self, hsm_key: yubihsm.objects.AsymmetricKey):
        self.hsm_obj = hsm_key

    def sign(self, data: bytes, signature_algorithm: ec.EllipticCurveSignatureAlgorithm) -> bytes:
        if isinstance(signature_algorithm, ec.ECDSA):
            return self.hsm_obj.sign_ecdsa(data)
        else:
            raise ValueError(f"Unsupported signature algorithm: {signature_algorithm}")

    def public_key(self) -> ec.EllipticCurvePublicKey:
        res = self.hsm_obj.get_public_key()
        assert isinstance(res, ec.EllipticCurvePublicKey), f"Unexpected public key type: {type(res)}"
        return res

    @property
    def curve(self) -> ec.EllipticCurve:
        return self.public_key().curve

    @property
    def key_size(self) -> int:
        return self.public_key().key_size

    def exchange(self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        return self.hsm_obj.derive_ecdh(peer_public_key)

    def private_bytes(self, encoding: Any, format: Any, encryption_algorithm: Any) -> bytes:
        raise NotImplementedError("HSM-backed key: private_bytes() not implemented")

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        raise NotImplementedError("HSM-backed key: private_numbers() not implemented")


def make_private_key_adapter(hsm_key: yubihsm.objects.AsymmetricKey) -> PrivateKeyHSMAdapter:
    """
    Create a PrivateKeyHSMAdapter object for the given YubiHSM-stored key.
    """
    info = hsm_key.get_info()
    if "RSA_" in str(info.algorithm.name.upper()):
        return RSAPrivateKeyHSMAdapter(hsm_key)
    elif "ED25519" in str(info.algorithm.name.upper()):
        return Ed25519PrivateKeyHSMAdapter(hsm_key)
    elif "EC_" in str(info.algorithm.name.upper()):
        return ECPrivateKeyHSMAdapter(hsm_key)
    else:
        raise ValueError(f"Unsupported key type: {info.algorithm}")
