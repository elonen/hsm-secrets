import base64
from abc import ABC, abstractmethod
import datetime
import os
from typing import List, Dict, Literal, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives.serialization import ssh

from hsm_secrets.ssh.openssh.ssh_data_types import SSHDataType

"""
OpenSSH certificate parsing and encoding.
Reference: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys

This is similar to the cryptography.hazmat.primitives.serialization.ssh.SSHCertificate class,
but with additional support for sk-ecdsa-sha2 and sk-ssh-ed25519 certificate types.
"""

class OpenSSHCertificate(ABC):
    """
    Base class for OpenSSH certificates. Subclasses implement different key types.
    """
    def __init__(self) -> None:
        self.nonce: bytes = b""
        self.serial: int = 0
        self.cert_type: ssh.SSHCertificateType = ssh.SSHCertificateType.USER
        self.cert_id: str
        self.valid_principals: List[str] = []
        self.valid_after: int = 0
        self.valid_before: int = 0
        self.critical_options: Dict[str, bytes] = {}
        self.extensions: Dict[str, bytes] = {}
        self.reserved: bytes = b""
        self.signature_key: bytes = b""
        self.signature: bytes = b""
        self.priv_key: Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]] = None


    @staticmethod
    def from_string_fmt(data: str) -> 'OpenSSHCertificate':
        """
        Decode an SSH certificate from its on-disk format.

        :param data: The certificate data as a string in the format "<type> <base64_data> <name>".
        :return: The decoded SSHCertificate object.
        :raises ValueError: If the input format is invalid or the certificate type mismatches.
        """
        parts = data.split(' ')
        if len(parts) != 3:
            raise ValueError("Invalid on-disk certificate format")

        cert_type, base64_data, _cert_name = parts
        decoded_data = base64.b64decode(base64_data)
        cert, remaining = OpenSSHCertificate.decode(decoded_data)
        assert not remaining, "Extra data after certificate"

        assert cert.cert_cipher_string() == cert_type, "Certificate type mismatch"
        return cert


    def to_string_fmt(self) -> str:
        """
        Encode an SSH certificate to its on-disk format.

        :param cert: The SSHCertificate object to encode.
        :return: The encoded certificate as a string in the format "type base64_data comment".
        """
        onwire_data = self.encode()
        base64_data = base64.b64encode(onwire_data).decode('ascii')
        return f"{self.cert_cipher_string()} {base64_data} {self.cert_id}"


    def encode(self) -> bytes:
        """
        Encode the SSH certificate into bytes (on-wire protocol format).
        :return: The encoded certificate as bytes.
        """
        encoded = self.make_signing_request()
        encoded += SSHDataType.encode_bytes(self.signature)
        return encoded


    def make_signing_request(self) -> bytes:
        """
        Encode "signing request" data for the certificate.
        This is identical to the on-wire format, but without the final signature field.
        :return: The encoded data as bytes.
        """
        encoded = b""
        encoded += SSHDataType.encode_string(self.cert_cipher_string(), 'ascii')
        encoded += SSHDataType.encode_bytes(self.nonce)
        encoded += self.encode_public_key()
        encoded += SSHDataType.encode_uint64(self.serial)
        encoded += SSHDataType.encode_uint32(self.cert_type.value)
        encoded += SSHDataType.encode_string(self.cert_id, 'utf-8')
        encoded += SSHDataType.encode_name_list(self.valid_principals)
        encoded += SSHDataType.encode_uint64(self.valid_after)
        encoded += SSHDataType.encode_uint64(self.valid_before)
        encoded += SSHDataType.encode_options(self.critical_options)
        encoded += SSHDataType.encode_options(self.extensions)
        encoded += SSHDataType.encode_bytes(self.reserved)
        encoded += SSHDataType.encode_bytes(self.signature_key)
        return encoded


    @staticmethod
    def decode(data: bytes) -> Tuple['OpenSSHCertificate', bytes]:
        """
        Decode bytes (on-wire format) into an SSH certificate object (and any remaining bytes).

        :param data: The bytes to decode.
        :return: A tuple containing the decoded certificate and any remaining bytes.
        """
        cipher_type, _ = SSHDataType.decode_string(data)

        for cert_class in (RSACertificate, ECDSACertificate, ED25519Certificate, SKECDSACertificate, SKEd25519Certificate):
            assert issubclass(cert_class, OpenSSHCertificate)
            if cert_class.cipher_match(cipher_type):
                cert = cert_class()
                cert_type_bytes, data = SSHDataType.decode_bytes(data)
                cert.nonce, data = SSHDataType.decode_bytes(data)

                data = cert.decode_public_key(data)
                assert cert_type_bytes.decode('ascii') == cert.cert_cipher_string(), "Certificate type mismatch"

                cert.serial, data = SSHDataType.decode_uint64(data)
                cert_type_value, data = SSHDataType.decode_uint32(data)
                cert.cert_type = ssh.SSHCertificateType(cert_type_value)

                cert.cert_id, data = SSHDataType.decode_string(data, 'utf-8')
                cert.valid_principals, data = SSHDataType.decode_name_list(data)
                cert.valid_after, data = SSHDataType.decode_uint64(data)
                cert.valid_before, data = SSHDataType.decode_uint64(data)

                cert.critical_options, data = SSHDataType.decode_options(data)
                cert.extensions, data = SSHDataType.decode_options(data)

                cert.reserved, data = SSHDataType.decode_bytes(data)
                cert.signature_key, data = SSHDataType.decode_bytes(data)
                cert.signature, data = SSHDataType.decode_bytes(data)

                return cert, data

        raise ValueError(f"Unsupported cipher: {cipher_type}")


    @staticmethod
    def cipher_match(cipher_name: str) -> bool:
        """
        Check if the given certificate/key cipher type matches this certificate type.

        :param cert_type: The certificate cipher type string.
        :return: True if the type matches, False otherwise.
        """
        raise NotImplementedError("Subclasses must implement this method")

    @abstractmethod
    def cert_cipher_string(self) -> str:
        """
        Return the cipher / crypto algorithm string for this certificate.
        :return: The algorithm string.
        """
        pass

    def key_cipher_string(self) -> str:
        """
        Get the public key algorithm string from the certificate type.
        :return: The public key algorithm string.
        """
        return self.cert_cipher_string().split('-cert-')[0]

    @abstractmethod
    def encode_public_key(self) -> bytes:
        """
        Encode the key type specific fields of the certificate.
        :return: The encoded key fields as bytes.
        """
        pass

    def encode_public_key_as_string(self) -> str:
        """
        Encode the public key to the ssh .pub string format.
        :return: The encoded public key as a string.
        """
        pk_data = SSHDataType.encode_string(self.key_cipher_string(), 'ascii') + self.encode_public_key()
        return f"{self.key_cipher_string()} {base64.b64encode(pk_data).decode('ascii')} {self.cert_id}"

    def encode_signature_key_as_string(self) -> str:
        """
        Encode the signature key to the ssh .pub string format.
        :return: The encoded signature key as a string.
        """
        sig_key_type, _ = SSHDataType.decode_string(self.signature_key)
        return f"{sig_key_type} {base64.b64encode(self.signature_key).decode('ascii')} {self.cert_id}-issuer"

    @abstractmethod
    def decode_public_key(self, data: bytes) -> bytes:
        """
        Decode the key type specific fields of the certificate.
        :param data: The bytes to decode.
        :return: Any remaining bytes after decoding the key fields.
        """
        pass


# --------

class RSACertificate(OpenSSHCertificate):
    """
    RSA-specific SSH certificate class.
    """
    def __init__(self, priv_key: Optional[rsa.RSAPrivateKey] = None) -> None:
        super().__init__()
        self.e: int = 0  # Public exponent
        self.n: int = 0  # Modulus
        self.priv_key = priv_key
        if priv_key:
            pub_key = priv_key.public_key().public_numbers()
            self.e = pub_key.e
            self.n = pub_key.n

    def cert_cipher_string(self) -> str:
        return "ssh-rsa-cert-v01@openssh.com"

    @staticmethod
    def cipher_match(cipher_name: str) -> bool:
        return cipher_name.startswith("ssh-rsa")

    def encode_public_key(self) -> bytes:
        return SSHDataType.encode_mpint(self.e) + SSHDataType.encode_mpint(self.n)

    def decode_public_key(self, data: bytes) -> bytes:
        self.e, data = SSHDataType.decode_mpint(data)
        self.n, data = SSHDataType.decode_mpint(data)
        return data

# --------

class ECDSACertificate(OpenSSHCertificate):
    """
    ECDSA-specific SSH certificate class.
    """
    def __init__(self, priv_key: Optional[ec.EllipticCurvePrivateKey] = None) -> None:
        super().__init__()
        self.curve: str = ""
        self.ec_point: bytes = b""
        self.priv_key = priv_key
        if priv_key:
            pub_key = priv_key.public_key()
            if isinstance(pub_key.curve, ec.SECP256R1):
                self.curve = 'nistp256'
            elif isinstance(pub_key.curve, ec.SECP384R1):
                self.curve = 'nistp384'
            elif isinstance(pub_key.curve, ec.SECP521R1):
                self.curve = 'nistp521'
            else:
                raise ValueError("Unsupported EC curve type: {pub_key.curve}")

            self.ec_point = pub_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            assert self.ec_point[0] == 0x04, "Invalid public key format"


    def cert_cipher_string(self) -> str:
        return f"ecdsa-sha2-{self.curve}-cert-v01@openssh.com"

    @staticmethod
    def cipher_match(cipher_name: str) -> bool:
        return cipher_name.startswith("ecdsa-sha2")

    def encode_public_key(self) -> bytes:
        return SSHDataType.encode_string(self.curve, 'ascii') + SSHDataType.encode_bytes(self.ec_point)

    def decode_public_key(self, data: bytes) -> bytes:
        self.curve, data = SSHDataType.decode_string(data)
        self.ec_point, data = SSHDataType.decode_bytes(data)
        return data

# --------

class SKECDSACertificate(ECDSACertificate):
    def __init__(self) -> None:
        super().__init__()
        self.application: str = "ssh:SOMETHING"

    def cert_cipher_string(self) -> str:
        return f"sk-ecdsa-sha2-{self.curve}-cert-v01@openssh.com"

    @staticmethod
    def cipher_match(cipher_name: str) -> bool:
        return cipher_name.startswith("sk-ecdsa-sha2")

    def encode_public_key(self) -> bytes:
        encoded = super().encode_public_key()
        encoded += SSHDataType.encode_string(self.application, 'utf-8')
        return encoded

    def decode_public_key(self, data: bytes) -> bytes:
        data = super().decode_public_key(data)
        self.application, data = SSHDataType.decode_string(data)
        return data

# --------

class ED25519Certificate(OpenSSHCertificate):
    """
    ED25519-specific SSH certificate class.
    """

    def __init__(self, priv_key: Optional[ed25519.Ed25519PrivateKey] = None) -> None:
        super().__init__()
        self.pk: bytes = b""  # Public key
        self.priv_key = priv_key
        if priv_key:
            self.pk = priv_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def cert_cipher_string(self) -> str:
        return "ssh-ed25519-cert-v01@openssh.com"

    @staticmethod
    def cipher_match(cipher_name: str) -> bool:
        return cipher_name.startswith("ssh-ed25519")

    def encode_public_key(self) -> bytes:
        return SSHDataType.encode_bytes(self.pk)

    def decode_public_key(self, data: bytes) -> bytes:
        self.pk, data = SSHDataType.decode_bytes(data)
        return data

# --------

class SKEd25519Certificate(ED25519Certificate):
    def __init__(self) -> None:
        super().__init__()
        self.application: str = "ssh:"

    def cert_cipher_string(self) -> str:
        return "sk-ssh-ed25519-cert-v01@openssh.com"

    @staticmethod
    def cipher_match(cipher_name: str) -> bool:
        return cipher_name.startswith("sk-ssh-ed25519")

    def encode_public_key(self) -> bytes:
        encoded = super().encode_public_key()
        encoded += SSHDataType.encode_string(self.application, 'utf-8')
        return encoded

    def decode_public_key(self, data: bytes) -> bytes:
        data = super().decode_public_key(data)
        self.application, data = SSHDataType.decode_string(data)
        return data

# --------

ExtensionLabelType = Literal["permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding", "permit-pty", "permit-user-rc"]

def str_to_extension(label: str) -> ExtensionLabelType:
    allowed_values = {"permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding", "permit-pty", "permit-user-rc"}
    if label in allowed_values:
        return label  # type: ignore
    raise ValueError(f"Invalid label: {label}. Must be one of {allowed_values}")


def cert_for_ssh_pub_id(
        encoded_public_key: str,            # in the format "<type> <base64_data> <name>"
        cert_id: str,                        # E.g. "user.name-1234567-principal1+principal2"
        cert_type: ssh.SSHCertificateType = ssh.SSHCertificateType.USER,
        nonce: Optional[bytes] = None,       # Random nonce (32 bytes), if not provided, it is generated
        serial: Optional[int] = None,        # Serial number of the certificate. If None, current timestamp is used.
        principals: List[str] = [],
        valid_seconds: int = 60*60*24*31,   # 31 days
        critical_options: Dict[str, bytes] = {},
        extensions: Dict[ExtensionLabelType, bytes] = {'permit-X11-forwarding': b'', 'permit-agent-forwarding': b'', 'permit-port-forwarding': b'', 'permit-pty': b'', 'permit-user-rc': b''},
    ) -> Union[RSACertificate, ECDSACertificate, ED25519Certificate, SKECDSACertificate, SKEd25519Certificate]:
    """
    Build an SSH certificate object fom an encoded public key / ID (in the format "<type> <base64_data> <name>").

    :param encoded_public_key: Encoded public key data.
    :param cert_type: The certificate type (USER or HOST).
    :param cert_id: The certificate ID (e.g. "user.name-1234567-principal1+principal2").
    :param nonce: Random nonce (32 bytes). Generated if not provided.
    :param serial: Serial number of the certificate. If None, current timestamp is used.
    :param principals: List of principals that the certificate is valid for.
    :param valid_seconds: Number of seconds the certificate is valid for (starting from now -1 min).
    :param critical_options: Dictionary of critical options.
    :param extensions: Dictionary of extensions.
    :return: The SSH certificate object.
    """
    parts = encoded_public_key.strip().split(' ')
    if len(parts) != 3:
        raise ValueError("Invalid encoded public key format")

    cipher_name, base64_data, key_name_from_file = parts
    key_data = base64.b64decode(base64_data)

    type_str, key_data = SSHDataType.decode_string(key_data)
    if type_str != cipher_name:
        raise ValueError("Key type mismatch")

    cert = None
    for cert_class in (RSACertificate, ECDSACertificate, ED25519Certificate, SKECDSACertificate, SKEd25519Certificate):
        assert issubclass(cert_class, OpenSSHCertificate)
        if cert_class.cipher_match(cipher_name):
            cert = cert_class()  # type: ignore
    if not cert:
        raise ValueError("Unsupported key type")

    cert.cert_type = cert_type
    cert.nonce = nonce or os.urandom(32)
    cert.serial = serial or int(datetime.datetime.now().timestamp())
    cert.cert_id = cert_id
    cert.valid_principals = principals
    cert.valid_after = int(datetime.datetime.now().timestamp() - 60)     # 1 minute ago, to allow for clock skew
    cert.valid_before = cert.valid_after + valid_seconds
    cert.critical_options = critical_options
    cert.extensions = {str(k): v for k, v in extensions.items()}

    cert.decode_public_key(key_data)
    assert isinstance(cert, (RSACertificate, ECDSACertificate, ED25519Certificate, SKECDSACertificate, SKEd25519Certificate))
    return cert
