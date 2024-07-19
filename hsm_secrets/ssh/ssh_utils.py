from __future__ import absolute_import, division

from math import floor
import os
import time
import struct
from typing import Sequence
from cryptography.utils import int_to_bytes

from cryptography.hazmat.primitives.asymmetric import (ed25519, rsa)


def create_template(ts_public_key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey,
                    key_whitelist: Sequence[int],
                    not_before: int,
                    not_after: int,
                    principals_blacklist: Sequence[str]) -> bytes:
    """
    Create an OpenSSH certificate template for YubiHSM2.

    Args:
        ts_public_key (str): The public key of the timestamp authority.
        key_whitelist (list): List of HSM Object IDs describing which Asymmetric Keys can be used with this template.
        not_before (int): Offset in seconds, substracted from the current time, before which certificate (request) is not valid.
        not_after (int): Offset in seconds, added to the current time, after which certificate (request) is not valid.
        principals_blacklist (list): List of Principals (user/host names) for which a certificate will not be issued.

    Returns:
        bytes: The certificate template as a byte string.
    """

    TS_ALGO_TAG = 1
    TS_KEY_TAG = 2
    CA_KEYS_WL_TAG = 3
    NB_TAG = 4
    NA_TAG = 5
    PRINCIPALS_BL_TAG = 6

    if isinstance(ts_public_key, rsa.RSAPublicKey):
        pubkey_bytes = int_to_bytes(ts_public_key.public_numbers().n)
        bits_to_algo = {2048: 9, 3072: 10, 4096: 11}
        algo = bits_to_algo.get(len(pubkey_bytes)*8)
        if algo is None:
            raise ValueError(f"Unsupported RSA key size: {len(pubkey_bytes)}")
    elif isinstance(ts_public_key, ed25519.Ed25519PublicKey):
        algo = 46
        pubkey_bytes = ts_public_key.public_bytes_raw()

    if algo is None:
        raise ValueError(f"Unsupported public key type: {type(ts_public_key)}")

    def pack_field(tag: int, data: bytes) -> bytes:
        return struct.pack('!B', tag) + struct.pack('!H', len(data)) + data

    templ = b''
    templ += pack_field(TS_ALGO_TAG, struct.pack('!B', algo))
    templ += pack_field(TS_KEY_TAG, pubkey_bytes)

    whitelist_bytes = b''.join(struct.pack('!H', int(ki)) for ki in key_whitelist)
    templ += pack_field(CA_KEYS_WL_TAG, whitelist_bytes)

    assert not_before >= 0, f"Invalid not_before value: {not_before}, must be >= 0 as it's substraced from current time"
    templ += pack_field(NB_TAG, struct.pack('!I', int(not_before)))

    assert not_after >= 0, f"Invalid not_after value: {not_after}, must be >= 0"
    templ += pack_field(NA_TAG, struct.pack('!I', int(not_after)))

    principals_bytes = b''.join(s.encode('utf8')+b'\x00' for s in principals_blacklist)
    templ += pack_field(PRINCIPALS_BL_TAG, principals_bytes)

    return templ



def create_request(
        ca_public_key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey,
        user_public_key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey,
        key_id: str,
        principals: Sequence[str],
        options: Sequence[tuple[str, bytes]]| None,     # "critical options"
        not_before: int,
        not_after: int,
        serial: int| None,
        host_key: bool = False,
        extensions: Sequence[tuple[str, bytes]] = [('permit-X11-forwarding', b''), ('permit-agent-forwarding', b''), ('permit-port-forwarding', b''), ('permit-pty', b''), ('permit-user-rc', b'')]
    ) -> bytes:
    """
    Creates an OpenSSH certificate request. It is similar to the certificate itself
    (https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys),
    but without the signature at the end.

    Args:
        ca_public_key (str): The public key of the CA that will sign the certificate.
        user_public_key (str): The public key of the user/host key to be signed.
        key_id (str): Free-form text set by the CA to identify the user/host in log messages.
        principals (list): A list of principal names that the certificate is valid for (e.g. "root", "user1", "sysops", "host.example.com").
        options (list): A list of "critical options" to be included in the certificate.
        not_before (int): Timestamp before which the certificate is not valid.
        not_after (int): Timestamp after which the certificate is not valid.
        serial (int): Serial number of the certificate. If None, current timestamp is used, as serial is a 64-bit unsigned integer.
        host_key (bool): True = host key certificate, False = user key certificate.
        extensions (list): A list of "extensions" to be included in the certificate.

    Returns:
        bytes: The certificate request as a byte string.
    """

    if not isinstance(user_public_key, (rsa.RSAPublicKey, ed25519.Ed25519PublicKey)):
        raise ValueError(f"Unsupported usr key type: {type(user_public_key)}")
    if not isinstance(ca_public_key, (rsa.RSAPublicKey, ed25519.Ed25519PublicKey)):
        raise ValueError(f"Unsupported CA key type: {type(ca_public_key)}")

    ca_key_type = (b"ssh-rsa" if isinstance(ca_public_key, rsa.RSAPublicKey) else b"ssh-ed25519")
    cert_name = (b"ssh-rsa-cert-v01@openssh.com" if isinstance(user_public_key, rsa.RSAPublicKey) else b"ssh-ed25519-cert-v01@openssh.com")

    def pack_bytes(data: bytes) -> bytes:
        return struct.pack('!I', len(data)) + data

    def pack_public_key(public_key: rsa.RSAPublicKey | ed25519.Ed25519PublicKey) -> bytes:
        output: bytes = b''
        if isinstance(public_key, rsa.RSAPublicKey):
            numbers = public_key.public_numbers()
            pubkey_e = int_to_bytes(numbers.e)
            pubkey_n = int_to_bytes(numbers.n)
            if pubkey_n[0] >= 0x80:
                pubkey_n = b'\x00' + pubkey_n
            output += pack_bytes(pubkey_e)
            output += pack_bytes(pubkey_n)
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            pk_encoded = public_key.public_bytes_raw() # RFC8032 encoding, hopefully??
            assert len(pk_encoded) == 32, f"Invalid Ed25519 encoded public key length: {len(pk_encoded)}"
            output += pack_bytes(pk_encoded)
        else:
            raise ValueError(f"Unsupported public key type: {type(public_key)}")
        return output

    def pack_options(options: Sequence[tuple[str, bytes]]) -> bytes:
        as_dict = {k: v for k, v in options}
        tuples = sorted(as_dict.items(), key=lambda x: x[0])
        res = b''
        for ext_name, ext_data in tuples:
            ext_name_bytes = ext_name.encode('utf8')
            res += pack_bytes(ext_name_bytes)
            res += pack_bytes(ext_data)
        return pack_bytes(res)

    req = b''
    req += pack_bytes(cert_name)

    nonce = os.urandom(32)
    req += pack_bytes(nonce)

    req += pack_public_key(user_public_key)

    if serial is None:
        serial = floor(time.time())
    req += struct.pack('!Q', serial)
    req += struct.pack('!I', (2 if host_key else 1))    # 2 = host key, 1 = user key

    req += pack_bytes(key_id.encode('utf8'))

    packed_principals = [pack_bytes(p.encode('utf8')) for p in principals]
    req += pack_bytes(b''.join(packed_principals))

    req += struct.pack('!Q', not_after)
    req += struct.pack('!Q', not_before)

    critical_options: Sequence[tuple[str, bytes]] = options or []

    req += pack_options(critical_options)
    req += pack_options(extensions)
    req += pack_bytes(b'')  # reserved string in the spec

    packed_type_and_key = pack_bytes(ca_key_type) + pack_public_key(ca_public_key)
    req += pack_bytes(packed_type_and_key)

    return req
