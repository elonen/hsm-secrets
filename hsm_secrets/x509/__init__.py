from copy import deepcopy
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat

import datetime
from datetime import timedelta
import ipaddress
from typing import Any, Dict, Union, List, Optional, Tuple

from hsm_secrets.config import HSMConfig, X509Cert, X509Info, load_hsm_config

import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives import hashes

import yubihsm.objects
import yubihsm.defs

from hsm_secrets.utils import open_hsm_session_with_default_admin

import click


class YubihsmRSAPrivateKey(rsa.RSAPrivateKey):
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

    # Unimplemented methods due to HSM-homed keys not being extractable

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        raise NotImplementedError("HSM-backed key: private_numbers() not implemented")

    def private_bytes(self, encoding: Encoding, format: PrivateFormat, encryption_algorithm: serialization.KeySerializationEncryption) -> bytes:
        raise NotImplementedError("HSM-backed key: private_bytes() not implemented")


class YubihsmEd25519PrivateKey(ed25519.Ed25519PrivateKey):
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



class YubihsmECPrivateKey(ec.EllipticCurvePrivateKey):
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



YubihsmPrivateKey = Union[YubihsmRSAPrivateKey, YubihsmEd25519PrivateKey, YubihsmECPrivateKey]


class X509CertBuilder:

    def __init__(self, hsm_config: HSMConfig, cert_def: X509Cert, hsm_key: yubihsm.objects.AsymmetricKey):
        self.hsm_config = hsm_config
        self.cert_def = cert_def
        self.cert_def_info = _merge_x509_info_with_defaults(cert_def.x509_info, hsm_config)

        public_key = hsm_key.get_public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            self.private_key: YubihsmPrivateKey = YubihsmRSAPrivateKey(hsm_key)
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            self.private_key = YubihsmEd25519PrivateKey(hsm_key)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            self.private_key = YubihsmECPrivateKey(hsm_key)
        else:
            raise ValueError(f"Unsupported key type: {type(public_key)}")


    def _mk_name_attribs(self) -> x509.Name:
        assert self.cert_def_info.attribs, "X509Info.attribs is missing"
        name_attributes: List[x509.NameAttribute] = [
            x509.NameAttribute(NameOID.COMMON_NAME, self.cert_def_info.attribs.common_name)
        ]
        if self.cert_def_info.attribs.organization:
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.cert_def_info.attribs.organization))
        if self.cert_def_info.attribs.locality:
            name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, self.cert_def_info.attribs.locality))
        if self.cert_def_info.attribs.state:
            name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.cert_def_info.attribs.state))
        if self.cert_def_info.attribs.country:
            name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, self.cert_def_info.attribs.country))
        return x509.Name(name_attributes)


    def _mkext_alt_name(self) -> x509.SubjectAlternativeName:
        assert self.cert_def_info.attribs, "X509Info.attribs.subject_alt_names is missing"
        san: List[Union[x509.DNSName, x509.IPAddress]] = []
        for name in self.cert_def_info.attribs.subject_alt_names:
            try:
                ip = ipaddress.ip_address(name)
                san.append(x509.IPAddress(ip))
            except ValueError:
                san.append(x509.DNSName(name))
        return x509.SubjectAlternativeName(san)


    def _mkext_key_usage(self) -> x509.KeyUsage:
        assert self.cert_def_info.key_usage, "X509Info.key_usage is missing"
        u = self.cert_def_info.key_usage
        assert len(u) <= 9, "Non-mapped key usage flags in config. Fix the code here."
        return x509.KeyUsage(
            digital_signature = "digitalSignature" in u,
            content_commitment = "nonRepudiation" in u,
            key_encipherment = "keyEncipherment" in u,
            data_encipherment = "dataEncipherment" in u,
            key_agreement = "keyAgreement" in u,
            key_cert_sign = "keyCertSign" in u,
            crl_sign = "cRLSign" in u,
            encipher_only = "encipherOnly" in u,
            decipher_only = "decipherOnly" in u)


    def _mkext_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        eku_map: Dict[str, x509.ObjectIdentifier] = {
            "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
            "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
            "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
            "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
            "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
            "OCSPSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
            "anyExtendedKeyUsage": ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE
        }
        assert self.cert_def_info.extended_key_usage, "X509Info.extended_key_usage is missing"
        usages = [eku_map[usage] for usage in self.cert_def_info.extended_key_usage if usage in eku_map]
        return x509.ExtendedKeyUsage(usages)


    def _build_cert_base(self, issuer: Optional[x509.Name] = None) -> x509.CertificateBuilder:
        subject = self._mk_name_attribs()
        builder = x509.CertificateBuilder().subject_name(subject)

        if issuer:
            builder = builder.issuer_name(issuer)
        else:
            builder = builder.issuer_name(subject)  # Self-signed

        assert self.cert_def_info.validity_days, "X509Info.validity_days is missing"

        builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + timedelta(days=self.cert_def_info.validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(self.private_key.public_key())

        builder = builder.add_extension(self._mkext_alt_name(), critical=False)

        if self.cert_def_info.key_usage:
            builder = builder.add_extension(self._mkext_key_usage(), critical=True)

        if self.cert_def_info.extended_key_usage:
            builder = builder.add_extension(self._mkext_extended_key_usage(), critical=False)

        if self.cert_def_info.is_ca:
            path_length = None if issuer is None else 0  # Root CA: None, Intermediate: 0
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)

        return builder


    def generate_csr(self) -> x509.CertificateSigningRequest:
        builder = x509.CertificateSigningRequestBuilder().subject_name(self._mk_name_attribs())

        builder = builder.add_extension(self._mkext_alt_name(), critical=False)

        if self.cert_def_info.key_usage:
            builder = builder.add_extension(self._mkext_key_usage(), critical=True)

        if self.cert_def_info.extended_key_usage:
            builder = builder.add_extension(self._mkext_extended_key_usage(), critical=False)

        ed = isinstance(self.private_key, YubihsmEd25519PrivateKey)
        return builder.sign(self.private_key, None if ed else hashes.SHA256())


    def generate_self_signed_cert(self) -> x509.Certificate:
        builder = self._build_cert_base()
        ed = isinstance(self.private_key, YubihsmEd25519PrivateKey)
        return builder.sign(self.private_key, None if ed else hashes.SHA256())


    def generate_cross_signed_intermediate_cert(self, issuer_certs: List[x509.Certificate], issuer_keys: List[YubihsmPrivateKey]) -> List[x509.Certificate]:
        if len(issuer_certs) != len(issuer_keys):
            raise ValueError("The number of issuer certificates must match the number of issuer keys")

        cross_signed_certs = []

        for issuer_cert, issuer_key in zip(issuer_certs, issuer_keys):
            builder = self._build_cert_base(issuer=issuer_cert.subject)

            # Add Authority Key Identifier
            authority_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key())
            builder = builder.add_extension(authority_key_identifier, critical=False)

            # Add Subject Key Identifier
            subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key())
            builder = builder.add_extension(subject_key_identifier, critical=False)

            ed = isinstance(issuer_key, YubihsmEd25519PrivateKey)
            cert = builder.sign(issuer_key, None if ed else hashes.SHA256())

            cross_signed_certs.append(cert)

        return cross_signed_certs





def _merge_x509_info_with_defaults(x509_info: Optional[X509Info], hsm_config: HSMConfig) -> X509Info:
    defaults = hsm_config.general.x509_defaults
    if x509_info is None:
        return deepcopy(defaults)

    merged = deepcopy(x509_info)

    if merged.is_ca is None:
        merged.is_ca = defaults.is_ca

    if merged.validity_days is None:
        merged.validity_days = defaults.validity_days

    if merged.attribs is None:
        merged.attribs = deepcopy(defaults.attribs)
    else:
        for attr in ['organization', 'locality', 'state', 'country']:
            if getattr(merged.attribs, attr) is None:
                setattr(merged.attribs, attr, getattr(defaults.attribs, attr))

        if defaults.attribs:
            if not merged.attribs.subject_alt_names:
                merged.attribs.subject_alt_names = defaults.attribs.subject_alt_names.copy()

    if merged.key_usage is None:
        merged.key_usage = defaults.key_usage.copy() if defaults.key_usage else None

    if merged.extended_key_usage is None:
        merged.extended_key_usage = defaults.extended_key_usage.copy() if defaults.extended_key_usage else None

    return merged


# Example usage
if __name__ == "__main__":
    hsm_config = load_hsm_config("hsm-conf.yml")

    rsa_root_ca_config = hsm_config.x509.root_certs[0]  # RSA root CA
    ed25519_root_ca_config = hsm_config.x509.root_certs[1]  # Ed25519 root CA
    ec_root_ca_config = hsm_config.x509.root_certs[2]  # EC root CA
    tls_ca_config = hsm_config.tls.intermediate_certs[0]

    ctx = click.Context(
        command=click.Command('tls', params=[]),
        obj={
            'config': hsm_config,
            'devserial': hsm_config.general.master_device
        })

    with open_hsm_session_with_default_admin(ctx) as (conf, ses):
        # Generate root CAs (RSA, Ed25519, EC)
        root_cas = []
        for root_config in [rsa_root_ca_config, ed25519_root_ca_config, ec_root_ca_config]:
            root_hsm_key = ses.get_object(root_config.key.id, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
            assert isinstance(root_hsm_key, yubihsm.objects.AsymmetricKey)
            root_cert_builder = X509CertBuilder(hsm_config, root_config, root_hsm_key)
            root_cert = root_cert_builder.generate_self_signed_cert()
            root_cas.append((root_cert, root_cert_builder.private_key))

        # Generate EC TLS Intermediate CA
        tls_hsm_key = ses.get_object(tls_ca_config.key.id, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
        assert isinstance(tls_hsm_key, yubihsm.objects.AsymmetricKey)
        tls_cert_builder = X509CertBuilder(hsm_config, tls_ca_config, tls_hsm_key)
        tls_csr = tls_cert_builder.generate_csr()

        # Cross-sign the intermediate CA with all root CAs
        cross_signed_certs = tls_cert_builder.generate_cross_signed_intermediate_cert(
            [cert for cert, _ in root_cas],
            [key for _, key in root_cas]
        )

        # Output results
        print("\nTLS Intermediate CA CSR:")
        print(tls_csr.public_bytes(Encoding.PEM).decode())

        for i, cert in enumerate(cross_signed_certs):
            key_type = type(root_cas[i][1]).__name__.replace('Yubihsm', '').replace('PrivateKey', '')
            print(f"\nTLS Intermediate CA Certificate (signed by {key_type} Root):")
            print(cert.public_bytes(Encoding.PEM).decode())
