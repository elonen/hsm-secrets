from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec

import datetime
from datetime import timedelta
import ipaddress
from typing import Dict, Union, List, Optional

from hsm_secrets.config import HSMConfig, X509Cert

import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.hazmat.primitives import hashes

import yubihsm.objects
import yubihsm.defs

from hsm_secrets.x509.def_utils import merge_x509_info_with_defaults
from hsm_secrets.x509.key_adapters import PrivateKeyHSMAdapter, RSAPrivateKeyHSMAdapter, Ed25519PrivateKeyHSMAdapter, ECPrivateKeyHSMAdapter


class X509CertBuilder:
    """
    Ephemeral class for building and signing X.509 certificates using the YubiHSM as a key store.
    """

    def __init__(self, hsm_config: HSMConfig, cert_def: X509Cert, hsm_key: yubihsm.objects.AsymmetricKey):
        """
        Initialize a new X.509 certificate builder.

        :param hsm_config: Full HSM configuration object (for defaults etc).
        :param cert_def: Certificate definition to build.
        :param hsm_key: The YubiHSM-stored asymmetric key object to use for signing and for getting public key.
        """
        self.hsm_config = hsm_config
        self.cert_def = cert_def
        self.cert_def_info = merge_x509_info_with_defaults(cert_def.x509_info, hsm_config)

        public_key = hsm_key.get_public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            self.private_key: PrivateKeyHSMAdapter = RSAPrivateKeyHSMAdapter(hsm_key)
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            self.private_key = Ed25519PrivateKeyHSMAdapter(hsm_key)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            self.private_key = ECPrivateKeyHSMAdapter(hsm_key)
        else:
            raise ValueError(f"Unsupported key type: {type(public_key)}")


    def generate_self_signed_cert(self) -> x509.Certificate:
        """
        Build and sign a self-signed X.509 certificate.
        """
        builder = self._build_cert_base()
        ed = isinstance(self.private_key, Ed25519PrivateKeyHSMAdapter)
        return builder.sign(self.private_key, None if ed else hashes.SHA256())


    def generate_cross_signed_intermediate_cert(self, issuer_certs: List[x509.Certificate], issuer_keys: List[PrivateKeyHSMAdapter]) -> List[x509.Certificate]:
        """
        Build and sign an intermediate X.509 certificate with one or more issuer certificates.
        This is used to cross-sign an intermediate CA certificate with root CAs.
        """
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

            ed = isinstance(issuer_key, Ed25519PrivateKeyHSMAdapter)
            cert = builder.sign(issuer_key, None if ed else hashes.SHA256())

            cross_signed_certs.append(cert)

        return cross_signed_certs


    def generate_csr(self) -> x509.CertificateSigningRequest:
        """
        Generate a Certificate Signing Request (CSR) for the certificate definition.
        This is used to request a certificate from an external CA.
        """
        builder = x509.CertificateSigningRequestBuilder().subject_name(self._mk_name_attribs())

        builder = builder.add_extension(self._mkext_alt_name(), critical=False)

        if self.cert_def_info.key_usage:
            builder = builder.add_extension(self._mkext_key_usage(), critical=True)

        if self.cert_def_info.extended_key_usage:
            builder = builder.add_extension(self._mkext_extended_key_usage(), critical=False)

        ed = isinstance(self.private_key, Ed25519PrivateKeyHSMAdapter)
        return builder.sign(self.private_key, None if ed else hashes.SHA256())


    # ----- Internal helpers -----

    def _build_cert_base(self, issuer: Optional[x509.Name] = None) -> x509.CertificateBuilder:
        """
        Build a base X.509 certificate object with common attributes.
        Used as a basis for both self-signed and cross-signed certificates.
        """
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

    # ----- Extension (OID) converters -----
    # These read the config object and convert it to the appropriate `cryptography` OID objects

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
