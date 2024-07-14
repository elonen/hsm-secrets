from copy import deepcopy
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from datetime import datetime, timedelta
import ipaddress
from typing import Dict, Union, List, Optional, Tuple

from hsm_secrets.config import HSMConfig, X509Cert, X509Info, load_hsm_config


class X509CertBuilder:

    def __init__(self, hsm_config: HSMConfig, cert_def: X509Cert):
        self.hsm_config = hsm_config
        self.cert_def = cert_def
        self.cert_def_info = _merge_x509_info_with_defaults(cert_def.x509_info, hsm_config)
        self.private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey] = self._create_key_pair()


    def _create_key_pair(self) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
        assert self.cert_def.key.algorithm == "rsa4096", "FIXME: algorithm must be rsa4096"
        key_type = "rsa"
        key_size = 4096

        if key_type == 'rsa':
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
        elif key_type == 'ec':
            curve: ec.EllipticCurve|None = None
            if key_size == 256:
                curve = ec.SECP256R1()
            elif key_size == 384:
                curve = ec.SECP384R1()
            elif key_size == 521:
                curve = ec.SECP521R1()
            else:
                raise ValueError(f"Unsupported EC key size: {key_size}")
            return ec.generate_private_key(curve)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")


    def _create_x509_name(self) -> x509.Name:
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


    def _create_x509_san(self) -> x509.SubjectAlternativeName:
        assert self.cert_def_info.attribs, "X509Info.attribs.subject_alt_names is missing"
        san: List[Union[x509.DNSName, x509.IPAddress]] = []
        for name in self.cert_def_info.attribs.subject_alt_names:
            try:
                ip = ipaddress.ip_address(name)
                san.append(x509.IPAddress(ip))
            except ValueError:
                san.append(x509.DNSName(name))
        return x509.SubjectAlternativeName(san)


    def _create_x509_key_usage(self) -> x509.KeyUsage:
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


    def _create_x509_extended_key_usage(self) -> x509.ExtendedKeyUsage:
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


    def generate_csr(self) -> x509.CertificateSigningRequest:
        subject = self._create_x509_name()
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        builder = builder.add_extension(self._create_x509_san(), critical=False)

        if self.cert_def_info.key_usage:
            builder = builder.add_extension(self._create_x509_key_usage(), critical=True)

        if self.cert_def_info.extended_key_usage:
            builder = builder.add_extension(self._create_x509_extended_key_usage(), critical=False)

        csr = builder.sign(self.private_key, hashes.SHA256())
        return csr


    def generate_self_signed_cert(self) -> x509.Certificate:
        subject = issuer = self._create_x509_name()
        builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)

        assert self.cert_def_info.validity_days, "X509Info.validity_days is missing"

        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=self.cert_def_info.validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(self.private_key.public_key())

        builder = builder.add_extension(self._create_x509_san(), critical=False)

        if self.cert_def_info.key_usage:
            builder = builder.add_extension(self._create_x509_key_usage(), critical=True)

        if self.cert_def_info.extended_key_usage:
            builder = builder.add_extension(self._create_x509_extended_key_usage(), critical=False)

        if self.cert_def_info.is_ca:
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

        cert = builder.sign(self.private_key, hashes.SHA256())
        return cert


    def generate_cert_and_csr(self) -> Tuple[x509.CertificateSigningRequest, x509.Certificate]:
        csr = self.generate_csr()
        cert = self.generate_self_signed_cert()
        return csr, cert


    def get_private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )


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
    cert_config = hsm_config.x509.root_certs[0]  # Assuming we want to generate the first root cert

    cert_builder = X509CertBuilder(hsm_config, cert_config)
    csr, cert = cert_builder.generate_cert_and_csr()

    private_key_pem = cert_builder.get_private_key_pem()
    csr_pem: bytes = csr.public_bytes(Encoding.PEM)
    cert_pem: bytes = cert.public_bytes(Encoding.PEM)

    print("Private Key:")
    print(private_key_pem.decode())
    print("\nCSR:")
    print(csr_pem.decode())
    print("\nCertificate:")
    print(cert_pem.decode())
