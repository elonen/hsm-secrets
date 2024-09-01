from enum import Enum
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.x509.extensions import ExtensionTypeVar
import cryptography.x509.oid as x509_oid

import asn1crypto.core  # type: ignore [import]

import datetime
from datetime import timedelta
import ipaddress
from typing import Callable, Dict, TypeVar, Union, List, Optional

from hsm_secrets.config import HSMConfig, HSMKeyID, HSMOpaqueObject, X509Info

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.primitives import hashes

import yubihsm.objects      # type: ignore [import]
import yubihsm.defs         # type: ignore [import]

from hsm_secrets.utils import HsmSecretsCtx
from hsm_secrets.x509.def_utils import find_cert_def, merge_x509_info_with_defaults
from hsm_secrets.key_adapters import RSAPrivateKeyHSMAdapter, Ed25519PrivateKeyHSMAdapter, ECPrivateKeyHSMAdapter, PrivateKeyOrAdapter


class CsrAmendMode(Enum):
    REPLACE = "replace"
    ADD = "add"
    KEEP = "keep"


class X509CertBuilder:
    """
    Ephemeral class for building and signing X.509 certificates using the YubiHSM as a key store.
    """
    private_key: PrivateKeyOrAdapter|None
    public_key: CertificatePublicKeyTypes
    csr: x509.CertificateSigningRequest|None
    dn_subject_override: Optional[str] = None

    def __init__(self,
                 hsm_config: HSMConfig,
                 cert_def_info: X509Info,
                 key_or_csr: Union[PrivateKeyOrAdapter, yubihsm.objects.AsymmetricKey, x509.CertificateSigningRequest],
                 dn_subject_override: Optional[str] = None
                 ):
        """
        Initialize a new X.509 certificate builder.

        :param hsm_config: Full HSM configuration object (for defaults etc).
        :param cert_def: Certificate definition to build.
        :param hsm_key: The YubiHSM-stored asymmetric key object to use for signing and for getting public key.
        """
        self.hsm_config = hsm_config
        self.cert_def_info = merge_x509_info_with_defaults(cert_def_info, hsm_config)

        self.dn_subject_override = dn_subject_override

        if isinstance(key_or_csr, x509.CertificateSigningRequest):
            self.csr = key_or_csr
            self.public_key = key_or_csr.public_key()
            self.private_key = None
        elif isinstance(key_or_csr, yubihsm.objects.AsymmetricKey):
            self.public_key = key_or_csr.get_public_key()
            if isinstance(self.public_key, rsa.RSAPublicKey):
                self.private_key = RSAPrivateKeyHSMAdapter(key_or_csr)
            elif isinstance(self.public_key, ed25519.Ed25519PublicKey):
                self.private_key = Ed25519PrivateKeyHSMAdapter(key_or_csr)
            elif isinstance(self.public_key, ec.EllipticCurvePublicKey):
                self.private_key = ECPrivateKeyHSMAdapter(key_or_csr)
            else:
                raise ValueError(f"Unsupported key type: {type(self.public_key)}")
        else:
            self.private_key = key_or_csr
            self.public_key = key_or_csr.public_key()


    def generate_and_self_sign(self) -> x509.Certificate:
        """
        Build and sign a self-signed X.509 certificate.
        """
        assert self.private_key, "No private key available for self-signing"
        builder = self._build_fresh_cert_base()
        return builder.sign(self.private_key, sign_hash_algo_for_key(self.private_key))


    def build_and_sign(self, issuer_cert: x509.Certificate, issuer_key: PrivateKeyOrAdapter) -> x509.Certificate:
        """
        Build and sign an intermediate X.509 certificate with one or more issuer certificates.
        """
        builder = self._build_fresh_cert_base(issuer=issuer_cert)
        return builder.sign(issuer_key, sign_hash_algo_for_key(issuer_key))


    def generate_csr(self) -> x509.CertificateSigningRequest:
        """
        Generate a Certificate Signing Request (CSR) for the certificate definition.
        This is used to request a certificate from an external CA.
        """
        assert self.private_key, "No private key available for CSR generation"
        builder = x509.CertificateSigningRequestBuilder().subject_name(self._mk_name_attribs())

        if self.cert_def_info.basic_constraints is not None:
            builder = builder.add_extension(x509.BasicConstraints(self.cert_def_info.basic_constraints.ca, self.cert_def_info.basic_constraints.path_len), critical=True)

        if self.cert_def_info.attribs and self.cert_def_info.subject_alt_name:
            builder = builder.add_extension(*self._mkext_alt_name())

        if self.cert_def_info.key_usage and self.cert_def_info.key_usage.usages:
            builder = builder.add_extension(*self._mkext_key_usage())

        if self.cert_def_info.extended_key_usage and self.cert_def_info.extended_key_usage.usages:
            builder = builder.add_extension(*self._mkext_extended_key_usage())

        if self.cert_def_info.name_constraints and (self.cert_def_info.name_constraints.permitted or self.cert_def_info.name_constraints.excluded):
            builder = builder.add_extension(*self._mkext_name_constraints())

        return builder.sign(self.private_key, sign_hash_algo_for_key(self.private_key))


    # ----- CSR amendment -----
    def amend_and_sign_csr(
            self,
            issuer_cert: x509.Certificate, issuer_key: PrivateKeyOrAdapter,
            amend_subject: CsrAmendMode = CsrAmendMode.KEEP,
            amend_sans: CsrAmendMode = CsrAmendMode.ADD,
            amend_key_usage: CsrAmendMode = CsrAmendMode.KEEP,
            amend_extended_key_usage: CsrAmendMode = CsrAmendMode.KEEP,
            amend_name_constraints: CsrAmendMode = CsrAmendMode.KEEP,
            amend_basic_constraints: CsrAmendMode = CsrAmendMode.REPLACE,
            amend_crl_urls: CsrAmendMode = CsrAmendMode.ADD,
            amend_ocsp_urls: CsrAmendMode = CsrAmendMode.ADD,
            validity_days: int|None = None
        ) -> x509.Certificate:
        """
        Amend a Certificate Signing Request self.csr using self.cert_def_info as a template,
        and sign it with given issuer_cert.
        """
        assert self.csr, "No CSR available for amendment"

        assert amend_subject != CsrAmendMode.ADD, "Amend mode ADD not supported for subject"
        subject = self.csr.subject if amend_subject==CsrAmendMode.KEEP else self._mk_name_attribs()

        validity = self.cert_def_info.validity_days or validity_days
        assert validity, "Validity days not set in either CSR or X509Info"

        builder = x509.CertificateBuilder(
            issuer_name = issuer_cert.subject,
            subject_name = subject,
            public_key = self.csr.public_key(),
            serial_number = x509.random_serial_number(),
            not_valid_before = datetime.datetime.now(datetime.UTC),
            not_valid_after = datetime.datetime.now(datetime.UTC) + timedelta(days=validity)
        )

        T = TypeVar('T')
        def _amend(
            self: X509CertBuilder,
            builder: x509.CertificateBuilder,
            extclass: type[ExtensionTypeVar],
            amend_mode: CsrAmendMode,
            new_ext_src: Optional[T],
            fn_mk_new_ext: Callable[[T], tuple[ExtensionTypeVar, bool]],
            fn_add: None | Callable[[ExtensionTypeVar, ExtensionTypeVar, bool, bool], tuple[ExtensionTypeVar, bool]]
        ) -> x509.CertificateBuilder:
            """
            Helper function to amend an extension in a CSR.
            Compares the existing extension in the CSR with a template from X509Info,
            and amends it according to the given mode.

            :param builder: The certificate builder to amend.
            :param extclass: The extension class to amend.
            :param amend_mode: The amendment mode (KEEP, REPLACE, ADD).
            :param new_ext_src: The new extension source object (from X509Info).
            :param fn_mk_new_ext: Function to create a new extension from the source object.
            :param fn_add: Function to add two extensions together (for ADD mode). None if not supported for this extension.
            """
            assert self.csr, "Bug: no self.csr, this should have been caught earlier"
            try:
                e = self.csr.extensions.get_extension_for_class(extclass)
                old_ext = e.value if e else None
                old_crit= e.critical if e else False
            except x509.ExtensionNotFound:
                old_ext = None
                old_crit = None

            new_ext, new_crit = None, None
            if new_ext_src is not None:
                new_ext, new_crit = fn_mk_new_ext(new_ext_src)
                assert isinstance(new_ext, extclass), f"Bug: fn_mk_new_ext() result is {type(new_ext)}, expected {extclass}"

            if old_ext is None and new_ext is None:
                return builder

            if amend_mode == CsrAmendMode.KEEP:
                ext = old_ext
                crit = old_crit
            elif amend_mode == CsrAmendMode.REPLACE:
                ext = new_ext
                crit = new_crit
            elif amend_mode == CsrAmendMode.ADD:
                if fn_add is None:
                    raise ValueError(f"ADD mode not supported for extension {extclass}")
                old_crit = old_crit or False
                new_crit = new_crit or False
                if old_ext is not None and new_ext is not None:
                    ext, crit = fn_add(old_ext, new_ext, old_crit, new_crit)
                else:
                    ext = old_ext if old_ext is not None else new_ext
                    crit = old_crit if old_ext is not None else new_crit
            else:
                raise ValueError(f"Invalid amend mode: {amend_mode}")

            if ext is not None:
                builder = builder.add_extension(ext, critical=crit or False)

            return builder


        # Subject Alternative Names (SANs)
        builder = _amend(self, builder, x509.SubjectAlternativeName,
            amend_mode = amend_sans,
            new_ext_src = self.cert_def_info.subject_alt_name,
            fn_mk_new_ext = lambda _nes: self._mkext_alt_name(),
            fn_add = lambda o,n, oc,nc: (x509.SubjectAlternativeName(list(o) + list(n)), oc or nc)
        )

        # Key Usage
        builder = _amend(self, builder, x509.KeyUsage,
            amend_mode = amend_key_usage,
            new_ext_src = self.cert_def_info.key_usage,
            fn_mk_new_ext = lambda _nes: self._mkext_key_usage(),
            fn_add = lambda o,n,oc,nc: (x509.KeyUsage(
                    digital_signature = o.digital_signature or n.digital_signature,
                    content_commitment = o.content_commitment or n.content_commitment,
                    key_encipherment = o.key_encipherment or n.key_encipherment,
                    data_encipherment = o.data_encipherment or n.data_encipherment,
                    key_agreement = o.key_agreement or n.key_agreement,
                    key_cert_sign = o.key_cert_sign or n.key_cert_sign,
                    crl_sign = o.crl_sign or n.crl_sign,
                    # Special handling for these -- encipher_only and decipher_only are undefined unless key_agreement is true:
                    encipher_only = (o.encipher_only if o.key_agreement else False) or (n.encipher_only if n.key_agreement else False),
                    decipher_only = (o.decipher_only if o.key_agreement else False) or (n.decipher_only if n.key_agreement else False)
                ), oc or nc)
        )

        # Extended Key Usage
        builder = _amend(self, builder, x509.ExtendedKeyUsage,
            amend_mode = amend_extended_key_usage,
            new_ext_src = self.cert_def_info.extended_key_usage,
            fn_mk_new_ext = lambda _nes: self._mkext_extended_key_usage(),
            fn_add = lambda o,n,oc,nc: (x509.ExtendedKeyUsage(list(set(o) | set(n))), oc or nc)
        )

        # Name Constraints
        builder = _amend(self, builder, x509.NameConstraints,
            amend_mode = amend_name_constraints,
            new_ext_src = self.cert_def_info.name_constraints,
            fn_mk_new_ext = lambda _nes: self._mkext_name_constraints(),
            fn_add = None
        )

        # Basic Constraints
        builder = _amend(self, builder, x509.BasicConstraints,
            amend_mode = amend_basic_constraints,
            new_ext_src = self.cert_def_info.basic_constraints,
            fn_mk_new_ext = lambda nes: (x509.BasicConstraints(nes.ca, nes.path_len), True),
            fn_add = None
        )

        # CRL Distribution Points
        builder = _amend(self, builder, x509.CRLDistributionPoints,
            amend_mode = amend_crl_urls,
            new_ext_src = self.cert_def_info.crl_distribution_points,
            fn_mk_new_ext = lambda nes: (x509.CRLDistributionPoints([x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(url)], relative_name=None, reasons=None, crl_issuer=None) for url in nes.urls]), False),
            fn_add = lambda o,n,oc,nc: (x509.CRLDistributionPoints(list(set(o) | set(n))), oc or nc)
        )

        # Authority Information Access (OCSP URLs)
        builder = _amend(self, builder, x509.AuthorityInformationAccess,
            amend_mode = amend_ocsp_urls,
            new_ext_src = self.cert_def_info.authority_info_access,
            fn_mk_new_ext = lambda nes: (x509.AuthorityInformationAccess([x509.AccessDescription(
                access_method=x509_oid.AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier(url)) for url in nes.ocsp]), False),
            fn_add = lambda o,n,oc,nc: (x509.AuthorityInformationAccess(list(set(o) | set(n))), oc or nc)
        )

        # Add Subject Key Identifier (SKI) and Authority Key Identifier (AKI)
        for ext in self._mk_ski_and_aki(issuer_cert):
            builder = builder.add_extension(ext, critical=False)

        # Sign the amended CSR
        return builder.sign(issuer_key, sign_hash_algo_for_key(issuer_key))


    # ----- Internal helpers -----

    def _build_fresh_cert_base(self, issuer: Optional[x509.Certificate] = None) -> x509.CertificateBuilder:
        """
        Build a base X.509 certificate object with common attributes.
        Used as a basis for both self-signed and cross-signed certificates.
        NOTE: This makes a fresh builder, ignoring self.csr (even if it's set).
        """
        subject = self._mk_name_attribs()
        builder = x509.CertificateBuilder().subject_name(subject)
        builder = builder.issuer_name(issuer.subject if issuer else subject)

        assert self.cert_def_info.validity_days, "X509Info.validity_days is missing"

        builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        assert self.cert_def_info.validity_days, "X509Info.validity_days is missing"
        builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + timedelta(days=self.cert_def_info.validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(self.public_key)

        def _add_ext_if_len_nonzero(ext: x509.ExtensionType, critical: bool):
            nonlocal builder
            if getattr(ext, '__len__', lambda: 0)() > 0:
                builder = builder.add_extension(ext, critical=critical)

        if self.cert_def_info.attribs and self.cert_def_info.subject_alt_name:
            _add_ext_if_len_nonzero(*self._mkext_alt_name())

        if self.cert_def_info.key_usage and self.cert_def_info.key_usage.usages:
            builder = builder.add_extension(*self._mkext_key_usage())

        if self.cert_def_info.extended_key_usage and self.cert_def_info.extended_key_usage.usages:
            builder = builder.add_extension(*self._mkext_extended_key_usage())

        if self.cert_def_info.name_constraints and (self.cert_def_info.name_constraints.permitted or self.cert_def_info.name_constraints.excluded):
            builder = builder.add_extension(*self._mkext_name_constraints())

        if self.cert_def_info.basic_constraints is not None:
            builder = builder.add_extension(*self._mk_basic_constraints())

        if self.cert_def_info.crl_distribution_points and self.cert_def_info.crl_distribution_points.urls:
            builder = builder.add_extension(*self._mk_crl_distribution_points())

        if self.cert_def_info.authority_info_access and self.cert_def_info.authority_info_access.ocsp:
            builder = builder.add_extension(*self._mk_authority_info_access())

        if self.cert_def_info.certificate_policies and self.cert_def_info.certificate_policies.policies:
            builder = builder.add_extension(*self._mk_cert_policies())

        if self.cert_def_info.policy_constraints:
            builder = builder.add_extension(*self._mk_policy_constraints())

        if self.cert_def_info.inhibit_any_policy:
            builder = builder.add_extension(*self._mk_inhibit_any_policy())

        # Add Subject Key Identifier (SKI) and Authority Key Identifier (AKI)
        for ext in self._mk_ski_and_aki(issuer):
            builder = builder.add_extension(ext, critical=False)

        return builder

    # ----- Extension (OID) converters -----

    def _mk_inhibit_any_policy(self) -> tuple[x509.InhibitAnyPolicy, bool]:
        assert self.cert_def_info.inhibit_any_policy, "X509Info.inhibit_any_policy is missing"
        return x509.InhibitAnyPolicy(self.cert_def_info.inhibit_any_policy.skip_certs), self.cert_def_info.inhibit_any_policy.critical

    def _mk_cert_policies(self) -> tuple[x509.CertificatePolicies, bool]:
        assert self.cert_def_info.certificate_policies, "X509Info.certificate_policies is missing"
        res: List[x509.PolicyInformation] = []
        for p in self.cert_def_info.certificate_policies.policies:
            qualifiers: List[Union[x509.UserNotice, str]] = []
            for q in (p.policy_qualifiers or []):
                if isinstance(q, str):
                    qualifiers.append(q)  # This is a CPS URI
                elif isinstance(q, X509Info.CertificatePolicies.PolicyInformation.UserNotice):
                    notice_ref = x509.NoticeReference(q.notice_ref.organization, q.notice_ref.notice_numbers) if q.notice_ref else None
                    qualifiers.append(x509.UserNotice(notice_ref, q.explicit_text))
                else:
                    raise ValueError(f"Unsupported policy qualifier type: {type(q)}")
            res.append(x509.PolicyInformation(x509.ObjectIdentifier(p.policy_identifier), qualifiers or None))
        return x509.CertificatePolicies(res), self.cert_def_info.certificate_policies.critical

    def _mk_policy_constraints(self) -> tuple[x509.PolicyConstraints, bool]:
        assert self.cert_def_info.policy_constraints, "X509Info.policy_constraints is missing"
        res = x509.PolicyConstraints(
            require_explicit_policy = self.cert_def_info.policy_constraints.require_explicit_policy,
            inhibit_policy_mapping = self.cert_def_info.policy_constraints.inhibit_policy_mapping)
        return res, self.cert_def_info.policy_constraints.critical

    def _mk_basic_constraints(self) -> tuple[x509.BasicConstraints, bool]:
        assert self.cert_def_info.basic_constraints, "X509Info.basic_constraints is missing"
        ca = self.cert_def_info.basic_constraints.ca or False
        path_len: int|None = self.cert_def_info.basic_constraints.path_len  # None if not set = no limit
        if not ca:
            path_len = None
        return x509.BasicConstraints(ca, path_len), True

    def _mk_crl_distribution_points(self) -> tuple[x509.CRLDistributionPoints, bool]:
        assert self.cert_def_info.crl_distribution_points, "X509Info.crl_distribution_points is missing"
        dps = [x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(url)], relative_name=None, reasons=None, crl_issuer=None) for url in self.cert_def_info.crl_distribution_points.urls]
        return x509.CRLDistributionPoints(dps), self.cert_def_info.crl_distribution_points.critical

    def _mk_authority_info_access(self) -> tuple[x509.AuthorityInformationAccess, bool]:
        assert self.cert_def_info.authority_info_access, "X509Info.authority_info_access is missing"
        aia_ocsp = [x509.AccessDescription(
            access_method=x509_oid.AuthorityInformationAccessOID.OCSP,
            access_location=x509.UniformResourceIdentifier(url))
            for url in self.cert_def_info.authority_info_access.ocsp]
        return x509.AuthorityInformationAccess(aia_ocsp), self.cert_def_info.authority_info_access.critical

    def _mk_ski_and_aki(self, issuer: x509.Certificate|None) -> tuple[x509.SubjectKeyIdentifier, x509.AuthorityKeyIdentifier]:
        """
        Create Subject Key Identifier (SKI) and Authority Key Identifier (AKI) extensions.
        """
        subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(self.public_key)

        if issuer:
            issuer_pubkey: CertificatePublicKeyTypes = issuer.public_key()
            assert isinstance(issuer_pubkey, (rsa.RSAPublicKey, ed25519.Ed25519PublicKey, ec.EllipticCurvePublicKey)), f"Unsupported public key type: {type(issuer_pubkey)}"
            authority_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pubkey)
        else:
            authority_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_key_identifier)

        return subject_key_identifier, authority_key_identifier

    def _mk_name_attribs(self) -> x509.Name:
        """
        Parse x500/LDAP-style Distinguished Name (DN) from self.dn_subject_override,
        or if not set, use the attributes from self.cert_def_info.
        """
        if self.dn_subject_override:
            return x509.Name(parse_x500_dn_subject(self.dn_subject_override))

        assert self.cert_def_info.attribs, "X509Info.attribs is missing"
        name_attributes: List[x509.NameAttribute] = [
            x509.NameAttribute(x509_oid.NameOID.COMMON_NAME, self.cert_def_info.attribs.common_name)
        ]
        if self.cert_def_info.attribs.organization:
            name_attributes.append(x509.NameAttribute(x509_oid.NameOID.ORGANIZATION_NAME, self.cert_def_info.attribs.organization))
        if self.cert_def_info.attribs.locality:
            name_attributes.append(x509.NameAttribute(x509_oid.NameOID.LOCALITY_NAME, self.cert_def_info.attribs.locality))
        if self.cert_def_info.attribs.state:
            name_attributes.append(x509.NameAttribute(x509_oid.NameOID.STATE_OR_PROVINCE_NAME, self.cert_def_info.attribs.state))
        if self.cert_def_info.attribs.country:
            name_attributes.append(x509.NameAttribute(x509_oid.NameOID.COUNTRY_NAME, self.cert_def_info.attribs.country))
        return x509.Name(name_attributes)

    def _mkext_alt_name(self) -> tuple[x509.SubjectAlternativeName, bool]:
        assert self.cert_def_info.subject_alt_name, "X509Info.subject_alt_name is missing"
        san: List[x509.GeneralName] = []
        for san_type, names in (self.cert_def_info.subject_alt_name.names or {}).items():
            try:
                san.extend([x509_str_to_general_name(san_type, name) for name in names])
            except Exception as e:
                raise ValueError(f"Failed to map SAN type '{san_type}' (names: '{str(names)}') to a class: {e}")
        return x509.SubjectAlternativeName(san), self.cert_def_info.subject_alt_name.critical

    def _mkext_key_usage(self) -> tuple[x509.KeyUsage, bool]:
        assert self.cert_def_info.key_usage, "X509Info.key_usage is missing"
        u = self.cert_def_info.key_usage.usages
        assert len(u) <= 9, "Non-mapped key usage flags in config. Fix the code here."
        res = x509.KeyUsage(
            digital_signature = "digitalSignature" in u,
            content_commitment = "nonRepudiation" in u,
            key_encipherment = "keyEncipherment" in u,
            data_encipherment = "dataEncipherment" in u,
            key_agreement = "keyAgreement" in u,
            key_cert_sign = "keyCertSign" in u,
            crl_sign = "cRLSign" in u,
            encipher_only = "encipherOnly" in u,
            decipher_only = "decipherOnly" in u)
        return res, self.cert_def_info.key_usage.critical

    def _mkext_extended_key_usage(self) -> tuple[x509.ExtendedKeyUsage, bool]:
        eku_map: Dict[str, x509.ObjectIdentifier] = {
            "serverAuth": x509_oid.ExtendedKeyUsageOID.SERVER_AUTH,
            "clientAuth": x509_oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            "codeSigning": x509_oid.ExtendedKeyUsageOID.CODE_SIGNING,
            "emailProtection": x509_oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
            "timeStamping": x509_oid.ExtendedKeyUsageOID.TIME_STAMPING,
            "OCSPSigning": x509_oid.ExtendedKeyUsageOID.OCSP_SIGNING,
            "anyExtendedKeyUsage": x509_oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
            "smartcardLogon": x509_oid.ExtendedKeyUsageOID.SMARTCARD_LOGON,
            "kerberosPKINITKDC": x509_oid.ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC,
            "ipsecIKE": x509_oid.ExtendedKeyUsageOID.IPSEC_IKE,
            "certificateTransparency": x509_oid.ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY
        }
        assert self.cert_def_info.extended_key_usage, "X509Info.extended_key_usage is missing"
        usages = [eku_map[usage] for usage in self.cert_def_info.extended_key_usage.usages if usage in eku_map]
        return x509.ExtendedKeyUsage(usages), self.cert_def_info.extended_key_usage.critical

    def _mkext_name_constraints(self) -> tuple[x509.NameConstraints, bool]:
        assert self.cert_def_info.name_constraints, "X509Info.name_constraints is missing"

        permitted = []
        if name_dict := self.cert_def_info.name_constraints.permitted:
            for name_type, names in name_dict.items():
                try:
                    permitted.extend([x509_str_to_general_name(name_type, name) for name in names])
                except Exception as e:
                    raise ValueError(f"Failed to map permitted name constraint type '{name_type}' (names: '{str(names)}') to a class: {e}")

        excluded = []
        if name_dict := self.cert_def_info.name_constraints.excluded:
            for name_type, names in name_dict.items():
                try:
                    excluded.extend([x509_str_to_general_name(name_type, name) for name in names])
                except Exception as e:
                    raise ValueError(f"Failed to map excluded name constraint type '{name_type}' (names: '{str(names)}') to a class: {e}")

        if len(set(permitted)) != len(permitted):
            raise ValueError("Duplicate permitted name constraints")
        if len(set(excluded)) != len(excluded):
            raise ValueError("Duplicate excluded name constraints")
        if set(permitted) & set(excluded):
            raise ValueError("Permitted and excluded name constraints overlap")

        res = x509.NameConstraints(
            permitted_subtrees=None if not permitted else permitted,
            excluded_subtrees=None if not excluded else excluded
        )
        return res, self.cert_def_info.name_constraints.critical


def x509_str_to_general_name(gn_type: str, data: str) -> x509.GeneralName:
    def _ip_or_network(n: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network]:
        try:
            return ipaddress.ip_address(n)
        except ValueError:
            return ipaddress.ip_network(n, strict=False)

    type_to_cls = {
        "dns": lambda n: x509.DNSName(n),
        "ip": lambda n: x509.IPAddress(_ip_or_network(n)),
        "rfc822": lambda n: x509.RFC822Name(n),
        "uri": lambda n: x509.UniformResourceIdentifier(n),
        "directory": lambda n: x509.DirectoryName(x509.Name(parse_x500_dn_subject(n))),
        "registered_id": lambda n: x509.RegisteredID(n),
        "upn": lambda n: x509.OtherName(
            x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
            asn1crypto.core.OctetString(asn1crypto.core.UTF8String(n).dump()).dump()
        ),
        "oid": lambda n: x509.OtherName(
            x509.ObjectIdentifier(n.split("=", 1)[0]),
            asn1crypto.core.OctetString(asn1crypto.core.UTF8String(n.split("=", 1)[1]).dump()).dump()
        )
    }
    if gn_type not in type_to_cls:
        raise ValueError(f"Unsupported general name type: {gn_type}")
    return type_to_cls[gn_type](data)


def parse_x500_dn_subject(subject_string: str) -> List[x509.NameAttribute]:
    """Parse a comma-separated x500/LDAP style DN string into a list of NameAttributes.
    Example: "CN=John Doe, O=Company, C=US" -> [NameAttribute(NameOID.COMMON_NAME, "John Doe"), ...]
    """
    subject_attrs = []

    # X.500/LDAP abbreviations
    # These are checked first, and if not found, check against x509_oid.NameOID.
    # Finally, try to parse the string as an OID number.
    name_oid_abbrev = {
        'CN': x509_oid.NameOID.COMMON_NAME,
        'C': x509_oid.NameOID.COUNTRY_NAME,
        'L': x509_oid.NameOID.LOCALITY_NAME,
        'ST': x509_oid.NameOID.STATE_OR_PROVINCE_NAME,
        'STREET': x509_oid.NameOID.STREET_ADDRESS,
        'O': x509_oid.NameOID.ORGANIZATION_NAME,
        'OU': x509_oid.NameOID.ORGANIZATIONAL_UNIT_NAME,
        'DC': x509_oid.NameOID.DOMAIN_COMPONENT,
        'UID': x509_oid.NameOID.USER_ID,
        'E': x509_oid.NameOID.EMAIL_ADDRESS,
        'SERIALNUMBER': x509_oid.NameOID.SERIAL_NUMBER,
        'T': x509_oid.NameOID.TITLE,
        'G': x509_oid.NameOID.GENERATION_QUALIFIER,
        'SURNAME': x509_oid.NameOID.SURNAME,
        'GIVENNAME':x509_oid.NameOID.GIVEN_NAME,
    }

    for item in subject_string.split(','):
        key, value = item.strip().split('=', 1)
        key = key.strip().upper()
        value = value.strip()

        if key in name_oid_abbrev:
            oid = name_oid_abbrev[key]
        elif hasattr(x509_oid.NameOID, key):
            oid = getattr(x509_oid.NameOID, key)
        else:
            try:
                oid = x509_oid.ObjectIdentifier(key)
            except ValueError:
                raise ValueError(f"Unsupported subject attribute: {key}. "
                                 f"Use a standard abbreviation or a valid OID.")

        subject_attrs.append(x509.NameAttribute(oid, value))

    return subject_attrs


def get_issuer_cert_and_key(ctx: HsmSecretsCtx, ses, ca_id: str|HSMKeyID) -> tuple[x509.Certificate, PrivateKeyOrAdapter]:
    issuer_cert_def = ctx.conf.find_def(ca_id, HSMOpaqueObject)
    issuer_x509_def = find_cert_def(ctx.conf, issuer_cert_def.id)
    assert issuer_x509_def, f"CA cert ID not found: 0x{issuer_cert_def.id:04x}"
    return ses.get_certificate(issuer_cert_def), ses.get_private_key(issuer_x509_def.key)


def sign_hash_algo_for_key(key: PrivateKeyOrAdapter) -> hashes.SHA256|hashes.SHA384|hashes.SHA512|None:
    if isinstance(key, (Ed25519PrivateKeyHSMAdapter, ed25519.Ed25519PrivateKey)):
        return None
    elif isinstance(key, (RSAPrivateKeyHSMAdapter, rsa.RSAPrivateKey)):
        return hashes.SHA256()
    elif isinstance(key, (ECPrivateKeyHSMAdapter, ec.EllipticCurvePrivateKey)):
        if key.key_size <= 256:
            return hashes.SHA256()
        elif key.key_size <= 384:
            return hashes.SHA384()
        else:
            return hashes.SHA512()
