from typing import Any, Callable
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from datetime import timedelta
from enum import Enum

from hsm_secrets.utils import cli_error, cli_info, cli_warn

class IssueSeverity(Enum):
    NOTICE = 1
    WARNING = 2
    ERROR = 3

class BaseCertificateChecker:
    """
    Base class for sanity checkers for all X.509 certificates.
    """
    def __init__(self, certificate: x509.Certificate):
        self.certificate = certificate
        self.issues: list[tuple[IssueSeverity, str]] = []

    def check(self):
        self._check_key_usage()
        self._check_extended_key_usage()
        self._check_subject_alternative_name()
        self._check_basic_constraints()
        self._check_key_type_and_size()
        self._check_validity_period()
        self._check_subject_and_issuer()
        self._check_signature_algorithm()
        self._check_revocation_info()
        self._check_name_constraints()
        self._check_key_identifiers()
        self._check_policy_extensions()
        self._check_key_usage_and_extended_key_usage_consistency()
        self._check_subject_common_name_consistency()

    def _add_issue(self, message: str, severity: IssueSeverity):
        self.issues.append((severity, message))

    def _check_key_usage(self):
        try:
            key_usage = self.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
            self._check_specific_key_usage(key_usage)
        except x509.ExtensionNotFound:
            self._add_issue("KeyUsage extension not found", IssueSeverity.ERROR)

    def _check_specific_key_usage(self, key_usage: x509.KeyUsage):
        # To be implemented by subclasses
        pass

    def _check_extended_key_usage(self):
        is_ca = False
        try:
            bc = self.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca = bc.ca
        except x509.ExtensionNotFound:
            pass

        if not is_ca:
            try:
                ext_key_usage = self.certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                self._check_specific_extended_key_usage(ext_key_usage)
            except x509.ExtensionNotFound:
                self._add_issue("ExtendedKeyUsage extension not found for a non-CA certificate", IssueSeverity.ERROR)

    def _check_specific_extended_key_usage(self, ext_key_usage: x509.ExtendedKeyUsage):
        # To be implemented by subclasses
        pass

    def _check_subject_alternative_name(self):
        try:
            san = self.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if not san:
                self._add_issue("SubjectAlternativeName extension is empty", IssueSeverity.WARNING)
            self._check_specific_subject_alternative_name(san)
        except x509.ExtensionNotFound:
            self._add_issue("SubjectAlternativeName extension not found", IssueSeverity.ERROR)

    def _check_specific_subject_alternative_name(self, san: x509.SubjectAlternativeName):
        # To be implemented by subclasses
        pass

    def _check_basic_constraints(self):
        try:
            bc = self.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            if bc.ca:
                self._add_issue("BasicConstraints: CA flag is True for an end-entity certificate", IssueSeverity.ERROR)
            elif bc.path_length is not None:
                self._add_issue(f"Path length constraint is set on a non-CA certificate", IssueSeverity.ERROR)
        except x509.ExtensionNotFound:
            self._add_issue("BasicConstraints extension not found", IssueSeverity.WARNING)

    def _check_key_type_and_size(self):
        public_key = self.certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < 2048:
                self._add_issue(f"RSA key size ({public_key.key_size}) is less than 2048 bits", IssueSeverity.ERROR)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if public_key.curve.key_size < 256:
                self._add_issue(f"EC key size ({public_key.curve.key_size}) is less than 256 bits", IssueSeverity.ERROR)
        elif not isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            self._add_issue(f"Unsupported key type: {type(public_key)}", IssueSeverity.ERROR)

    def _check_validity_period(self):
        max_validity = timedelta(days=398)
        if (self.certificate.not_valid_after_utc - self.certificate.not_valid_before_utc) > max_validity:
            self._add_issue("Certificate validity period exceeds 398 days", IssueSeverity.NOTICE)

    def _check_subject_and_issuer(self):
        if not self.certificate.subject:
            self._add_issue("Subject DN is empty", IssueSeverity.ERROR)
        if not self.certificate.issuer:
            self._add_issue("Issuer DN is empty", IssueSeverity.ERROR)

    def _check_signature_algorithm(self):
        weak_algorithms = {
            x509.SignatureAlgorithmOID.RSA_WITH_MD5,
            x509.SignatureAlgorithmOID.RSA_WITH_SHA1,
            x509.SignatureAlgorithmOID.DSA_WITH_SHA1,
            x509.SignatureAlgorithmOID.ECDSA_WITH_SHA1,
        }
        if self.certificate.signature_algorithm_oid in weak_algorithms:
            self._add_issue(f"Weak signature algorithm used: {self.certificate.signature_algorithm_oid._name}", IssueSeverity.ERROR)

    def _check_revocation_info(self):
        has_crl = False
        has_ocsp = False
        try:
            self.certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            has_crl = True
        except x509.ExtensionNotFound:
            pass

        try:
            aia = self.certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            has_ocsp = any(desc.access_method == ExtendedKeyUsageOID.OCSP_SIGNING for desc in aia)
        except x509.ExtensionNotFound:
            pass

        if not (has_crl or has_ocsp):
            self._add_issue("Neither CRL nor OCSP revocation information is present", IssueSeverity.WARNING)

    def _check_name_constraints(self):
        try:
            nc = self.certificate.extensions.get_extension_for_class(x509.NameConstraints)
            if not nc.critical:
                self._add_issue("NameConstraints extension should be marked critical", IssueSeverity.WARNING)
        except x509.ExtensionNotFound:
            pass

    def _check_key_identifiers(self):
        try:
            self.certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        except x509.ExtensionNotFound:
            self._add_issue("SubjectKeyIdentifier extension not found", IssueSeverity.WARNING)

        try:
            self.certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        except x509.ExtensionNotFound:
            self._add_issue("AuthorityKeyIdentifier extension not found", IssueSeverity.WARNING)

    def _check_policy_extensions(self):
        #try:
        #    self.certificate.extensions.get_extension_for_class(x509.CertificatePolicies)
        #except x509.ExtensionNotFound:
        #    self._add_issue("CertificatePolicies extension not found", IssueSeverity.NOTICE)
        pass

    def _check_key_usage_and_extended_key_usage_consistency(self):
        try:
            ku = self.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
            eku = self.certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value

            if ExtendedKeyUsageOID.SERVER_AUTH in eku or ExtendedKeyUsageOID.CLIENT_AUTH in eku:
                if not ku.digital_signature:
                    self._add_issue("digitalSignature not set in KeyUsage, but serverAuth or clientAuth is present in ExtendedKeyUsage", IssueSeverity.ERROR)

            if ExtendedKeyUsageOID.EMAIL_PROTECTION in eku:
                if not (ku.digital_signature or ku.key_encipherment or ku.key_agreement):
                    self._add_issue("Neither digitalSignature, keyEncipherment, nor keyAgreement is set in KeyUsage, but emailProtection is present in ExtendedKeyUsage", IssueSeverity.ERROR)
        except x509.ExtensionNotFound:
            pass  # Already checked in previous methods

    def _check_subject_common_name_consistency(self):
        try:
            san = self.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            common_names = self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if common_names:
                cn_value_b = common_names[0].value
                cn_value = bytes(cn_value_b).decode() if not isinstance(cn_value_b, str) else cn_value_b
                if not cn_value.strip():
                    self._add_issue("Subject CommonName is empty (but not null)", IssueSeverity.ERROR)
                self._check_specific_subject_common_name_consistency(cn_value, san)
        except x509.ExtensionNotFound:
            pass  # Already checked in previous methods

    def _check_specific_subject_common_name_consistency(self, cn_value: str, san: x509.SubjectAlternativeName):
        # To be implemented by subclasses
        pass

    @staticmethod
    def show_issues(issues: list[tuple[IssueSeverity, str]]):
        notices = [message for severity, message in issues if severity == IssueSeverity.NOTICE]
        warnings = [message for severity, message in issues if severity == IssueSeverity.WARNING]
        errors = [message for severity, message in issues if severity == IssueSeverity.ERROR]

        if not (notices or warnings or errors):
            return

        prn: Any = cli_error if errors else (cli_warn if warnings else cli_info)
        prn("Detected issues:")

        if notices:
            cli_info(" - ℹ️ Cert notices:")
            for msg in notices:
                cli_info(f"   - {msg}")

        if warnings:
            cli_warn(" - ⚠️ Cert warnings:")
            for msg in warnings:
                cli_warn(f"   - {msg}")

        if errors:
            cli_error(" - ⛔️ Cert errors:")
            for msg in errors:
                cli_error(f"   - {msg}")


    def check_and_show_issues(self) -> list[tuple[IssueSeverity, str]]:
        self.check()
        self.show_issues(self.issues)
        return self.issues


# ------


class X509CACertificateChecker(BaseCertificateChecker):
    """
    Base sanity checker class for CA certificates (both root and intermediate).
    """
    def _check_basic_constraints(self):
        try:
            bc = self.certificate.extensions.get_extension_for_class(x509.BasicConstraints)
            if not bc.critical:
                self._add_issue("BasicConstraints extension not marked critical for a CA", IssueSeverity.WARNING)
            if not bc.value.ca:
                self._add_issue("BasicConstraints: CA flag is False for a CA", IssueSeverity.ERROR)
            self._check_path_length_constraint(bc.value.path_length)
        except x509.ExtensionNotFound:
            self._add_issue("BasicConstraints extension not found", IssueSeverity.ERROR)

    def _check_path_length_constraint(self, path_length):
        # To be implemented by subclasses
        pass

    def _check_specific_key_usage(self, key_usage: x509.KeyUsage):
        if not key_usage.key_cert_sign:
            self._add_issue("KeyUsage does not include keyCertSign", IssueSeverity.ERROR)
        if not key_usage.digital_signature:
            self._add_issue("KeyUsage does not include digitalSignature", IssueSeverity.WARNING)
        if key_usage.key_encipherment:
            self._add_issue("KeyUsage includes keyEncipherment, which is not typically needed for CA certificates", IssueSeverity.WARNING)

    def _check_name_constraints(self):
        #try:
        #    nc = self.certificate.extensions.get_extension_for_class(x509.NameConstraints)
        #    if not nc.critical:
        #        self._add_issue("NameConstraints extension should be marked critical", IssueSeverity.WARNING)
        #except x509.ExtensionNotFound:
        #    self._add_issue("NameConstraints extension not found", IssueSeverity.NOTICE)
        pass

    def _check_policy_extensions(self):
        try:
            cp = self.certificate.extensions.get_extension_for_class(x509.CertificatePolicies)
            if not cp.value:
                self._add_issue("CertificatePolicies extension is empty", IssueSeverity.WARNING)
        except x509.ExtensionNotFound:
            pass

        try:
            pc = self.certificate.extensions.get_extension_for_class(x509.PolicyConstraints)
            self._add_issue(f"PolicyConstraints extension found with values: {pc.value}", IssueSeverity.NOTICE)
        except x509.ExtensionNotFound:
            pass

    def _check_validity_period(self):
        #max_validity = timedelta(days=5*365)  # 5 years
        #if (self.certificate.not_valid_after - self.certificate.not_valid_before) > max_validity:
        #    self._add_issue("Certificate validity period exceeds 5 years", IssueSeverity.NOTICE)
        pass

    def _check_key_type_and_size(self):
        public_key = self.certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < 2048:
                self._add_issue(f"RSA key size ({public_key.key_size}) is less than 2048 bits", IssueSeverity.ERROR)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if public_key.curve.key_size < 256:
                self._add_issue(f"EC key size ({public_key.curve.key_size}) is less than 256 bits", IssueSeverity.ERROR)

    def _check_revocation_info(self):
        has_crl = False
        has_ocsp = False
        try:
            self.certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            has_crl = True
        except x509.ExtensionNotFound:
            pass

        try:
            aia = self.certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            has_ocsp = any(desc.access_method == ExtendedKeyUsageOID.OCSP_SIGNING for desc in aia)
        except x509.ExtensionNotFound:
            pass

        if not (has_crl or has_ocsp):
            self._add_issue("Neither CRL nor OCSP revocation information is present", IssueSeverity.WARNING)

    # CA certificates don't need to have a SAN extension, so don't check it
    def _check_subject_alternative_name(self):
        pass

    def _check_specific_subject_alternative_name(self, san: x509.SubjectAlternativeName):
        pass

    def _check_subject_common_name_consistency(self):
        pass


class X509RootCACertificateChecker(X509CACertificateChecker):
    """
    Sanity checker class for root CA certificates.
    """
    def _check_path_length_constraint(self, path_length):
        if path_length is not None:
            self._add_issue(f"Root CA has a path length constraint of {path_length}. Consider removing it for maximum flexibility.", IssueSeverity.NOTICE)

    def _check_revocation_info(self):
        # Root CAs typically don't have revocation info
        pass

    def _check_name_constraints(self):
        try:
            self.certificate.extensions.get_extension_for_class(x509.NameConstraints)
            self._add_issue("NameConstraints extension found. This is unusual for a root CA.", IssueSeverity.WARNING)
        except x509.ExtensionNotFound:
            pass  # Expected for root CA

    def _check_extended_key_usage(self):
        try:
            self.certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            self._add_issue("ExtendedKeyUsage extension found. This is unusual for a root CA.", IssueSeverity.WARNING)
        except x509.ExtensionNotFound:
            pass  # Expected for root CA



class X509IntermediateCACertificateChecker(X509CACertificateChecker):
    """
    Sanity checker class for intermediate CA certificates.
    """
    def _check_path_length_constraint(self, path_length):
        if path_length is None:
            self._add_issue("No path length constraint set.", IssueSeverity.NOTICE)
        elif path_length > 0:
            self._add_issue(f"Path length constraint is set to {path_length}. Ensure you need this intermediate CA to sign more intermediates.", IssueSeverity.NOTICE)
