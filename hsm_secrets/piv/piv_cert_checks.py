from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from typing import List, Literal

from hsm_secrets.x509.cert_checker import BaseCertificateChecker, IssueSeverity

# ------

class PIVDomainControllerCertificateChecker(BaseCertificateChecker):
    def _check_specific_key_usage(self, key_usage: x509.KeyUsage):
        if not key_usage.digital_signature:
            self._add_issue("KeyUsage does not include digitalSignature", IssueSeverity.ERROR)
        if not key_usage.key_encipherment:
            self._add_issue("KeyUsage does not include keyEncipherment", IssueSeverity.ERROR)

    def _check_specific_extended_key_usage(self, ext_key_usage: x509.ExtendedKeyUsage):
        if ExtendedKeyUsageOID.SERVER_AUTH not in ext_key_usage:
            self._add_issue("ExtendedKeyUsage does not include serverAuth", IssueSeverity.ERROR)
        if ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC not in ext_key_usage:
            self._add_issue("ExtendedKeyUsage does not include KerberosKDC (PKINIT)", IssueSeverity.ERROR)

    def _check_specific_subject_alternative_name(self, san: x509.SubjectAlternativeName):
        has_dns = any(isinstance(name, x509.DNSName) for name in san)
        has_upn = any(isinstance(name, x509.OtherName) and name.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3" for name in san)

        if not has_dns:
            self._add_issue("SubjectAlternativeName does not include a DNS name", IssueSeverity.ERROR)
        if has_upn:
            self._add_issue("DC certificates does not usually include a UPN (User Principal Name)", IssueSeverity.NOTICE)

    def _check_specific_subject_common_name_consistency(self, cn_value: str, san: x509.SubjectAlternativeName):
        dns_names = [name.value for name in san if isinstance(name, x509.DNSName)]
        if cn_value not in dns_names:
            self._add_issue(f"Subject Common Name '{cn_value}' is not present in SubjectAlternativeName DNS names", IssueSeverity.WARNING)

    def _check_subject_and_issuer(self):
        super()._check_subject_and_issuer()
        subject = self.certificate.subject
        org_name = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        #if not org_name:
        #    self._add_issue("Subject DN does not include Organization Name", IssueSeverity.WARNING)

# ------

class PIVUserCertificateChecker(BaseCertificateChecker):
    def __init__(self, certificate: x509.Certificate, os_type: Literal["windows", "other"]):
        super().__init__(certificate)
        self.os_type = os_type

    def _check_specific_key_usage(self, key_usage: x509.KeyUsage):
        if not key_usage.digital_signature:
            self._add_issue("KeyUsage does not include digitalSignature", IssueSeverity.ERROR)
        if not key_usage.key_encipherment:
            self._add_issue("KeyUsage does not include keyEncipherment", IssueSeverity.WARNING)

    def _check_specific_extended_key_usage(self, ext_key_usage: x509.ExtendedKeyUsage):
        if ExtendedKeyUsageOID.CLIENT_AUTH not in ext_key_usage:
            self._add_issue("ExtendedKeyUsage does not include clientAuth", IssueSeverity.ERROR)
        if ExtendedKeyUsageOID.SMARTCARD_LOGON not in ext_key_usage:
            self._add_issue("ExtendedKeyUsage does not include smartCardLogon", IssueSeverity.ERROR)
        #if ExtendedKeyUsageOID.EMAIL_PROTECTION not in ext_key_usage:
        #    self._add_issue("ExtendedKeyUsage does not include emailProtection", IssueSeverity.NOTICE)

    def _check_specific_subject_alternative_name(self, san: x509.SubjectAlternativeName):
        has_upn = any(isinstance(name, x509.OtherName) and name.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3" for name in san)
        has_rfc822 = any(isinstance(name, x509.RFC822Name) for name in san)

        if not has_upn and self.os_type == "windows":
            self._add_issue("SubjectAlternativeName does not include a UPN (User Principal Name)", IssueSeverity.WARNING)
        if not has_rfc822 and self.os_type == "other":
            self._add_issue("SubjectAlternativeName does not include an RFC822 (email) name", IssueSeverity.NOTICE)

    def _check_specific_subject_common_name_consistency(self, cn_value: str, san: x509.SubjectAlternativeName):
        # NOTE: these checks are pretty permissive
        upn = next((name.value.decode() for name in san if isinstance(name, x509.OtherName) and name.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3"), None)
        if upn:
            upn_username = upn.split('@')[0]
            if cn_value.lower() not in upn.lower() and upn_username.lower() not in cn_value.lower():
                self._add_issue(f"Subject CN '{cn_value}' does not appear to be related to UPN '{upn}'", IssueSeverity.NOTICE)

        rfc822_name = next((name.value for name in san if isinstance(name, x509.RFC822Name)), None)
        if rfc822_name:
            if cn_value.lower() not in rfc822_name.lower() and '@' in rfc822_name:
                email_username = rfc822_name.split('@')[0]
                if email_username.lower() not in cn_value.lower():
                    self._add_issue(f"Subject CN '{cn_value}' does not appear to be related to email '{rfc822_name}'", IssueSeverity.NOTICE)


    def _check_subject_and_issuer(self):
        super()._check_subject_and_issuer()
        subject = self.certificate.subject
        common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not common_name:
            self._add_issue("Subject DN does not include Common Name", IssueSeverity.WARNING)

        org_name = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if not org_name:
            self._add_issue("Subject DN does not include Organization Name", IssueSeverity.WARNING)

    def _check_policy_extensions(self):
        super()._check_policy_extensions()
        try:
            cert_policies = self.certificate.extensions.get_extension_for_class(x509.CertificatePolicies).value
            # US Federal PIV-I policy (not required for non-US-government PIVs)
            #has_piv_auth_policy = any(policy.policy_identifier.dotted_string == "2.16.840.1.101.3.2.1.3.13" for policy in cert_policies)
            #if not has_piv_auth_policy:
            #    self._add_issue("Certificate does not include the PIV Authentication policy OID (2.16.840.1.101.3.2.1.3.13)", IssueSeverity.WARNING)
        except x509.ExtensionNotFound:
            pass  # Already handled in base class
