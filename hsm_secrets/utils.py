from typing import Optional, Sequence

from click import echo
import click

from yubihsm import YubiHsm # type: ignore
from yubihsm.core import AuthSession
from yubihsm.defs import CAPABILITY, ALGORITHM

from yubikit.hsmauth import HsmAuthSession  #, DEFAULT_MANAGEMENT_KEY
from ykman import scripting
import yubikit.core

from hsm_secrets.config import AsymmetricAlgorithm, AsymmetricCapabilityName, AuthKeyCapabilityName, HSMConfig



def ask_for_password(title: str) -> str:
    return click.prompt(f"Enter the password for {title}", hide_input=True)


def connect_hsm_and_auth_with_yubikey(config: HSMConfig, auth_key_id: int, yubikey_slot_label: str, yubikey_password: Optional[str] = None) -> AuthSession:
    """
    Connects to a YubHSM and authenticates a session using the first YubiKey found.

    Args:
        username (str): The username for the key labels.
        config (Config): The configuration object containing the connector URL and user.
        auth_key_id (int): The ID of the authentication key.
        yubikey_slot_label (str): The label of the YubiKey slot to use for authenticating with the HSM.
        yubikey_password (Optional[str]): The password for the YubiKey HSM slot. If None, the user is asked for the password.

    Returns:
        HsmAuthSession: The authenticated HSM session.
    """
    try:
        yubikey = scripting.single()    # Connect to the first YubiKey found
        hsmauth = HsmAuthSession(yubikey.smart_card())
        hsm = YubiHsm.connect(str(config.general.connector_url))

        symmetric_auth = hsm.init_session(auth_key_id)
        pwd = yubikey_password or ask_for_password(f"YubiKey HSM slot '{yubikey_slot_label}'")

        echo(f"Authenticating... " + click.style("(Touch your YubiKey if it blinks)", fg='yellow'))
        session_keys = hsmauth.calculate_session_keys_symmetric(
            label=yubikey_slot_label,
            credential_password=pwd,
            context=symmetric_auth.context)

        session = symmetric_auth.authenticate(*session_keys)

        echo(f"Session authenticated Ok.")
        return session

    except yubikit.core.InvalidPinError as e:
        echo(click.style("InvalidPinError", fg='red') + f" for YubiKey HSM slot '{yubikey_slot_label}':")
        echo(click.style(str(e), fg='red'))
        exit(1)


def domains_int(domains: Sequence[int]) -> int:
    """
    Convert a set of domain numbers to a 16-bit bitfield.
    """
    bitfield = 0
    for domain in set(domains):
        if 1 <= domain <= 16:
            bitfield |= (1 << (domain - 1))
        else:
            raise ValueError(f"Domain {domain} is out of range. Must be between 1 and 16.")
    return bitfield


def encode_capabilities(names: Sequence[AsymmetricCapabilityName]|set[AsymmetricCapabilityName]) -> CAPABILITY:
    """
    Convert a list of capability names to a bitfield.
    """
    mapping = {
        "get-opaque": CAPABILITY.GET_OPAQUE,
        "put-opaque": CAPABILITY.PUT_OPAQUE,
        "put-authentication-key": CAPABILITY.PUT_AUTHENTICATION_KEY,
        "put-asymmetric-key": CAPABILITY.PUT_ASYMMETRIC,
        "generate-asymmetric-key": CAPABILITY.GENERATE_ASYMMETRIC_KEY,
        "sign-pkcs": CAPABILITY.SIGN_PKCS,
        "sign-pss": CAPABILITY.SIGN_PSS,
        "sign-ecdsa": CAPABILITY.SIGN_ECDSA,
        "sign-eddsa": CAPABILITY.SIGN_EDDSA,
        "decrypt-pkcs": CAPABILITY.DECRYPT_PKCS,
        "decrypt-oaep": CAPABILITY.DECRYPT_OAEP,
        "derive-ecdh": CAPABILITY.DERIVE_ECDH,
        "export-wrapped": CAPABILITY.EXPORT_WRAPPED,
        "import-wrapped": CAPABILITY.IMPORT_WRAPPED,
        "put-wrap-key": CAPABILITY.PUT_WRAP_KEY,
        "generate-wrap-key": CAPABILITY.GENERATE_WRAP_KEY,
        "exportable-under-wrap": CAPABILITY.EXPORTABLE_UNDER_WRAP,
        "set-option": CAPABILITY.SET_OPTION,
        "get-option": CAPABILITY.GET_OPTION,
        "get-pseudo-random": CAPABILITY.GET_PSEUDO_RANDOM,
        "put-mac-key": CAPABILITY.PUT_HMAC_KEY,
        "generate-hmac-key": CAPABILITY.GENERATE_HMAC_KEY,
        "sign-hmac": CAPABILITY.SIGN_HMAC,
        "verify-hmac": CAPABILITY.VERIFY_HMAC,
        "get-log-entries": CAPABILITY.GET_LOG_ENTRIES,
        "sign-ssh-certificate": CAPABILITY.SIGN_SSH_CERTIFICATE,
        "get-template": CAPABILITY.GET_TEMPLATE,
        "put-template": CAPABILITY.PUT_TEMPLATE,
        "reset-device": CAPABILITY.RESET_DEVICE,
        "decrypt-otp": CAPABILITY.DECRYPT_OTP,
        "create-otp-aead": CAPABILITY.CREATE_OTP_AEAD,
        "randomize-otp-aead": CAPABILITY.RANDOMIZE_OTP_AEAD,
        "rewrap-from-otp-aead-key": CAPABILITY.REWRAP_FROM_OTP_AEAD_KEY,
        "rewrap-to-otp-aead-key": CAPABILITY.REWRAP_TO_OTP_AEAD_KEY,
        "sign-attestation-certificate": CAPABILITY.SIGN_ATTESTATION_CERTIFICATE,
        "put-otp-aead-key": CAPABILITY.PUT_OTP_AEAD_KEY,
        "generate-otp-aead-key": CAPABILITY.GENERATE_OTP_AEAD_KEY,
        "wrap-data": CAPABILITY.WRAP_DATA,
        "unwrap-data": CAPABILITY.UNWRAP_DATA,
        "delete-opaque": CAPABILITY.DELETE_OPAQUE,
        "delete-authentication-key": CAPABILITY.DELETE_AUTHENTICATION_KEY,
        "delete-asymmetric-key": CAPABILITY.DELETE_ASYMMETRIC_KEY,
        "delete-wrap-key": CAPABILITY.DELETE_WRAP_KEY,
        "delete-hmac-key": CAPABILITY.DELETE_HMAC_KEY,
        "delete-template": CAPABILITY.DELETE_TEMPLATE,
        "delete-otp-aead-key": CAPABILITY.DELETE_OTP_AEAD_KEY,
        "change-authentication-key": CAPABILITY.CHANGE_AUTHENTICATION_KEY,
        "put-symmetric-key": CAPABILITY.PUT_SYMMETRIC_KEY,
        "generate-symmetric-key": CAPABILITY.GENERATE_SYMMETRIC_KEY,
        "delete-symmetric-key": CAPABILITY.DELETE_SYMMETRIC_KEY,
        "decrypt-ecb": CAPABILITY.DECRYPT_ECB,
        "encrypt-ecb": CAPABILITY.ENCRYPT_ECB,
        "decrypt-cbc": CAPABILITY.DECRYPT_CBC,
        "encrypt-cbc": CAPABILITY.ENCRYPT_CBC,
    }
    names = set(names)
    if 'all' in names:
        return CAPABILITY.ALL
    elif 'none' in names:
        return CAPABILITY.NONE
    else:
        res = CAPABILITY.NONE
        for name in names:
            if name not in mapping:
                raise ValueError(f"Unknown capability name '{name}'")
            res |= mapping[name]
        return res


def encode_algorithm(name_literal: str|AsymmetricAlgorithm) -> ALGORITHM:
    mapping = {
        "rsa-pkcs1-sha1": ALGORITHM.RSA_PKCS1_SHA1,
        "rsa-pkcs1-sha256": ALGORITHM.RSA_PKCS1_SHA256,
        "rsa-pkcs1-sha384": ALGORITHM.RSA_PKCS1_SHA384,
        "rsa-pkcs1-sha512": ALGORITHM.RSA_PKCS1_SHA512,
        "rsa-pss-sha1": ALGORITHM.RSA_PSS_SHA1,
        "rsa-pss-sha256": ALGORITHM.RSA_PSS_SHA256,
        "rsa-pss-sha384": ALGORITHM.RSA_PSS_SHA384,
        "rsa-pss-sha512": ALGORITHM.RSA_PSS_SHA512,
        "rsa2048": ALGORITHM.RSA_2048,
        "rsa3072": ALGORITHM.RSA_3072,
        "rsa4096": ALGORITHM.RSA_4096,
        "ecp256": ALGORITHM.EC_P256,
        "ecp384": ALGORITHM.EC_P384,
        "ecp521": ALGORITHM.EC_P521,
        "eck256": ALGORITHM.EC_K256,
        "ecbp256": ALGORITHM.EC_BP256,
        "ecbp384": ALGORITHM.EC_BP384,
        "ecbp512": ALGORITHM.EC_BP512,
        "hmac-sha1": ALGORITHM.HMAC_SHA1,
        "hmac-sha256": ALGORITHM.HMAC_SHA256,
        "hmac-sha384": ALGORITHM.HMAC_SHA384,
        "hmac-sha512": ALGORITHM.HMAC_SHA512,
        "ecdsa-sha1": ALGORITHM.EC_ECDSA_SHA1,
        "ecdh": ALGORITHM.EC_ECDH,
        "rsa-oaep-sha1": ALGORITHM.RSA_OAEP_SHA1,
        "rsa-oaep-sha256": ALGORITHM.RSA_OAEP_SHA256,
        "rsa-oaep-sha384": ALGORITHM.RSA_OAEP_SHA384,
        "rsa-oaep-sha512": ALGORITHM.RSA_OAEP_SHA512,
        "aes128-ccm-wrap": ALGORITHM.AES128_CCM_WRAP,
        "opaque-data": ALGORITHM.OPAQUE_DATA,
        "opaque-x509-certificate": ALGORITHM.OPAQUE_X509_CERTIFICATE,
        "mgf1-sha1": ALGORITHM.RSA_MGF1_SHA1,
        "mgf1-sha256": ALGORITHM.RSA_MGF1_SHA256,
        "mgf1-sha384": ALGORITHM.RSA_MGF1_SHA384,
        "mgf1-sha512": ALGORITHM.RSA_MGF1_SHA512,
        "template-ssh": ALGORITHM.TEMPLATE_SSH,
        "aes128-yubico-otp": ALGORITHM.AES128_YUBICO_OTP,
        "aes128-yubico-authentication": ALGORITHM.AES128_YUBICO_AUTHENTICATION,
        "aes192-yubico-otp": ALGORITHM.AES192_YUBICO_OTP,
        "aes256-yubico-otp": ALGORITHM.AES256_YUBICO_OTP,
        "aes192-ccm-wrap": ALGORITHM.AES192_CCM_WRAP,
        "aes256-ccm-wrap": ALGORITHM.AES256_CCM_WRAP,
        "ecdsa-sha256": ALGORITHM.EC_ECDSA_SHA256,
        "ecdsa-sha384": ALGORITHM.EC_ECDSA_SHA384,
        "ecdsa-sha512": ALGORITHM.EC_ECDSA_SHA512,
        "ed25519": ALGORITHM.EC_ED25519,
        "ecp224": ALGORITHM.EC_P224
    }
    if mapping.get(name_literal.lower(), None) is None:
        raise ValueError(f"Unknown algorithm name '{name_literal}'")
    return mapping[name_literal.lower()]
