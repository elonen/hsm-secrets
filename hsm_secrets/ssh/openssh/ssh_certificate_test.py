# ssh_certificate_test.py

import argparse
import base64
import sys

from hsm_secrets.ssh.openssh.signing import sign_ssh_cert, verify_ssh_cert
from hsm_secrets.ssh.openssh.ssh_certificate import cert_for_ssh_pub_id, OpenSSHCertificate, RSACertificate, ECDSACertificate, ED25519Certificate

from cryptography.hazmat.primitives.serialization import ssh
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec

def print_certificate_details(cert: OpenSSHCertificate) -> None:
    print(f"  Key Cipher: {cert.cert_cipher_string()}")
    print(f"  ID: {cert.cert_id}")
    print(f"  Serial: {cert.serial}")
    print(f"  Nonce: {base64.b64encode(cert.nonce).decode('ascii')}")
    print(f"  Type: {cert.cert_type}")
    print(f"  Valid Principals: {', '.join(cert.valid_principals)}")
    print(f"  Valid After: {cert.valid_after}")
    print(f"  Valid Before: {cert.valid_before}")
    print(f"  Critical Options: {cert.critical_options}")
    print(f"  Extensions: {cert.extensions}")

    if isinstance(cert, RSACertificate):
        print(f"  RSA Public Exponent: {cert.e}")
        print(f"  RSA Modulus: {cert.n}")
    elif isinstance(cert, ECDSACertificate):
        print(f"  ECDSA Curve: {cert.curve}")
        print(f"  ECDSA Public Key: {base64.b64encode(cert.ec_point).decode('ascii')}")
    elif isinstance(cert, ED25519Certificate):
        print(f"  ED25519 Public Key: {base64.b64encode(cert.pk).decode('ascii')}")

    print(f"  Signature Key: {base64.b64encode(cert.signature_key).decode('ascii')}")
    print(f"  Signature: {base64.b64encode(cert.signature).decode('ascii')}")


def read_file_str(file_path: str) -> str:
    try:
        with open(file_path, 'r') as f:
            return f.read().strip()
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)



def parsecert(args: argparse.Namespace) -> None:
    file_contents = read_file_str(args.cert_file)

    try:
        cert = OpenSSHCertificate.from_string_fmt(file_contents)
    except ValueError as e:
        print(f"Error parsing certificate: {e}")
        sys.exit(1)

    print("\nCertificate Details:")
    print_certificate_details(cert)

    re_encoded_data = cert.to_string_fmt()
    assert file_contents == re_encoded_data, "Re-encoded data does not match original data"

    re_parsed_cert = OpenSSHCertificate.from_string_fmt(re_encoded_data)

    # Perform all the assertions as in the original code
    assert cert.cert_cipher_string() == re_parsed_cert.cert_cipher_string(), "Certificate type mismatch"
    assert cert.nonce == re_parsed_cert.nonce, "Nonce mismatch"
    assert cert.signature == re_parsed_cert.signature, "Signature mismatch"
    assert cert.signature_key == re_parsed_cert.signature_key, "Signature key mismatch"
    assert cert.valid_principals == re_parsed_cert.valid_principals, "Valid principals mismatch"
    assert cert.valid_after == re_parsed_cert.valid_after, "Valid after mismatch"
    assert cert.valid_before == re_parsed_cert.valid_before, "Valid before mismatch"
    assert cert.critical_options == re_parsed_cert.critical_options, "Critical options mismatch"
    assert cert.extensions == re_parsed_cert.extensions, "Extensions mismatch"

    print("OK - " + args.cert_file)


def parsepub(args: argparse.Namespace) -> None:
    file_contents = read_file_str(args.pub_file)

    cert = cert_for_ssh_pub_id(
        file_contents,
        cert_id = args.pub_file,
        cert_type = ssh.SSHCertificateType.USER,
        principals=["basic_users", "admins"])

    print("Parsed public key into a certificate:")
    print_certificate_details(cert)

    print("")
    print("Testing signing & verification with different issuers:")

    issuers = [
        ed25519.Ed25519PrivateKey.generate(),
        rsa.generate_private_key(65537, 2048),
        ec.generate_private_key(ec.SECP256R1()),
    ]
    for ca in issuers:
        assert isinstance(ca, (rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey))
        sign_ssh_cert(cert, ca)
        print(f" - Signed ok with {ca.__class__.__name__}")
        #print_certificate_details(cert)
        if verify_ssh_cert(cert):
            print(f"   - Verified OK")
        else:
            print(f"   - Verification FAILED!")

def checksig(args: argparse.Namespace) -> None:
    cert_contents = read_file_str(args.cert_file)

    try:
        cert = OpenSSHCertificate.from_string_fmt(cert_contents)
    except ValueError as e:
        print(f"Error parsing certificate: {e}")
        sys.exit(1)

    is_valid = verify_ssh_cert(cert)

    if is_valid:
        print(f"Signature OK: {args.cert_file}")
    else:
        print(f"Signature is INVALID: {args.cert_file}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH Certificate Test Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # parsecert command
    parsecert_parser = subparsers.add_parser("parsecert", help="Parse and validate a certificate file")
    parsecert_parser.add_argument("cert_file", help="Path to the certificate file")

    # parsepub command
    parsepub_parser = subparsers.add_parser("parsepub", help="Parse a public key file")
    parsepub_parser.add_argument("pub_file", help="Path to the public key file")

    # checksig command
    checksig_parser = subparsers.add_parser("checksig", help="Verify a certificate signature")
    checksig_parser.add_argument("cert_file", help="Path to the certificate file")

    args = parser.parse_args()

    if args.command == "parsecert":
        parsecert(args)
    elif args.command == "parsepub":
        parsepub(args)
    elif args.command == "checksig":
        checksig(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
