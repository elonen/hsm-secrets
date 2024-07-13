import base64
from dataclasses import dataclass
from typing import List, Sequence
from Crypto.Protocol.SecretSharing import Shamir
import secrets
import itertools
import re
from textwrap import dedent
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

from hsm_secrets.utils import group_by_4


@dataclass
class SecretShare:
    """
    Represents a single 128 bit secret share, either plaintext or encrypted.
    The shares can be converted to and from strings in a human-readable format:

    Plaintext share:
        <N> - <P1> <P2> ... <P8>
        ...where:
            N - Share number, in hex
            P1..P8 - 4 hex digits of the share
            Example: '1 cdef 1234 5678 90ab 1234 5678 90ab cdef'

    Encrypted share:
        <N> - crypted <CSUM> - <C1> <C2> ... <C8>
        ...where:
            N - Share number, in hex
            'crypted' - literal string to indicate encryption
            CSUM - 2 last hex digits of MD5 checksum of the raw (binary) non-encrypted share
            C1..C8 - 4 hex digits of the encrypted share
        Example: '1 - crypted ab - cdef 1234 5678 90ab 1234 5678 90ab cdef'

    Spaces and dashes are optional and interchangeable in the string representation.

    Encryption algorithm is AES-128-ECB using a key derived from a password with scrypt(N=2^14, r=8, p=1, key_len=16, salt='').

    The `ssss-combine -t 3 -x -D` CLI command can be used to combine plaintext shares.
    It expects format: `<N>-<P1><P2>...<P8>` (e.g. '1-cdef1234567890ab1234567890abcdef')
    """
    num: int
    data: bytes
    checksum: str       # 2 last hex digits from MD5 of the data
    encrypted: bool

    def validate(self) -> 'SecretShare':
        """
        Check if the share is valid.
        """
        if len(self.data) != 16:
            raise ValueError("Secret data must be 128 bits (16 bytes)")
        if self.num < 1 or self.num > 15:
            raise ValueError("Share number must be between 1 and 15")
        if not re.match(r'^[0-9a-f]{2}$', self.checksum.lower()):
            raise ValueError("Checksum must be 2 hex digits")
        if not self.encrypted:
            if self.checksum != hashlib.md5(self.data).hexdigest()[-2:].lower():
                raise ValueError("Checksum does not match data")
        return self


    def __str__(self) -> str:
        """
        Convert the share to a human-readable string.
        """
        self.validate()
        if self.encrypted:
            return f'{self.num} - crypted {self.checksum} - ' + group_by_4(self.data.hex())
        else:
            return f'{self.num} - ' + group_by_4(self.data.hex())


    @staticmethod
    def from_bytes(num: int, data: bytes) -> 'SecretShare':
        """
        Create a plaintext share from a number and data.
        """
        s = SecretShare(num, data, hashlib.md5(data).hexdigest()[-2:], False)
        return s.validate()


    @staticmethod
    def from_str(s: str) -> 'SecretShare':
        """
        Parse a share from a human-readable string.
        """
        res = None
        compact = re.sub(r'[-\s]+', '', s.lower())  # Remove spaces and dashes

        # Parse encrypted share
        crypted_match = re.match(r'^([0-9a-f])[-\s]*crypted[-\s]*((?:[0-9a-f][-\s]*){2})((?:[0-9a-f][-\s]*){32})$', compact)
        if crypted_match:
            res = SecretShare(
                num = int(crypted_match.group(1), 16),
                checksum = crypted_match.group(2),
                data = bytes.fromhex(crypted_match.group(3)),
                encrypted = True)

        # Parse plaintext share
        plain_match = re.match(r'^([0-9a-f])[-\s]*((?:[0-9a-f][-\s]*){32})$', compact)
        if plain_match:
            res = SecretShare(
                num = int(plain_match.group(1), 16),
                data = bytes.fromhex(plain_match.group(2)),
                checksum = hashlib.md5(bytes.fromhex(plain_match.group(2))).hexdigest()[-2:],
                encrypted = False)

        if res is None:
            raise ValueError("Share is not in the correct format: " + s)

        return res.validate()



def create_16char_ascii_password(rnd: bytes|None = None) -> str:
    """
    Create a 15 ASCII characters long password, prefixed with 'S' (total 16 bytes).
    If a random bytes are not provided, they are generated.

    Note! This is not a super secure password in itself (90 bits of entropy),
    and should only be used where leaking its hash is not possible
    (e.g. stored in an HSM or as a seed for a slow key derivation function).

    Args:
        rnd (bytes|None): Optional random bytes to use as the secret.

    Returns:
        bytes: An ASCII password prefixed with 'S' (total 16 bytes = 128 bits)
    """
    rnd = ((rnd or b'') + secrets.token_bytes(15))[:15]
    return 'S' + base64.b64encode(rnd).decode('ASCII')[:15]


def split_ssss_secret(threshold: int, num_shares: int, secret: bytes) -> List[SecretShare]:
    """
    Create human-readable Shamir shares from the secret.

    Args:
        threshold (int): The minimum number of shares needed to reconstruct the secret.
        num_shares (int): The total number of shares to create.
        secret (bytes): The secret to be split into shares. Must be 128 bits (16 bytes).

    Returns:
        List[SecretShare]: Split shares
    """
    assert len(secret) == 16, "Secret must be 128 bits (16 bytes)"
    assert secret.startswith(b'S'), "Secret must start with 'S' (for validation)"
    assert threshold <= num_shares
    assert 1 < threshold <= 15
    res = [SecretShare.from_bytes(i, data) for i, data in Shamir.split(threshold, num_shares, secret, ssss=True)]
    nums = [s.num for s in res]
    assert len(nums) == len(set(nums)), "Duplicate share numbers"
    assert set(range(1, num_shares+1)) == set(nums), "Unexpected share numbers"
    return res


def recombine_ssss_shares(share_strings: Sequence[str], validate_with_s: bool = True) -> bytes:
    """
    Recombine shares to reconstruct the secret.
    The shares must be in the same format as returned by `split_ssss_secret`, or from `ssss-split` CLI command.

    Args:
        shares (List[str]): A list of 'threshold' number of shares.

    Returns:
        bytes: The reconstructed secret (16 bytes)

    Raises:
        ValueError: If the reconstructed secret does not start with 'S' (and validate_with_s is True).
        ValueError: If the shares are not decrypted.
    """
    recomb_shares = []
    for s in [SecretShare.from_str(s) for s in share_strings]:
        if s.encrypted:
            raise ValueError("Shares must be decrypted before recombining")
        recomb_shares.append((s.num, s.data))

    reconstructed_secret = Shamir.combine(recomb_shares, ssss=True)
    if validate_with_s:
        if not reconstructed_secret.startswith(b'S'):
            raise ValueError("Recombined secret does not start with 'S', may be invalid")

    return reconstructed_secret


def _derive_key(password: str, salt: str = '') -> bytes:
    try:
        password.encode('latin1', errors='strict')    # Check if password is Latin-1 compatible
    except UnicodeEncodeError:
        raise ValueError("Password must be Latin-1 compatible (due to scrypt)")
    key = scrypt(password=password, salt=salt, key_len=128//8, N=2**14, r=8, p=1)   # type: ignore
    assert isinstance(key, bytes) and len(key) == 128/8
    return key


def encrypt_share(share: SecretShare, password: str|None) -> SecretShare:
    """
    Encrypt share, or return the share as-is if no password is provided.
    """
    if not password:
        return share
    elif share.encrypted:
        raise ValueError("Share is already encrypted")

    cipher = AES.new(_derive_key(password), AES.MODE_ECB)
    return SecretShare(
        num = share.num,
        data = cipher.encrypt(share.data),
        checksum = share.checksum,
        encrypted = True).validate()


def decrypt_share(share: SecretShare, password: str) -> SecretShare:
    """
    Decrypt share (if not already decrypted) using the provided password.
    """
    if not share.encrypted:
        return share

    cipher = AES.new(_derive_key(password), AES.MODE_ECB)
    return SecretShare(
        num = share.num,
        data = cipher.decrypt(share.data),
        checksum = share.checksum,
        encrypted = False).validate()


def verify_shares(secret: bytes, threshold: int, share_strings: List[str]) -> int:
    """
    Verify that all combinations of 'threshold' number of shares can reconstruct the secret.
    Return the number of combinations tested.
    """
    combs_tested = 0
    for combination in itertools.combinations(share_strings, threshold):
        assert recombine_ssss_shares(combination, validate_with_s=False) == secret, f"Reconstructed secret does not match original secret"
        combs_tested += 1
    assert combs_tested > 0, "No combinations tested"
    return combs_tested

# --------------------------------------------------------

def test_create_and_recombine_shares():
    # Create a secret
    secret = create_16char_ascii_password().encode('ASCII')
    assert secret.startswith(b'S'), "Secret does not start with 'S'"
    print("Generated secret hex: " + secret.hex() + " (ASCII: \"" + secret.decode('ASCII') + "\")")
    print()

    # Define threshold and number of shares
    threshold = 3
    num_shares = 5
    print(f"Threshold: {threshold}, Number of shares: {num_shares}")

    # Create shares
    orig_shares = split_ssss_secret(threshold, num_shares, secret)
    assert len(orig_shares) == num_shares, f"Expected {num_shares} shares, got {len(orig_shares)}"

    passwords = ['', '', create_16char_ascii_password(), create_16char_ascii_password(), '']
    assert len(passwords) == len(orig_shares)
    encrypted_shares = [encrypt_share(s, pw) for s, pw in zip(orig_shares, passwords)]

    for es, pw, sh in zip(encrypted_shares, passwords, orig_shares):
        assert not es.encrypted or (es.data != sh.data)
        print(f'{es}   (password: "{pw}", plaintext: "{sh}")' if pw else es)

    del orig_shares
    print()

    # Test combinations of shares
    decrypted_shares = [str(decrypt_share(es, pw)) for es, pw in zip(encrypted_shares, passwords)]
    combs_tested = verify_shares(secret, threshold, decrypted_shares)
    assert combs_tested > 0, "No combinations tested"
    print(f"Tested {combs_tested} combinations of {threshold} shares out of {len(decrypted_shares)} total shares.")


if __name__ == "__main__":
    test_create_and_recombine_shares()
