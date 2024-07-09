from typing import List
from Crypto.Protocol.SecretSharing import Shamir
import secrets
import itertools
import click
from textwrap import dedent


def create_secret(rnd: bytes|None = None) -> bytes:
    """
    Create a secret with a fixed 'SS' prefix.
    If a random bytes are not provided, they are generated.
    Only the first 14 bytes of the random bytes are used.
    If it's < 14 bytes, the rest is filled with random bytes.

    Args:
        rnd (bytes|None): Optional random bytes to use as the secret. If None, random bytes are generated.

    Returns:
        bytes: A secret prefixed with 'SS' followed by 14 random bytes (total 128 bits).
    """
    rnd = (rnd or b'') + secrets.token_bytes(128 // 8)
    return b'SS' + rnd[:14]


def split_ssss_secret_humanized(threshold: int, num_shares: int, secret: bytes) -> List[str]:
    """
    Create human-readable Shamir shares from the secret.
    Each share is a combination of custodian number (1-num_shares) and a secret 128-bit secret.
    The returned shares are compatible with `ssss-combine -t 3 -x -D` CLI command, as well as the `recombine_shares` function.

    The "human readable" format returned by this function is:
        <N> <P1> <P2> ... <P8>
    where:
        N - Share number, in hex
        P1..P8 - 4 hex digits of the share
    Example:
        '1 abcd ef12 3456 7890 abcd ef12 3456'

    Args:
        threshold (int): The minimum number of shares needed to reconstruct the secret.
        num_shares (int): The total number of shares to create.
        secret (bytes): The secret to be split into shares. Must be 128 bits (16 bytes).

    Returns:
        List[str]: A list of human-readable shares.
    """
    assert len(secret) == 16, "Secret must be 128 bits (16 bytes)"
    assert secret.startswith(b'SS'), "Secret does not start with 'SS'"
    assert threshold <= num_shares, "Threshold must be less than or equal to the number of shares"
    assert threshold > 1, "Threshold must be greater than 1"
    assert threshold <= 15, "Threshold must be less than or equal to 15"

    human_readable_shares = []
    for share in Shamir.split(threshold, num_shares, secret, ssss=True):
        hex_share = share[1].hex()
        hex_share = f'{share[0]:x} ' + ' '.join([hex_share[i:i + 4] for i in range(0, len(hex_share), 4)])
        human_readable_shares.append(hex_share)

    return human_readable_shares


def recombine_ssss_shares(shares: List[str]) -> bytes:
    """
    Recombine shares to reconstruct the secret.

    Args:
        shares (List[str]): A list of human-readable shares.

    Returns:
        bytes: The reconstructed secret (16 bytes)

    Raises:
        AssertionError: If the reconstructed secret does not start with 'SS'.
    """
    recomb_shares = []

    for hrs in shares:
        parts = hrs.split(' ')
        share_num = int(parts[0], 16)
        hex_share = ''.join(parts[1:])
        share = (share_num, bytes.fromhex(hex_share))
        recomb_shares.append(share)

    reconstructed_secret = Shamir.combine(recomb_shares, ssss=True)
    assert reconstructed_secret.startswith(b'SS'), "Reconstructed secret does not start with 'SS', reconstruction failed"
    return reconstructed_secret


def test_shares(secret: bytes, threshold: int, human_readable_shares: List[str]) -> int:
    """
    Test all combinations of threshold shares and assert for any problems.

    Args:
        secret (bytes): The original secret.
        human_readable_shares (List[str]): A list of human-readable shares.

    Returns:
        int: The number of combinations tested.

    Raises:
        AssertionError: If any reconstructed secret does not match the original secret.
    """
    recomb_shares = []

    for s in human_readable_shares:
        parts = s.split(' ')
        share_num = int(parts[0], 16)
        hex_share = ''.join(parts[1:])
        share = (share_num, bytes.fromhex(hex_share))
        recomb_shares.append(share)

    combs_tested = 0
    for combination in itertools.combinations(recomb_shares, threshold):
        reconstructed_secret = Shamir.combine(list(combination), ssss=True)
        assert reconstructed_secret == secret, f"Reconstructed secret does not match original secret"
        combs_tested += 1

    assert combs_tested > 0, "No combinations tested"
    return combs_tested


def test_create_and_recombine_shares():
    # Create a secret
    secret = create_secret()
    assert secret.startswith(b'SS'), "Secret does not start with 'SS'"
    print("Generated secret: " + secret.hex() + " (" + str(secret) + ")")
    print()

    # Define threshold and number of shares
    threshold = 3
    num_shares = 4 + threshold
    print(f"Threshold: {threshold}, Number of shares: {num_shares}")

    # Create shares
    shares = split_ssss_secret_humanized(threshold, num_shares, secret)
    assert len(shares) == num_shares, f"Expected {num_shares} shares, got {len(shares)}"

    print("Human-readable shares:")
    for share in shares:
        print(share)
    print()

    # Test combinations of shares
    combs_tested = test_shares(secret, threshold, shares)
    assert combs_tested > 0, "No combinations tested"
    print(f"Tested {combs_tested} combinations of {threshold} shares out of {len(shares)} total shares.")


if __name__ == "__main__":
    test_create_and_recombine_shares()
