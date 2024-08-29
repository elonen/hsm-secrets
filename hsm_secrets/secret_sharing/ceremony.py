from typing import Callable
from textwrap import dedent
import re

import click

from hsm_secrets.secret_sharing.shared_secret import SecretShare, create_16char_ascii_password, decrypt_share, encrypt_share, recombine_ssss_shares, split_ssss_secret, verify_shares_strings
from hsm_secrets.secret_sharing.ui import SecretSharingClickUI, SecretSharingUIBase
from hsm_secrets.utils import group_by_4


def cli_splitting_ceremony(
        threshold: int,
        num_shares: int,
        apply_secret_fn: Callable[[bytes], None],
        with_backup_key: bool = True,
        rnd: bytes|None = None,
        ui: SecretSharingUIBase = SecretSharingClickUI()):
    """
    Host a splitting ceremony to create shares from a secret, in a CLI session.

    NOTE! The `apply_secret_fn` function may be called even if the ceremony is aborted.

    :param threshold: The number of shares required to reconstruct the secret.
    :param num_shares: The number of shares to create.
    :param apply_secret_fn: A function to apply the secret to the system (must be idempotent, and take a single 'bytes' argument).
    :param with_backup_key: Whether to include a backup key in the ceremony.
    :param rnd: Pre-generated entropy to use for secret, or None to generate a new one.
    :param unit_test: Whether to run in unit test mode (no pauses and input)
    """
    ui.clear()

    backup_desc = """
        ## Backup key

        You have chosen to include a backup key in the ceremony.
        This is a way to circumvent the threshold requirement in case of key loss,
        but it also increases the risk of compromise! Each custodian will be shown
        a piece of the original secret, and be asked to write it down and to
        put it in an envelope. After the ceremony, the envelope must be sealed
        and stored in a bank vault or similar secure location.
    """
    n_papers = num_shares * 2 if with_backup_key else num_shares
    backup_req = """
        - 1 larger "master envelope" to hold the smaller backup key envelopes
    """ if with_backup_key else ""

    ui.msg(dedent(f"""
        # Welcome to Secret Sharing Ceremony!

        We will be creating and splitting a secret key into {num_shares} shares,
        with a threshold of {threshold} shares required to reconstruct it.
        {backup_desc if with_backup_key else ''}
        ## You will need

        - water-proof pens
        - {num_shares} custodians (trusted key share holders) present
        - {n_papers}+ pieces of foldable paper to write down the secrets
        - {n_papers}+ envelopes {backup_req}

        ## Rules

        - Each custodian is only allowed to touch ENTER key on the computer, nothing else,
          while the shares are being displayed.
        - Other custodians must only see the screen when their own share is shown.
        - After ALL the shares have been written down, the program will ask each custodian
          to type in their share to verify that they have written it down correctly.

        First, we will enumerate the custodians, and ask if they want to password-protect
        their shares.

        The optional password will be used to encrypt the share, and must be remembered
        by the custodian to decrypt it later. It's an additional security measure, and not
        strictly necessary. The password does NOT need to be very strong, it is
        hashed with scrypt(n=2^20, r=8, p=1), which takes >1s to compute.
    """))

    ui.confirm_or_abort("Start the ceremony?")
    ui.msg("")

    secret, backup_parts = _make_secret_and_backup_parts(num_shares, rnd)
    ui.msg(f"Secret created ({len(secret) * 8} bits).")

    assert secret.decode('ASCII').encode('ASCII') == secret, "Generated secret is not ASCII-compatible"
    apply_secret_fn(secret)
    ui.msg("Secret applied/loaded into the system.")

    custodian_names, custodian_passwords = _prompt_for_custodian_names_and_passwords(num_shares, ui)
    ui.pause("Press ENTER to continue...")
    ui.clear()

    # Make the custodian shares
    plain_shares = split_ssss_secret(threshold, num_shares, secret)
    assert set(s.num for s in plain_shares) == set(custodian_passwords.keys())

    shares = _optionally_encrypt_shares(plain_shares, custodian_passwords)

    for s in shares:
        _display_custodian_share(threshold, num_shares, custodian_names[s.num], s.num, str(s), ui)
        if with_backup_key:
            bpart_str = group_by_4(backup_parts[int(s.num)-1].hex())
            _display_custodian_backup_part(num_shares, s.num, bpart_str, ui)

    ui.msg("All shares have been created.")
    ui.msg("Now, each custodian will be asked to type in their share to verify it.")
    ui.msg("")

    typed_in_decrypted_shares: list[SecretShare] = []
    typed_in_backup_parts: list[bytes] = []

    for s in shares:
        cust_name = click.style(custodian_names[s.num], fg='green')
        ui.msg(f"Custodian {cust_name} (#{s.num}), approach the keyboard and type in your share.")
        ui.msg("")
        ui.msg("Others SHOULD see the screen but NOT the keyboard:")
        ui.msg("- Input is hidden for privacy")
        ui.msg("- Custodians must not do anything else than type in their share on the terminal")
        ui.msg("")

        share_input = _prompt_verify_share(num_shares, plain_shares[s.num-1], ui)

        typed_in_decrypted_shares.append(share_input)
        ui.msg(f"Share #{s.num} verified ok.")
        ui.msg("")

        if with_backup_key:
            correct_part = backup_parts[int(s.num) - 1]
            typed_in_backup_parts.append(_prompt_verify_backup_part(s.num, num_shares, correct_part, ui))

        ui.msg(f"Share{' and backup' if with_backup_key else ''} verified.")
        ui.pause("Press ENTER to continue...")
        ui.clear()

    if with_backup_key:
        recombined_backup_secret = b''.join(typed_in_backup_parts)
        assert secret == recombined_backup_secret, "Backup key parts do not match the original secret. Ceremony failed."

    n_combs_tested = verify_shares_strings(secret, threshold, [str(s) for s in typed_in_decrypted_shares])
    ui.msg(f"All shares have been verified, and {n_combs_tested} combinations have been tested for reconstruction.")
    ui.msg("")

    if with_backup_key:
        ui.msg("All custodians, put your backup key envelopes in a common master envelope, and seal it.")
        ui.msg("")
        ui.msg(dedent("""
            The master envelope should be printed with the following text:

                    CRITICAL: Hex-encoded YubiHSM2 Emergency Root Auth Key

                    Only take this envelope out of the vault if
                    the following conditions are met:

                    - ALL the core server admin personnel, who are currently
                    employed, agree that accessing this envelope is necessary.

                    - The MAJORITY of them are present to authorize the
                    opening of this envelope.

                    The same rules apply for destroying and/or replacing
                    this envelope.

                    Date Sealed: [Date]
        """))

    ui.msg("The ceremony is now complete.")
    ui.msg(click.style("IMPORTANT: After this, CLOSE THE TERMINAL SESSION to ensure that secrets", fg='yellow'))
    ui.msg(click.style("are not left in the terminal's scrollback history.", fg='yellow'))



def cli_reconstruction_ceremony(secret_starts_with_s = True, ui: SecretSharingUIBase = SecretSharingClickUI()) -> bytes:
    """
    Host a reconstruction ceremony to reconstruct a secret from shares, in a CLI session.

    By default, the reconstructed secret is expected to start with b'S', so that it can be verified to be valid.
    If `secret_starts_with_s` is False, the verification step is skipped.

    :param secret_starts_with_s: Whether the shares start with 'S' (True) or not (False)
    :return: The reconstructed secret (bytes)
    """
    ui.clear()
    ui.msg("# Secret Reconstruction Ceremony")
    ui.msg("")
    ui.msg("Reconstructing secret from custodian shares.")
    ui.msg("Each custodian will be asked to type in their share.")
    ui.msg("")
    ui.msg("Others SHOULD see the screen but NOT the keyboard:")
    ui.msg("- Input is hidden for privacy")
    ui.msg("- Custodians must not do anything else than type in their share on the terminal")
    ui.msg("")

    threshold = ui.prompt_threshold()
    assert threshold > 0

    shares: list[SecretShare] = []
    while len(shares) < threshold:
        share_num = len(shares) + 1
        shares.append(_prompt_input_share(share_num, threshold, ui))

    try:
        return recombine_ssss_shares([str(s) for s in shares], validate_with_s=secret_starts_with_s)
    except ValueError as e:
        ui.msg(click.style("Reconstruction failed (secret did not start with 'S). The shares are invalid or insufficient.", fg='red'))
        ui.pause("Press ENTER to continue...")
        raise

# ----- helpers -----

def _make_secret_and_backup_parts(num_shares: int, rnd: bytes|None) -> tuple[bytes, list[bytes]]:
    secret = create_16char_ascii_password(rnd).encode('ASCII')

    parts = [secret[i * len(secret) // num_shares: (i + 1) * len(secret) // num_shares] for i in range(num_shares)]
    parts[-1] += secret[len(b''.join(parts)):]  # Add the remainder to the last part, if any
    assert b''.join(parts) == secret, "Backup parts did not match the original secret: '" + str(b''.join(parts)) + "' != '" + str(secret) + "'"
    assert len(parts) == num_shares
    assert all(len(bp) > 0 for bp in parts)

    return secret, parts


def _prompt_for_custodian_names_and_passwords(num_shares: int, ui: SecretSharingUIBase) -> tuple[dict[int, str], dict[int, str|None]]:
    """
    Interactively prompt for `num_shares` custodian names and optional passwords for shares.
    """
    names: dict[int, str] = {}
    passwords: dict[int, str|None] = {}
    for share_num in range(1, num_shares+1):
        names[share_num], passwords[share_num] = ui.prompt_name_and_password(share_num, list(names.values()))
        ui.msg("")
    return names, passwords


def _optionally_encrypt_shares(shares: list[SecretShare], custodian_passwords: dict[int, str|None]) -> list[SecretShare]:
    res = []
    for s in shares:
        if pwd := custodian_passwords.get(s.num):
            res.append(encrypt_share(s, pwd))
        else:
            res.append(s)
    return res


def _display_custodian_share(threshold: int, num_shares: int, name: str, share_num: int, share_str: str, ui: SecretSharingUIBase):
    """
    Display a share to a custodian, and prompt them to write it down on a piece of paper.
    :return: The share as a string
    """
    cust_name = click.style(name, fg='green')
    ui.msg(f"Custodian {cust_name} (#{share_num}), approach the screen. Others must not see the screen or the paper.")
    ui.msg("")
    ui.msg("- Write it down AS-IS on a piece of paper, fold it and put it in an envelope.")
    ui.msg("- KEEP THE ENVELOPE, AND DO NOT SEAL IT YET.")
    ui.msg(f"- Write "+ click.style(f"'Share #{share_num}/{num_shares}, {threshold} required'", fg='green') + " on the envelope.")
    ui.msg("")
    ui.pause("Press ENTER to reveal your share. After writing it down, press ENTER again to continue...")
    ui.display_share(share_num, share_str)
    ui.clear()


def _display_custodian_backup_part(num_shares: int, share_num: int, backup_part_str: str, ui: SecretSharingUIBase):
    ui.msg("Now, the backup key part.")
    ui.msg("")
    ui.msg("- Write it down on a piece of paper, fold it and put it in another envelope.")
    ui.msg("- Write "+ click.style(f"'Hex encoded backup key part #{share_num}/{num_shares}'", fg='green') + " on the envelope.")
    ui.msg("- KEEP THE ENVELOPE, AND DO NOT SEAL IT YET.")
    ui.msg("")
    ui.pause("Press ENTER to reveal the key part. After writing it down, press ENTER again to continue...")
    ui.display_backup_part(share_num, f"{share_num}/{num_shares}: " + backup_part_str)
    ui.clear()


def _prompt_verify_share(total_shares: int, correct: SecretShare, ui: SecretSharingUIBase) -> SecretShare:
    """
    Prompt a custodian to type in their share, decrypt it if necessary, and verify it against the correct share.
    :param total_shares: The total number of shares
    :param correct: The correct share to verify against
    :param unit_test_input: Optional tuple of (share_input, password) for unit testing, or None for interactive input
    :return: Decrypted share as typed in by the custodian
    """
    while True:
        ui.msg(f"Type in share #{correct.num}/{total_shares} to verify it. You can skip whitespaces and dashes.")
        input = ui.prompt_share_str("Your share:", correct.num)
        try:
            inputted_share = SecretShare.from_str(input)
        except ValueError as e:
            ui.msg("Invalid share. Try again. Error: " + str(e))
            continue

        if inputted_share.encrypted:
            ui.msg("Share is encrypted. Please type in the password to decrypt it.")
            pw = ui.prompt_password("Your password:", correct.num)
            try:
                inputted_share = decrypt_share(inputted_share, pw)
                ui.msg("Decrypted successfully.")
            except ValueError as e:
                ui.msg("Decryption failed. Try again. Error: " + str(e))
                continue

        if inputted_share.num != correct.num:
            ui.msg("Share number does not match. Try again.")
            continue

        if inputted_share.data != correct.data:
            ui.msg("Share data does not match. Try again.")
            continue

        break

    return inputted_share


def _prompt_verify_backup_part(num: int, total_shares: int, correct: bytes, ui: SecretSharingUIBase) -> bytes:
        def _clean_up_backup_part(bp: str):
            # '1/3: 1234 5678 90ab'  =>  '1234567890ab'
            return re.sub(r'^[0-9]+ */ *[0-9]+[: ]*', '', bp).replace(' ', '').strip()

        ui.msg(f"Now, type in backup key part #{num}/{total_shares} in hex format. You can skip the 'n/m:' prefix and whitespaces.")
        input_str = ui.prompt_backup_part_str("Your backup key part:", num)
        typed_backup_part = _clean_up_backup_part(input_str)

        while not str(typed_backup_part).lower() == correct.hex().lower():
            ui.msg("Backup key part does not match. Try again.")
            input_str = ui.prompt_backup_part_str("Your backup key part:", num)
            typed_backup_part = _clean_up_backup_part(input_str)

        bin_part = bytes.fromhex(typed_backup_part)
        assert bin_part == correct
        return bin_part


def _prompt_input_share(share_num: int, total_shares: int, ui: SecretSharingUIBase) -> SecretShare:
    """
    Interactively prompt a custodian to type in a share, and optionally decrypt it.
    :return: The share as typed in by the custodian
    """
    ui.msg("")
    ui.msg(f"Custodian {share_num}/{total_shares}, please type in your share. You can skip whitespaces and dashes.")
    while True:
        share_str = ui.prompt_share_str("Your share:", share_num)
        try:
            s = SecretShare.from_str(share_str)
        except ValueError as e:
            ui.msg("Invalid share. Try again. Error: " + str(e))
            continue

        if s.encrypted:
            pw = ui.prompt_password("The share is encrypted. Type in the password to decrypt it", share_num)
            try:
                s = decrypt_share(s, pw)
            except ValueError as e:
                ui.msg("Decryption failed. Try again. Error: " + str(e))
                continue

        return s




# ----- main -----

'''
if __name__ == '__main__':
    """
    Run a simulation of the secret sharing ceremony and reconstruction ceremony,
    without actually using the secret for anything.
    """
    test_secret_sharing_ceremony_and_reconstruction()
'''