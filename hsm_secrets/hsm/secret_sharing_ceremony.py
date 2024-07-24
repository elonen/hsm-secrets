from typing import Callable
import click
from textwrap import dedent
import re

from hsm_secrets.hsm.shared_secret import SecretShare, create_16char_ascii_password, decrypt_share, encrypt_share, recombine_ssss_shares, split_ssss_secret, verify_shares
from hsm_secrets.utils import cli_ui_msg, group_by_4, secure_display_secret


def cli_splitting_ceremony(
        threshold: int,
        num_shares: int,
        apply_secret_fn: Callable,
        with_backup_key: bool = True,
        pre_secret: bytes|None = None):
    """
    Host a splitting ceremony to create shares from a secret, in a CLI session.

    NOTE! The `apply_secret_fn` function may be called even if the ceremony is aborted.

    :param threshold: The number of shares required to reconstruct the secret.
    :param num_shares: The number of shares to create.
    :param apply_secret_fn: A function to apply the secret to the system (must be idempotent, and take a single 'bytes' argument).
    :param with_backup_key: Whether to include a backup key in the ceremony.
    :param pre_secret: A pre-generated secret to use, or None to generate a new one.
    """
    click.clear()

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


    cli_ui_msg(dedent(f"""
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
    """))

    click.confirm("Start the ceremony?", abort=True, err=True)
    cli_ui_msg("")

    # Get custodian names and passwords
    custodian_names = {}
    custodian_passwords = {}

    click.clear()
    for i in range(1, num_shares + 1):
        name = click.prompt(f"Enter the name of custodian #{i}", err=True).strip() or f"#{i}"
        custodian_names[i] = name
        if click.confirm(f"Password-protect share?", abort=False, err=True):
            pw = click.prompt("Custodian " + click.style(f"'{name}'", fg='green') + ", enter the password", hide_input=True, err=True).strip()
            custodian_passwords[i] = pw
        else:
            custodian_passwords[i] = None
        cli_ui_msg("")

    secret = create_16char_ascii_password(pre_secret).encode('ASCII')
    cli_ui_msg(f"Secret created ({len(secret) * 8} bits).")
    apply_secret_fn(secret)
    cli_ui_msg("Secret applied/loaded into the system.")

    # Divide the original key into num_shares parts for backup
    backup_parts = [secret[i * len(secret) // num_shares: (i + 1) * len(secret) // num_shares] for i in range(num_shares)]
    backup_parts[-1] += secret[len(b''.join(backup_parts)):]  # Add the remainder to the last part, if any
    assert b''.join(backup_parts) == secret, "Backup parts did not match the original secret: '" + str(b''.join(backup_parts)) + "' != '" + str(secret) + "'"
    assert len(backup_parts) == num_shares
    assert all(len(bp) > 0 for bp in backup_parts)

    click.pause("Press ENTER to continue...")
    click.clear()

    # Make the custodian shares
    plain_shares = split_ssss_secret(threshold, num_shares, secret)
    assert set(s.num for s in plain_shares) == set(custodian_passwords.keys())
    shares = [encrypt_share(s, custodian_passwords.get(s.num)) for s in plain_shares]

    for s in shares:
        cust_name = click.style(custodian_names[s.num], fg='green')
        cli_ui_msg(f"Custodian {cust_name} (#{s.num}), approach the screen. Others must not see the screen or the paper.")
        cli_ui_msg("")
        cli_ui_msg("- Write it down AS-IS on a piece of paper, fold it and put it in an envelope.")
        cli_ui_msg("- KEEP THE ENVELOPE, AND DO NOT SEAL IT YET.")
        cli_ui_msg(f"- Write "+ click.style(f"'Share #{s.num}/{num_shares}, {threshold} required'", fg='green') + " on the envelope.")
        cli_ui_msg("")
        click.pause("Press ENTER to reveal your share. After writing it down, press ENTER again to continue...")

        secure_display_secret(str(s))
        click.clear()

        if with_backup_key:
            backup_part = backup_parts[int(s.num) - 1]
            cli_ui_msg("Now, the backup key part.")
            cli_ui_msg("")
            cli_ui_msg("- Write it down on a piece of paper, fold it and put it in another envelope.")
            cli_ui_msg("- Write "+ click.style(f"'Hex encoded backup key part #{s.num}/{num_shares}'", fg='green') + " on the envelope.")
            cli_ui_msg("- KEEP THE ENVELOPE, AND DO NOT SEAL IT YET.")
            cli_ui_msg("")
            click.pause("Press ENTER to reveal the key part. After writing it down, press ENTER again to continue...")
            secure_display_secret(f"{s.num}/{num_shares}: " + group_by_4(backup_part.hex()))
            click.clear()

    cli_ui_msg("All shares have been created.")
    cli_ui_msg("Now, each custodian will be asked to type in their share to verify it.")
    cli_ui_msg("")

    typed_in_shares = []
    typed_in_backup_parts = []

    for s in shares:
        cust_name = click.style(custodian_names[s.num], fg='green')
        cli_ui_msg(f"Custodian {cust_name} (#{s.num}), approach the keyboard and type in your share.")
        cli_ui_msg("")
        cli_ui_msg("Others SHOULD see the screen but NOT the keyboard:")
        cli_ui_msg("- Input is hidden for privacy")
        cli_ui_msg("- Custodians must not do anything else than type in their share on the terminal")
        cli_ui_msg("")

        typed_share = None
        while True:
            input = click.prompt("Your share:", hide_input=True, err=True)
            try:
                typed_share = SecretShare.from_str(input)
            except ValueError as e:
                cli_ui_msg("Invalid share. Try again. Error: " + str(e))
                continue

            if typed_share.encrypted:
                cli_ui_msg("Share is encrypted. Please type in the password to decrypt it.")
                pw = click.prompt("Your password:", hide_input=True, err=True)
                try:
                    typed_share = decrypt_share(typed_share, pw)
                    cli_ui_msg("Decrypted successfully.")
                except ValueError as e:
                    cli_ui_msg("Decryption failed. Try again. Error: " + str(e))
                    continue
            break

        typed_in_shares.append(typed_share)
        cli_ui_msg(f"Share #{s.num} verified ok.")
        cli_ui_msg("")

        def clean_up_backup_part(bp: str):
            # '1/3: 1234 5678 90ab'  =>  '1234567890ab'
            return re.sub(r'^[0-9]+ */ *[0-9]+[: ]*', '', bp).replace(' ', '').strip()

        if with_backup_key:
            cli_ui_msg(f"Now, type in backup key part #{s.num}/{num_shares} in hex format.")
            typed_backup_part = clean_up_backup_part(click.prompt("Your backup key part:", hide_input=True, err=True))

            while not str(typed_backup_part).lower() == backup_parts[int(s.num) - 1].hex().lower():
                cli_ui_msg("Backup key part does not match. Try again.")
                typed_backup_part = clean_up_backup_part(click.prompt("Your backup key part:", hide_input=True, err=True))

            bin_part = bytes.fromhex(typed_backup_part)
            assert bin_part == backup_parts[int(s.num) - 1]
            typed_in_backup_parts.append(bin_part)

        cli_ui_msg("Share and backup verified. Please seal your envelope(s) now.")
        click.pause("Press ENTER to continue...")
        click.clear()

    backup_secret = b''.join(typed_in_backup_parts)
    assert secret == backup_secret, "Backup key parts do not match the original secret. Ceremony failed."

    n_combs_tested = verify_shares(secret, threshold, [str(s) for s in typed_in_shares])
    cli_ui_msg(f"All shares have been verified, and {n_combs_tested} combinations have been tested for reconstruction.")
    cli_ui_msg("")
    if with_backup_key:
        cli_ui_msg("All custodians, put your backup key envelopes in a common master envelope, and seal it.")
        cli_ui_msg("")
        cli_ui_msg(dedent("""
            The master envelope should be printed with the following text:

                    CRITICAL: Hex-encoded YubiHSM2 Emergency Root Auth Key

                    Only take this envelope out of the vault if
                    the following conditions are met:

                    - ALL the sysops personnel, who are currently employed,
                    agree that accessing this envelope is necessary.

                    - The MAJORITY of them are present to authorize the
                    opening of this envelope.

                    The same rules apply for destroying and/or replacing
                    this envelope.

                    Date Sealed: [Date]
        """))

    cli_ui_msg("The ceremony is now complete.")
    cli_ui_msg(click.style("IMPORTANT: After this, CLOSE THE TERMINAL SESSION to ensure that secrets", fg='yellow'))
    cli_ui_msg(click.style("are not left in the terminal's scrollback history.", fg='yellow'))


def cli_reconstruction_ceremony(secret_starts_with_s = True) -> bytes:
    """
    Host a reconstruction ceremony to reconstruct a secret from shares, in a CLI session.

    By default, the reconstructed secret is expected to start with b'S', so that it can be verified to be valid.
    If `secret_starts_with_s` is False, the verification step is skipped.

    :param secret_starts_with_s: Whether the shares start with 'S' (True) or not (False)
    :return: The reconstructed secret (bytes)
    """
    click.clear()
    cli_ui_msg("# Secret Reconstruction Ceremony")
    cli_ui_msg("")
    cli_ui_msg("Reconstructing secret from custodian shares.")
    cli_ui_msg("Each custodian will be asked to type in their share.")
    cli_ui_msg("")
    cli_ui_msg("Others SHOULD see the screen but NOT the keyboard:")
    cli_ui_msg("- Input is hidden for privacy")
    cli_ui_msg("- Custodians must not do anything else than type in their share on the terminal")
    cli_ui_msg("")

    threshold = click.prompt("How many shares are required to reconstruct the secret", type=int, err=True)
    assert threshold > 0

    shares: list[SecretShare] = []
    while len(shares) < threshold:
        cust_i = len(shares) + 1
        cli_ui_msg("")
        share_str = click.prompt(f"Custodian {cust_i}/{threshold}, enter your share", hide_input=True, err=True)
        try:
            s = SecretShare.from_str(share_str)
        except ValueError as e:
            cli_ui_msg("Invalid share. Try again. Error: " + str(e))
            continue

        if s.encrypted:
            pw = click.prompt("The share is encrypted. Type in the password to decrypt it", hide_input=True, err=True)
            try:
                s = decrypt_share(s, pw)
            except ValueError as e:
                cli_ui_msg("Decryption failed. Try again. Error: " + str(e))
                continue

        shares.append(s)

    try:
        return recombine_ssss_shares([str(s) for s in shares], validate_with_s=secret_starts_with_s)
    except ValueError as e:
        cli_ui_msg(click.style("Reconstruction failed (secret did not start with 'S). The shares are invalid or insufficient.", fg='red'))
        click.pause("Press ENTER to continue...")
        raise



if __name__ == '__main__':
    """
    Run a simulation of the secret sharing ceremony and reconstruction ceremony,
    without actually using the secret for anything.
    """
    correct_secret = None
    def apply_secret(secret: bytes):
        global correct_secret
        correct_secret = secret
        cli_ui_msg(click.style(f"\n    [~~ SIMULATION: called apply_secret('{str(secret)}') ~~]\n", fg='cyan'))

    cli_splitting_ceremony(3, 5, apply_secret, with_backup_key=True)

    cli_ui_msg("---------- SPLITTING DONE ----------")
    cli_ui_msg("Now, let's try to reconstruct the secret.")
    click.pause("Press ENTER to continue...")

    reconst = cli_reconstruction_ceremony()
    cli_ui_msg(click.style(f"Reconstructed secret: {str(reconst)}", fg='green'))

    if correct_secret == reconst:
        cli_ui_msg("Secrets match!")
    else:
        cli_ui_msg("ERROR: Generated and reconstructed secrets did not match!")
