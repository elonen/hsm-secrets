import click
from textwrap import dedent
import re
import curses
import time

from hsm_secrets.hsm.shared_secret import create_secret, split_ssss_secret_humanized, test_shares


def cli_splitting_ceremony(threshold: int, num_shares: int, with_backup_key: bool = True, pre_secret: bytes|None = None):
    """
    Host a splitting ceremony to create shares from a secret, in a CLI session.
    """
    click.clear()

    backup_desc = """
        ## Backup key

        You have chosen to include a backup key in the ceremony.
        This is a way to circumvent the threshold requirement in case of key loss,
        but it also increases the risk of compromise! Each custodian will be shown
        a piece of the (original) secret, and be asked to write it down and to
        put it in an envelope. After the ceremony, the envelope must be sealed
        and stored in a bank vault or similar secure location.

    """
    n_papers = num_shares * 2 if with_backup_key else num_shares
    backup_req = """
        - 1 larger "master envelope" to hold the smaller backup key envelopes
    """ if with_backup_key else ""


    click.echo(dedent(f"""
        # Welcome to the (Shamir's) Secret Sharing Ceremony!

        We will be splitting a secret key into {num_shares} shares,
        with a threshold of {threshold} shares required to reconstruct it.
        {backup_desc if with_backup_key else ''}
        You will need:

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

    """))

    click.confirm("Start the ceremony?", abort=True)

    secret = create_secret(pre_secret)
    click.echo(f"Secret created ({len(secret) * 8} bits).")

    # Split the original key naively into num_shares parts for backup key
    backup_part_len = len(secret) // num_shares
    remaining = b'' + secret
    backup_parts = []
    for i in range(num_shares):
        backup_parts.append(remaining[:backup_part_len])
        remaining = remaining[backup_part_len:]
        if i == num_shares - 1:
            backup_parts[-1] += remaining
    assert len(backup_parts) == num_shares
    assert b''.join(backup_parts) == secret
    assert all(len(bp)>0 for bp in backup_parts)

    click.pause("Press ENTER to continue...")
    click.clear()

    # Make the custodian shares
    shares = split_ssss_secret_humanized(threshold, num_shares, secret)
    for s in shares:
        custodian_n = s.split(' ')[0]
        assert len(custodian_n) == 1

        click.echo(f"Custodian #{custodian_n}, approach the screen. Others must look away.")
        click.echo("")
        click.echo("- Write it down on a piece of paper, fold it and put it in an envelope.")
        click.echo("- KEEP THE ENVELOPE, AND DO NOT SEAL IT YET.")
        click.echo(f"- Write "+ click.style(f"'Custodian #{custodian_n}'", fg='green') + " on the envelope.")
        click.echo("")
        click.pause("Press ENTER to reveal your share. After writing it down, press ENTER again to continue...")
        display_and_wipe_secret(s)
        click.clear()

        if with_backup_key:
            backup_part = backup_parts[int(custodian_n) - 1]
            click.echo("Now, the backup key part.")
            click.echo("")
            click.echo("- Write it down on a piece of paper, fold it and put it in another envelope.")
            click.echo("- Write "+ click.style(f"'Backup key #{custodian_n}/{num_shares}'", fg='green') + " on the envelope.")
            click.echo("- KEEP THE ENVELOPE, AND DO NOT SEAL IT YET.")
            click.echo("")
            click.pause("Press ENTER to reveal your share. After writing it down, press ENTER again to continue...")
            grouped_in_4 = ' '.join([backup_part.hex()[i:i + 4] for i in range(0, len(backup_part.hex()), 4)])
            display_and_wipe_secret(f"{custodian_n}/{num_shares} " + grouped_in_4)
            click.clear()

    click.echo("All shares have been created.")
    click.echo("Now, each custodian will be asked to type in their share to verify it.")

    typed_in_shares = []
    typed_in_backup_parts = []

    for s in shares:
        assert len(s) > 128/8   # Sanity check
        custodian_n = s.split(' ')[0]
        click.echo(f"Custodian #{custodian_n}, approach the keyboard and type in your share. All others must look away.")
        typed_share = click.prompt("Your share:", hide_input=True)
        while not str(typed_share).replace(' ', '').lower() == s.replace(' ', '').lower():
            click.echo("Share does not match. Try again.")
            typed_share = click.prompt("Your share:", hide_input=True)
        typed_in_shares.append(typed_share)
        click.echo(f"Share #{custodian_n} verified.")
        click.echo("")

        def clean_up_backup_part(bp: str):
            # '1/3 1234 5678 90ab'  =>  '1234567890ab'
            return re.sub(r'^[0-9]+ */ *[0-9]+ +', '', bp).replace(' ', '').strip()

        if with_backup_key:
            click.echo(f"Now, type in backup key part #{custodian_n}/{num_shares}")
            typed_backup_part = clean_up_backup_part(click.prompt("Your backup key part:", hide_input=True))

            while not str(typed_backup_part).lower() == backup_parts[int(custodian_n) - 1].hex().lower():
                click.echo("Backup key part does not match. Try again.")
                typed_backup_part = clean_up_backup_part(click.prompt("Your backup key part:", hide_input=True))

            bin_part = bytes.fromhex(typed_backup_part)
            assert bin_part == backup_parts[int(custodian_n) - 1]
            typed_in_backup_parts.append(bin_part)

        click.echo("Share and backup verified. Please seal your envelope(s) now.")
        click.pause("Press ENTER to continue...")
        click.clear()

    backup_secret = b''.join(typed_in_backup_parts)
    assert secret == backup_secret, "Backup key parts do not match the original secret. Ceremony failed."

    n_combs_tested = test_shares(secret, threshold, typed_in_shares)
    click.echo(f"All shares have been verified, and {n_combs_tested} combinations have been tested for reconstruction.")
    click.echo("")
    if with_backup_key:
        click.echo("All custodians, put your backup key envelopes in a common master envelope, and seal it.")
        click.echo("")
        click.echo(dedent("""
            The master envelope should be printed with the following text:

                    CRITICAL: YubiHSM2 Emergency Recovery Key

                    Only take this envelope out of the vault if
                    the following conditions are met:

                    - ALL the sysops personnel, who are currently employed,
                    agree that accessing this envelope is necessary.
                    - The MAJORITY of them are present to authorize the
                    opening of this envelope.

                    The same rules apply for destroying and/or replacing
                    this envelope.

                    Date Sealed: [Date]
                    Sealed by: [Custodian Names]

        """))

    click.echo("The ceremony is now complete.")
    click.echo(click.style("IMPORTANT: After this, CLOSE THE TERMINAL SESSION to ensure that secrets", fg='yellow'))
    click.echo(click.style("are not left in the terminal's scrollback history.", fg='yellow'))


def display_and_wipe_secret(secret:str, wipe_char='x'):
    """
    Display a secret on the screen, and then wipe it with a wipe_char.
    """
    def do_it(stdscr):
        stdscr.clear()

        # Create a new window
        height, width = stdscr.getmaxyx()
        win_height = 3
        win_width = len(secret) + 4
        win = curses.newwin(win_height, win_width, height // 2 - 1, width // 2 - win_width // 2)

        # Display the secret
        win.box()
        win.addstr(1, 2, secret)
        win.refresh()

        click.pause("") # Wait for ENTER key

        # Overwrite the secret with wipe_char
        stdscr.clear()
        win.box()
        win.addstr(1, 2, wipe_char * len(secret))
        win.refresh()

    curses.wrapper(do_it)


if __name__ == '__main__':
    cli_splitting_ceremony(3, 4, with_backup_key=True)
