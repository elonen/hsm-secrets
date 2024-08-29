
import click

from hsm_secrets.secret_sharing.ceremony import cli_reconstruction_ceremony, cli_splitting_ceremony
from hsm_secrets.secret_sharing.ui import SecretSharingMockUI


def test_secret_sharing_ceremony_and_reconstruction():
    ui = SecretSharingMockUI(2, ["Alice", "Bob", "Charlie"], [None, "password2", None])

    correct_secret = None
    def apply_secret(secret: bytes):
        assert isinstance(secret, bytes)
        nonlocal correct_secret
        correct_secret = secret
        ui.msg(click.style(f"\n    [~~ SIMULATION: called apply_secret('{str(secret)}') ~~]\n", fg='cyan'))

    cli_splitting_ceremony(2, 3, apply_secret, with_backup_key=True, ui=ui)

    ui.msg("---------- SPLITTING DONE ----------")
    ui.msg("Now, let's try to reconstruct the secret.")
    ui.msg("")
    ui.pause("Press ENTER to continue...")

    reconst = cli_reconstruction_ceremony(ui=ui)
    ui.msg(click.style("Correct secret: " + str(correct_secret), fg='green'))
    ui.msg(click.style(f"Reconstructed secret: {str(reconst)}", fg='green'))

    assert correct_secret == reconst, "TEST FAILED: Generated and reconstructed secrets did not match!"
    ui.msg("Test Ok")
