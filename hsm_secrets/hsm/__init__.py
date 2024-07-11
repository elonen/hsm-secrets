import sys
import click
from hsm_secrets.config import HSMConfig
from hsm_secrets.hsm.secret_sharing_ceremony import cli_reconstruction_ceremony, cli_splitting_ceremony
from hsm_secrets.utils import connect_hsm_and_auth_with_yubikey, open_hsm_session_with_default_admin, open_hsm_session_with_shared_admin, open_hsm_session_with_yubikey, print_yubihsm_object
import yubihsm.defs, yubihsm.exceptions, yubihsm.objects

from click import style

def swear_you_are_on_airgapped_computer():
    click.echo(style(r"""
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|        !!! IMPORTANT: AIRGAPPED MACHINE REQUIRED !!!          |
|                                                               |
|  You are about to perform a critical operation involving      |
|  sensitive data and the security of your YubiHSM devices.     |
|                                                               |
|  It is of utmost importance that you ensure you are on an     |
|  airgapped machine, completely isolated from any network      |
|  connections, to prevent potential security breaches and      |
|  unauthorized access to your sensitive information.           |
|                                                               |
|  Also make sure the operating system is running without       |
|  persistent storage, on Tails Linux OS or similar.            |
|  When done, you might even want to physically destroy the     |
|  media to ensure no data is left behind.                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """, fg='yellow'))
    click.confirm(style("Are you absolutely certain that you are on an airgapped machine?", fg='bright_white', bold=True), abort=True)


@click.group()
@click.pass_context
def cmd_hsm(ctx):
    """YubiHSM2 management / super admin commands"""
    ctx.ensure_object(dict)


@cmd_hsm.command('list-objects')
@click.pass_context
@click.option('--use-default-admin', is_flag=True, help="Use the default admin key (instead of YubiKey)")
def list_objects(ctx: click.Context, use_default_admin: bool):
    """List objects in the YubiHSM"""

    def do_it(conf, ses):
        objects = ses.list_objects()
        click.echo("YubiHSM Objects:")
        for o in objects:
            print_yubihsm_object(o)

    if use_default_admin:
        with open_hsm_session_with_default_admin(ctx) as (conf, ses):
            do_it(conf, ses)
    else:
        click.echo("Using YubiKey to authenticate.")
        with open_hsm_session_with_yubikey(ctx) as (conf, ses):
            do_it(conf, ses)


@cmd_hsm.command('add-insecure-admin-key')
@click.pass_context
@click.option('--use-backup-secret', is_flag=True, help="Use backup secret instead of shared secret")
def add_insecure_admin_key(ctx: click.Context, use_backup_secret: bool):
    """Re-add the insecure default admin key, using shared or backup secret

    Using either a shared secret or a backup secret, (re-)create the default admin key on the YubiHSM.
    This is a temporary key that should be removed after the management operations are complete.
    """
    swear_you_are_on_airgapped_computer()

    def do_it(conf, ses):
        default_key = ses.get_object(conf.admin.default_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
        assert isinstance(default_key, yubihsm.objects.AuthenticationKey)

        try:
            _ = default_key.get_info()  # Raises an exception if the key does not exist
            click.echo(f"Default admin key already exists: {default_key} info:")
            print_yubihsm_object(default_key)
            click.echo("")
            if click.confirm("Overwrite the existing key?", default=False, abort=True):
                default_key.delete()
        except yubihsm.exceptions.YubiHsmDeviceError as e:
            if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                click.echo("Old key not found, creating a new one...")
            else:
                raise e

        default_key.put_derived(
            session=ses,
            object_id=conf.admin.default_admin_key.id,
            label=conf.admin.default_admin_key.label,
            domains=conf.get_domain_bitfield(conf.admin.default_admin_key.domains),
            capabilities=conf.capability_from_names(conf.admin.default_admin_key.capabilities),
            delegated_capabilities=conf.capability_from_names(conf.admin.default_admin_key.delegated_capabilities),
            password=conf.admin.default_admin_password)

        click.echo(f"OK. Default insecure admin key (0x{conf.admin.default_admin_key.id:04x}: '{conf.admin.default_admin_password}') added successfully.")
        click.echo("!!! DON'T FORGET TO REMOVE IT after you're done with the management operations.")

    # Obtain the password
    password = None
    try:
        if use_backup_secret:
            click.echo("Using backup secret to authenticate (instead of shared secret).")
            is_hex = click.prompt("Is the backup secret hex-encoded (instead of a direct password) [y/n]?", type=bool)
            password_text = click.prompt("Backup secret", type=str, hide_input=True)
            assert isinstance(password_text, str)
            if is_hex:
                click.echo("Interpreting backup secret as hex-encoded UTF-8 string.")
                password = bytes.fromhex(password_text).decode('UTF-8')
            else:
                click.echo("Interpreting backup secret as a direct string.")
                password = password_text
        else:
            click.echo("Using shared secret to authenticate.")
            password = cli_reconstruction_ceremony().decode('UTF-8')
    except UnicodeDecodeError:
        click.echo("Failed to decode password as UTF-8.")
        raise

    try:
        with open_hsm_session_with_shared_admin(ctx, password) as (conf, ses):
            do_it(conf, ses)
    except yubihsm.exceptions.YubiHsmAuthenticationError as e:
        click.echo("ERROR: Failed to authenticate with the provided password.")
        sys.exit(1)


@cmd_hsm.command('add-shared-admin-key')
@click.option('--num-shares', type=int, required=True, help="Number of shares to generate")
@click.option('--threshold', type=int, required=True, help="Number of shares required to reconstruct the key")
@click.option('--skip-ceremony', is_flag=True, default=False, help="Skip the secret sharing ceremony, ask for password directly (debug)")
@click.pass_context
def add_shared_admin_key(ctx: click.Context, num_shares: int, threshold: int, skip_ceremony: bool):
    """Host a secret sharing ceremony to add admin key to YubiHSM"""
    swear_you_are_on_airgapped_computer()

    def do_it(conf, ses):
        def apply_password(new_password: str):
            shared_key = ses.get_object(conf.admin.shared_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
            assert isinstance(shared_key, yubihsm.objects.AuthenticationKey)

            try:
                _ = shared_key.get_info()  # Raises an exception if the key does not exist
                click.echo(f"Shared admin key already exists:")
                print_yubihsm_object(shared_key)
                click.echo("")
                if click.confirm("Overwrite the existing key?", default=False, abort=True):
                    shared_key.delete()
                    click.echo("Old key removed. Creating a new one...")
            except yubihsm.exceptions.YubiHsmDeviceError as e:
                if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                    pass    # No key found, proceed
                else:
                    raise e

            shared_key.put_derived(
                session = ses,
                object_id = conf.admin.shared_admin_key.id,
                label = conf.admin.shared_admin_key.label,
                domains = conf.get_domain_bitfield(conf.admin.shared_admin_key.domains),
                capabilities = conf.capability_from_names(conf.admin.shared_admin_key.capabilities),
                delegated_capabilities = conf.capability_from_names(conf.admin.shared_admin_key.delegated_capabilities),
                password = new_password)

        if skip_ceremony:
            apply_password(click.prompt("Enter the (new) shared admin password to store", type=str, hide_input=True))
        else:
            cli_splitting_ceremony(num_shares, threshold, apply_password)

        click.echo("OK. Shared admin key added successfully.")
    try:
        with open_hsm_session_with_default_admin(ctx) as (conf, ses):
            do_it(conf, ses)
    except yubihsm.exceptions.YubiHsmAuthenticationError as e:
        click.echo("ERROR: Failed to authenticate with the default admin key.")
        sys.exit(1)


@cmd_hsm.command('remove-insecure-admin-key')
@click.pass_context
def remove_insecure_admin_key(ctx: click.Context):
    """Remove the insecure default admin key"""
    with open_hsm_session_with_default_admin(ctx) as (conf, ses):
        default_key = ses.get_object(conf.admin.default_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
        assert isinstance(default_key, yubihsm.objects.AuthenticationKey)
        try:
            _ = default_key.get_info()
            default_key.delete()
            click.echo("Ok. Default admin key removed.")
        except yubihsm.exceptions.YubiHsmDeviceError as e:
            if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                click.echo("Default admin key not found. Nothing to remove.")
            else:
                raise e

        # Make sure it's really gone
        try:
            _ = default_key.get_info()
            click.echo(click.style("ERROR!!! Insecure admin key still exists. Don't leave the airgapped session before removing it.", fg='red'))
        except yubihsm.exceptions.YubiHsmDeviceError as e:
            if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                pass # Ok, it's gone
            else:
                click.echo("ERROR!! Unexpected error while checking that the key is removed. PLEASE VERIFY MANUALLY THAT IT'S GONE!")
                click.prompt("Press ENTER to continue...", type=str)
                raise e


@cmd_hsm.command('add-wrap-key')
@click.option('--key-id', type=int, required=True, help="ID of the wrap key")
@click.pass_context
def add_wrap_key(ctx: click.Context, key_id: int):
    """Add a new wrap key to the YubiHSM"""
    raise NotImplementedError("This command is not yet implemented.")


@cmd_hsm.command('sync-with-config')
@click.option('--config-file', type=click.Path(exists=True), required=True, help="Path to the configuration file")
@click.pass_context
def sync_with_config(ctx: click.Context, config_file: str):
    """Synchronize the YubiHSM with the provided configuration file"""
    raise NotImplementedError("This command is not yet implemented.")


@cmd_hsm.command('replicate-master-hsm')
@click.option('--master-hsm-id', type=str, required=True, help="ID of the master YubiHSM")
@click.pass_context
def replicate_master_hsm(ctx: click.Context, master_hsm_id: str):
    """Replicate the keys from the master YubiHSM to the connected YubiHSMs"""
    raise NotImplementedError("This command is not yet implemented.")
