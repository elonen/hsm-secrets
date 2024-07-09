import click
from hsm_secrets.utils import connect_hsm_and_auth_with_yubikey, open_hsm_session_with_default_admin, open_hsm_session_with_yubikey
import yubihsm.defs, yubihsm.exceptions, yubihsm.objects

from click import style

def swear_you_are_on_airgapped_machine():
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
def list_objects(ctx: click.Context):
    """List objects in the YubiHSM"""
    with open_hsm_session_with_yubikey(ctx) as (conf, ses):
        objects = ses.list_objects()
        print("YubiHSM Objects:")
        print(objects)


@cmd_hsm.command('add-insecure-admin-key')
@click.pass_context
def add_insecure_admin_key(ctx: click.Context):
    """Add an insecure admin key to the YubiHSM"""
    swear_you_are_on_airgapped_machine()

    click.echo("!! TODO: reconstruct shared admin key from shares and authenticate with it here instead of with yubikey")

    with open_hsm_session_with_yubikey(ctx) as (conf, ses):
        default_key = ses.get_object(conf.admin.default_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
        assert isinstance(default_key, yubihsm.objects.AuthenticationKey)

        try:
            info = default_key.get_info()
            click.echo(f"Default admin key already exists: {default_key} info: {info}. No need to recreate.")
            return
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
            capabilities=conf.CapabilityFromNames(conf.admin.default_admin_key.capabilities),
            delegated_capabilities=conf.CapabilityFromNames(conf.admin.default_admin_key.delegated_capabilities),
            password=conf.admin.default_admin_password)


@cmd_hsm.command('add-wrap-key')
@click.option('--key-id', type=int, required=True, help="ID of the wrap key")
@click.pass_context
def add_wrap_key(ctx: click.Context, key_id: int):
    """Add a new wrap key to the YubiHSM"""
    raise NotImplementedError("This command is not yet implemented.")


@cmd_hsm.command('add-shared-admin-key')
@click.option('--num-shares', type=int, required=True, help="Number of shares to generate")
@click.option('--threshold', type=int, required=True, help="Number of shares required to reconstruct the key")
@click.pass_context
def add_shared_admin_key(ctx: click.Context, num_shares: int, threshold: int):
    """Generate a new shared admin key using Shamir's Secret Sharing and add it to the YubiHSM"""
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


@cmd_hsm.command('remove-insecure-admin-key')
@click.pass_context
def remove_insecure_admin_key(ctx: click.Context, key_id: int):
    """Remove the insecure admin key from the YubiHSM"""
    # Implementation goes here
    with open_hsm_session_with_default_admin(ctx) as (conf, ses):
        default_key = ses.get_object(conf.admin.default_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
        assert isinstance(default_key, yubihsm.objects.AuthenticationKey)
        try:
            info = default_key.get_info()
            click.echo(f"Default admin key exists: {default_key} info: {info}. Removing it...")
            default_key.delete()
        except yubihsm.exceptions.YubiHsmDeviceError as e:
            if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                click.echo("Default admin key not found. Nothing to remove.")
            else:
                raise e

        try:
            info = default_key.get_info()
            click.echo(click.style(f"Default admin key still exists: {default_key} info: {info}.", fg='yellow'))
            click.echo(click.style("!!! Insecure admin key still exists. Don't leave the airgapped session before removing it.", fg='red'))
        except yubihsm.exceptions.YubiHsmDeviceError as e:
            if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                click.echo("Default admin key not found. YubiHSM is now clean.")
            else:
                raise e
