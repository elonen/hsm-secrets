import sys
import click
from hsm_secrets.config import HSMConfig
from hsm_secrets.hsm.secret_sharing_ceremony import cli_reconstruction_ceremony, cli_splitting_ceremony
from hsm_secrets.utils import open_hsm_session_with_default_admin, open_hsm_session_with_shared_admin, open_hsm_session_with_yubikey, print_yubihsm_object
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
    """YubiHSM2 management / super admin commands

    These commands generally require a group of HSM custodians working together
    on an airgapped machine to perform security-sensitive operations on the YubiHSMs.

    `list-objects` is an exception. It can be run by anyone alone.

    HSM setup workflow:

    0. Connect all devices.
    1. Reset devices to factory defaults.
    2. Set common wrap key to all devices.
    3. Host a secret sharing ceremony to add admin key.
    4. Add user keys (Yubikey auth) to master device.
    5. Sync configuration to master device (generate missing secrets)
    6. Clone master device to other ones.
    7. Remove default admin key from all devices.

    Management workflow:

    1. Re-add insecure default admin key with shared/backup secret on all devices.
    2. Perform necessary management operations on master device.
    3. Clone master device to other ones.
    4. Remove default admin key from all devices.
    """
    ctx.ensure_object(dict)


@cmd_hsm.command('list-objects')
@click.pass_context
@click.option('--use-default-admin', is_flag=True, help="Use the default admin key (instead of YubiKey)")
@click.option('--alldevs', is_flag=True, help="List objects on all devices")
def list_objects(ctx: click.Context, use_default_admin: bool, alldevs: bool):
    """List objects in the YubiHSM"""

    def do_it(conf, ses, serial):
        objects = ses.list_objects()
        click.echo(f"YubiHSM Objects on device {serial}:")
        for o in objects:
            print_yubihsm_object(o)

    dev_serials = ctx.obj['config'].general.all_devices.keys() if alldevs else [ctx.obj['devserial']]
    for serial in dev_serials:
        if use_default_admin:
            with open_hsm_session_with_default_admin(ctx, device_serial=serial) as (conf, ses):
                do_it(conf, ses, serial)
        else:
            click.echo("Using YubiKey to authenticate.")
            with open_hsm_session_with_yubikey(ctx, device_serial=serial) as (conf, ses):
                do_it(conf, ses, serial)


@cmd_hsm.command('add-insecure-admin-key')
@click.pass_context
@click.option('--use-backup-secret', is_flag=True, help="Use backup secret instead of shared secret")
def add_insecure_admin_key(ctx: click.Context, use_backup_secret: bool):
    """Re-add insecure default admin key for management operations

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
            session = ses,
            object_id = conf.admin.default_admin_key.id,
            label = conf.admin.default_admin_key.label,
            domains = conf.get_domain_bitfield(conf.admin.default_admin_key.domains),
            capabilities = conf.capability_from_names(conf.admin.default_admin_key.capabilities),
            delegated_capabilities = conf.capability_from_names(conf.admin.default_admin_key.delegated_capabilities),
            password = conf.admin.default_admin_password)

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


@cmd_hsm.command('remove-insecure-admin-key')
@click.pass_context
@click.option('--alldevs', is_flag=True, help="Remove on all devices")
@click.option('--force', is_flag=True, help="Force removal even if no other admin key exists")
def remove_insecure_admin_key(ctx: click.Context, alldevs: bool, force: bool):
    """Remove insecure default admin key from the YubiHSM(s)"""

    dev_serials = ctx.obj['config'].general.all_devices.keys() if alldevs else [ctx.obj['devserial']]

    for serial in dev_serials:
        with open_hsm_session_with_default_admin(ctx, device_serial=serial) as (conf, ses):
            default_key = ses.get_object(conf.admin.default_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
            assert isinstance(default_key, yubihsm.objects.AuthenticationKey)
            try:
                _ = default_key.get_info()

                try:
                    # Check that shared admin key exists
                    if not force:
                        shared_key = ses.get_object(conf.admin.shared_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
                        _ = shared_key.get_info()

                    # Ok, it does, we can remove the default one
                    default_key.delete()
                    click.echo(f"Ok. Default admin key removed on device {serial}.")

                except yubihsm.exceptions.YubiHsmDeviceError as e:
                    if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                        click.echo(f"ERROR: Shared admin key not found on device {serial}. You could lose access to the device, so refusing the operation (use --force to override).")
                        raise click.Abort()
                    else:
                        raise e

            except yubihsm.exceptions.YubiHsmDeviceError as e:
                if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                    click.echo(f"Default admin key not found on device {serial}. Skipping.")
                else:
                    raise e

            # Make sure it's really gone
            try:
                _ = default_key.get_info()
                click.echo(click.style(f"ERROR!!! Insecure admin key still exists on device {serial}. Don't leave the airgapped session before removing it.", fg='red'))
            except yubihsm.exceptions.YubiHsmDeviceError as e:
                if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                    pass # Ok, it's gone
                else:
                    click.echo("ERROR!! Unexpected error while checking that the key is removed. PLEASE VERIFY MANUALLY THAT IT'S GONE!")
                    click.prompt("Press ENTER to continue...", type=str)
                    raise e


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



@cmd_hsm.command('set-common-wrap-key')
@click.pass_context
def add_wrap_key(ctx: click.Context):
    """Set a new wrap key to all YubiHSMs

    Generate a new wrap key and set it to all configured YubiHSMs.
    It is used to export/import keys securely between the devices.
    This requires all the devices in config file to be connected and reachable.
    """
    swear_you_are_on_airgapped_computer()

    dev_serials = []
    secret = None
    with open_hsm_session_with_default_admin(ctx) as (conf, ses):
        dev_serials = conf.general.all_devices.keys()
        assert len(dev_serials) > 0, "No devices found in the configuration file."
        click.echo("Generating secret on master device...")
        secret = ses.get_pseudo_random(256//8)

    click.echo("Secret generated. Distributing it to all devices...")
    click.echo("")

    for serial in dev_serials:
        with open_hsm_session_with_default_admin(ctx, device_serial=serial) as (conf, ses):
            key_id = conf.admin.wrap_key.id
            wrap_key = ses.get_object(key_id, yubihsm.defs.OBJECT.WRAP_KEY)
            assert isinstance(wrap_key, yubihsm.objects.WrapKey)
            try:
                _ = wrap_key.get_info()  # Raises an exception if the key does not exist
                click.echo(f"Wrap key 0x{key_id:04x} already exists on device {serial}:")
                print_yubihsm_object(wrap_key)
                click.echo("")
                if click.confirm("Overwrite the existing key?", default=False, abort=False):
                    wrap_key.delete()
                else:
                    click.echo(f" !! Skipping wrap key setup on device {serial}.")
                    continue
            except yubihsm.exceptions.YubiHsmDeviceError as e:
                if e.code == yubihsm.defs.ERROR.OBJECT_NOT_FOUND:
                    pass    # No key found, proceed
                else:
                    raise e

            click.echo(f"Adding wrap key 0x{key_id:04x} to device {serial}...")

            wrap_key.put(
                key = secret,
                session = ses,
                object_id = key_id,
                label = conf.admin.wrap_key.label,
                algorithm = conf.algorithm_from_name(conf.admin.wrap_key.algorithm),
                domains = conf.get_domain_bitfield(conf.admin.wrap_key.domains),
                capabilities = conf.capability_from_names(set(conf.admin.wrap_key.capabilities)),
                delegated_capabilities = conf.capability_from_names(set(conf.admin.wrap_key.delegated_capabilities)))

    del secret
    click.echo(f"OK. Common wrap key added to all devices (serials: {', '.join(dev_serials)}).")


@cmd_hsm.command('sync-with-config')
@click.option('--config-file', type=click.Path(exists=True), required=True, help="Path to the configuration file")
@click.pass_context
def sync_with_config(ctx: click.Context, config_file: str):
    """Synchronize the YubiHSM with the provided configuration file"""
    raise NotImplementedError("This command is not yet implemented.")


@cmd_hsm.command('clone-master-hsm')
@click.pass_context
def clone_master_hsm(ctx: click.Context):
    """Clone the keys from the master YubiHSM to other connected YubiHSMs"""
    raise NotImplementedError("This command is not yet implemented.")
