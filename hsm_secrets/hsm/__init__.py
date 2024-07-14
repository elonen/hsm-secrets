import re
import secrets
import sys
import click
from hsm_secrets.config import HSMConfig
from hsm_secrets.hsm.secret_sharing_ceremony import cli_reconstruction_ceremony, cli_splitting_ceremony
from hsm_secrets.utils import group_by_4, hsm_obj_exists, hsm_put_derived_auth_key, hsm_put_symmetric_auth_key, hsm_put_wrap_key, list_yubikey_hsm_creds, open_hsm_session_with_default_admin, open_hsm_session_with_shared_admin, open_hsm_session_with_yubikey, print_yubihsm_object, prompt_for_secret, pw_check_fromhex, secure_display_secret
import yubihsm.defs, yubihsm.exceptions, yubihsm.objects
from yubihsm.core import AuthSession

import yubikit.hsmauth
import ykman.scripting

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
    2. Set a common wrap key to all devices.
    3. Host a Secret Sharing Ceremony to add a super admin key.
    4. Add user keys (Yubikey auth) to master device.
    5. Generate and store necessary keys on the master device.
    6. Check that all keys are present on master (`compare-to-config`). Iterate if needed.
    7. Clone master device to other ones.
    8. Double check that all keys are present on all devices (`compare-to-config --alldevs`).
    9. Remove default admin key from all devices.

    Management workflow:

    1. Re-add insecure default admin key with shared/backup secret on all devices.
    2. Perform necessary management operations on master device.
    3. Clone master device to other ones.
    4. Remove default admin key from all devices.
    """
    ctx.ensure_object(dict)

# ---------------

@cmd_hsm.command('list-objects')
@click.pass_context
@click.option('--use-default-admin', is_flag=True, help="Use the default admin key (instead of Yubikey)")
@click.option('--alldevs', is_flag=True, help="List objects on all devices")
def list_objects(ctx: click.Context, use_default_admin: bool, alldevs: bool):
    """List objects in the YubiHSM"""

    def do_it(conf, ses, serial):
        objects = ses.list_objects()
        click.echo(f"YubiHSM Objects on device {serial}:")
        for o in objects:
            click.echo("")
            print_yubihsm_object(o)
        click.echo("")

    dev_serials = ctx.obj['config'].general.all_devices.keys() if alldevs else [ctx.obj['devserial']]
    for serial in dev_serials:
        if use_default_admin:
            with open_hsm_session_with_default_admin(ctx, device_serial=serial) as (conf, ses):
                do_it(conf, ses, serial)
        else:
            with open_hsm_session_with_yubikey(ctx, device_serial=serial) as (conf, ses):
                do_it(conf, ses, serial)

# ---------------

@cmd_hsm.command('add-insecure-admin-key')
@click.pass_context
@click.option('--use-backup-secret', is_flag=True, help="Use backup secret instead of shared secret")
@click.option('--alldevs', is_flag=True, help="Add on all devices")
def add_insecure_admin_key(ctx: click.Context, use_backup_secret: bool, alldevs: bool):
    """Re-add insecure default admin key for management operations

    Using either a shared secret or a backup secret, (re-)create the default admin key on the YubiHSM.
    This is a temporary key that should be removed after the management operations are complete.
    """
    swear_you_are_on_airgapped_computer()

    def do_it(conf: HSMConfig, ses: AuthSession, serial: str):
        obj = hsm_put_derived_auth_key(ses, serial, conf, conf.admin.default_admin_key, conf.admin.default_admin_password)
        click.echo(f"OK. Default insecure admin key (0x{obj.id:04x}: '{conf.admin.default_admin_password}') added successfully.")
        click.echo("!!! DON'T FORGET TO REMOVE IT after you're done with the management operations.")

    # Obtain the shared (or backup) password
    password = None
    try:
        if use_backup_secret:
            click.echo("Using backup secret to authenticate (instead of shared secret).")
            is_hex = click.prompt("Is the backup secret hex-encoded (instead of a direct password) [y/n]?", type=bool)

            password = prompt_for_secret("Backup secret", check_fn=(pw_check_fromhex if is_hex else None))
            if is_hex:
                click.echo("Interpreting backup secret as hex-encoded UTF-8 string.")
                password = bytes.fromhex(password).decode('UTF-8')
        else:
            click.echo("Using shared secret to authenticate.")
            password = cli_reconstruction_ceremony().decode('UTF-8')
    except UnicodeDecodeError:
        click.echo("Failed to decode password as UTF-8.")
        raise

    dev_serials = ctx.obj['config'].general.all_devices.keys() if alldevs else [ctx.obj['devserial']]
    for serial in dev_serials:
        try:
            with open_hsm_session_with_shared_admin(ctx, password, device_serial=serial ) as (conf, ses):
                do_it(conf, ses, serial)
        except yubihsm.exceptions.YubiHsmAuthenticationError as e:
            click.echo("ERROR: Failed to authenticate with the provided password.")
            sys.exit(1)

# ---------------

@cmd_hsm.command('remove-insecure-admin-key')
@click.pass_context
@click.option('--alldevs', is_flag=True, help="Remove on all devices")
@click.option('--force', is_flag=True, help="Force removal even if no other admin key exists")
def remove_insecure_admin_key(ctx: click.Context, alldevs: bool, force: bool):
    """Remove insecure default admin key from the YubiHSM(s)

    Last step in the management workflow. Remove the default admin key from the YubiHSM(s).
    The command first checks that a shared admin key exists on the device(s) before removing the default one.
    """
    dev_serials = ctx.obj['config'].general.all_devices.keys() if alldevs else [ctx.obj['devserial']]
    for serial in dev_serials:
        with open_hsm_session_with_default_admin(ctx, device_serial=serial) as (conf, ses):

            default_key = ses.get_object(conf.admin.default_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
            assert isinstance(default_key, yubihsm.objects.AuthenticationKey)

            if hsm_obj_exists(default_key):
                # Check that shared admin key exists before removing the default one
                if not force:
                    shared_key = ses.get_object(conf.admin.shared_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
                    assert isinstance(shared_key, yubihsm.objects.AuthenticationKey)
                    if not hsm_obj_exists(shared_key):
                        click.echo(f"ERROR: Shared admin key not found on device {serial}. You could lose access to the device, so refusing the operation (use --force to override).")
                        raise click.Abort()

                # Ok, it does, we can proceed
                default_key.delete()
                click.echo(f"Ok. Default admin key removed on device {serial}.")
            else:
                click.echo(f"Default admin key not found on device {serial}. Skipping.")

            # Make sure it's really gone
            try:
                if hsm_obj_exists(default_key):
                    click.echo(click.style(f"ERROR!!! Default admin key still exists on device {serial}. Don't leave the airgapped session before removing it.", fg='red'))
                    click.pause("Press ENTER to continue.")
                    raise click.Abort()
            except Exception as e:
                click.echo("ERROR!! Unexpected error while checking that the key is removed. PLEASE VERIFY MANUALLY THAT IT'S GONE!")
                click.pause("Press ENTER to continue.")
                raise e

# ---------------

@cmd_hsm.command('add-shared-admin-key')
@click.option('--num-shares', type=int, required=True, help="Number of shares to generate")
@click.option('--threshold', type=int, required=True, help="Number of shares required to reconstruct the key")
@click.option('--skip-ceremony', is_flag=True, default=False, help="Skip the secret sharing ceremony, ask for password directly")
@click.pass_context
def add_shared_admin_key(ctx: click.Context, num_shares: int, threshold: int, skip_ceremony: bool):
    """Host a Secret Sharing Ceremony to add admin key to the master YubiHSM

    The ceremony is a formal multi-step process where the system generates a new shared admin key
    and splits it into multiple shares. The shares are then distributed to the custodians.
    The key can be reconstructed when at least `threshold` number of shares are combined,
    regardless of `num_shares` generated.

    This is a very heavy process, and should be only done once, on the master YubiHSM.
    The resulting key can then be cloned to other devices via key wrapping operations.
    """
    swear_you_are_on_airgapped_computer()

    def do_it(conf, ses, serial):
        def apply_password_fn(new_password: str):
            hsm_put_derived_auth_key(ses, serial, conf, conf.admin.shared_admin_key, new_password)

        if skip_ceremony:
            apply_password_fn(prompt_for_secret("Enter the (new) shared admin password to store", confirm=True))
        else:
            cli_splitting_ceremony(num_shares, threshold, apply_password_fn)

        click.echo("OK. Shared admin key added successfully.")

    try:
        with open_hsm_session_with_default_admin(ctx) as (conf, ses):
            do_it(conf, ses, ctx.obj['devserial'])
    except yubihsm.exceptions.YubiHsmAuthenticationError as e:
        click.echo("ERROR: Failed to authenticate with the default admin key.")
        sys.exit(1)

# ---------------

@cmd_hsm.command('make-common-wrap-key')
@click.pass_context
def make_wrap_key(ctx: click.Context):
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
            hsm_put_wrap_key(ses, serial, conf, conf.admin.wrap_key, secret)

    del secret
    click.echo(f"OK. Common wrap key added to all devices (serials: {', '.join(dev_serials)}).")

# ---------------

def ask_yubikey_hsm_mgt_key(prompt: str, confirm = False, default = False) -> tuple[str, bytes]:
    """Prompt user for a Yubikey hsmauth Management Key (32 hex characters)"""

    def validate_mgt_key(value: str) -> str|None:
        value = value.replace(' ', '')
        if not re.match(r'^[0-9a-f]{32}$', value):
            return "Management Key must be 32 lower case hex digit."
        if pw_check_fromhex(value) is not None:
            return "Failed to decode hex string."
        return None

    default_str = "0000 0000 0000 0000 0000 0000 0000 0000" if default else None    # Yubico's default mgt key
    key_str = prompt_for_secret(prompt, default=default_str, confirm=confirm, check_fn=validate_mgt_key).replace(' ', '')
    key_bytes = bytes.fromhex(key_str)
    return (key_str, key_bytes)

# ---------------

def change_yubikey_hsm_mgt_key(auth_ses: yubikit.hsmauth.HsmAuthSession, old_key_bin=None, ask_before_change=True):
    """Change the Yubikey hsmauth Management Key (aka. Admin Access Code)"""

    click.echo("A 'Management Key' is required to edit the Yubikey hsmauth slots.")
    click.echo("It must be a 32 hex characters long, e.g. '0011 2233 4455 6677 8899 aabb ccdd eeff'")
    click.echo("This unwieldy key is used rarely. You should probably store it in a password manager.")
    click.echo("")

    if old_key_bin is None:
        _, old_key_bin = ask_yubikey_hsm_mgt_key("Enter the OLD Management Key", default=True)

    if not ask_before_change or click.confirm("Change Management Key now?", default=False, abort=False):
        new_mgt_key = None
        if click.prompt("Generate the key ('n' = enter manually)?", type=bool, default="y"):
            new_mgt_key_bin = secrets.token_bytes(16)
            new_mgt_key = new_mgt_key_bin.hex().lower()
            assert len(new_mgt_key) == 32

            click.echo("Key generated. It will be now shown on screen. Everyone else should look away.")
            click.echo("When you have stored the key, press ENTER again to continue.")
            click.echo("")
            click.pause("Press ENTER to reveal the key.")
            secure_display_secret(group_by_4(new_mgt_key))
        else:
            new_mgt_key, new_mgt_key_bin = ask_yubikey_hsm_mgt_key("Enter the new Management Key", confirm=True)

        auth_ses.put_management_key(old_key_bin, new_mgt_key_bin)
        click.echo("Management Key changed.")

# ---------------

@cmd_hsm.command('set-yubikey-hsmauth-mgt-key')
@click.pass_context
def set_yubikey_hsm_auth_mgt_key(ctx: click.Context):
    """Set the Yubikey hsmauth Management Key (aka. Admin Access Code)

    This can also be done with the `yubihsm-auth -a change-mgmkey -k <oldkey>` command.
    It's included here for convenience.
    """
    yubikey = ykman.scripting.single()    # Connect to the first Yubikey found, prompt user to insert one if not found
    auth_ses = yubikit.hsmauth.HsmAuthSession(connection=yubikey.smart_card())
    _, old_mgt_key_bin = ask_yubikey_hsm_mgt_key("Enter the old Management Key", default=True)
    change_yubikey_hsm_mgt_key(auth_ses, old_mgt_key_bin, ask_before_change=False)

# ---------------

@cmd_hsm.command('add-user-auth')
@click.pass_context
@click.option('--label', required=True, help="Label of the Yubikey hsmauth slot (in config file)")
@click.option('--alldevs', is_flag=True, help="Add to all devices")
def add_user_auth(ctx: click.Context, label: str, alldevs: bool):
    """Add a new user auth key to a) Yubikey hsmauth slot and b) the YubiHSM(s)

    Generate a new password-protected public auth key, and store it in the
    YubiHSM(s) as a user key. The same label will be used on both the Yubikey and the YubiHSM.
    """
    conf: HSMConfig = ctx.obj['config']
    user_key_configs = [uk for uk in conf.user_keys if uk.label == label]
    if not user_key_configs:
        raise click.ClickException(f"User key with label '{label}' not found in the configuration file.")
    elif len(user_key_configs) > 1:
        raise click.ClickException(f"Multiple user keys with label '{label}' found in the configuration file.")

    user_key_conf = user_key_configs[0]

    yubikey = ykman.scripting.single()    # Connect to the first Yubikey found, prompt user to insert one if not found
    yk_auth_ses = yubikit.hsmauth.HsmAuthSession(connection=yubikey.smart_card())
    existing_slots = list(yk_auth_ses.list_credentials())

    old_slot = None
    for slot in existing_slots:
        if slot.label == label:
            old_slot = slot
            click.echo(f"Yubikey hsmauth slot with label '{label}' already exists.")
            click.confirm("Overwrite the existing slot?", default=False, abort=True)    # Abort if user doesn't want to overwrite

    click.echo("Changing Yubikey hsmauth slots requires the Management Key (aka. Admin Access Code)")
    click.echo("(Note: this tool removes spaces, so you can enter the mgt key with or without grouping.)")

    mgt_key, mgt_key_bin = ask_yubikey_hsm_mgt_key("Enter the Management Key", default=True)
    if old_slot:
        yk_auth_ses.delete_credential(mgt_key_bin, old_slot.label)
        click.echo(f"Old key in slot '{old_slot.label}' deleted.")

    click.echo("")
    click.echo("Yubikey hsmauth slots are protected by a password.")
    click.echo("It doesn't have to be very strong, as it's only used as a second factor for the Yubikey.")
    click.echo("It should be something you can remember, but also stored in a password manager.")
    click.echo("")
    cred_password = prompt_for_secret("Enter (ascii-only) password or PIN for the slot", confirm=True, enc_test='ascii')

    ykver = str(yubikey.info.version)
    if ykver >= "5.6.0":
        click.echo(f"NOTE: This Yubikey's version {ykver} would support asymmetric keys. Maybe add support for this command?")
    else:
        click.echo(f"NOTE: This Yubikey's version is {ykver} (< 5.6.0). (Only symmetric keys supported.)")

    click.echo("Generating symmetric key for the slot...")
    key_enc, key_mac = secrets.token_bytes(16), secrets.token_bytes(16)  # key pair, 128 bits each

    # Store the auth key on Yubikey
    cred = yk_auth_ses.put_credential_symmetric(
        management_key=mgt_key_bin,
        label=label,
        key_enc=key_enc,
        key_mac=key_mac,
        credential_password=cred_password,
        touch_required=True)

    click.echo(f"Auth key added to the Yubikey (serial {yubikey.info.serial}) hsmauth slot '{cred.label}' (type: {repr(cred.algorithm)})")

    # Store it in the YubiHSMs
    dev_serials = conf.general.all_devices.keys() if alldevs else [ctx.obj['devserial']]
    for serial in dev_serials:
        with open_hsm_session_with_default_admin(ctx, device_serial=serial) as (conf, ses):
            hsm_put_symmetric_auth_key(ses, serial, conf, user_key_conf, key_enc, key_mac)

    click.echo("OK. User key added" + (f" to all devices (serials: {', '.join(dev_serials)})" if alldevs else "") + ".")
    click.echo("")
    click.echo("TIP! Test with the `list-objects` command to check that Yubikey hsmauth method works correctly.")

    # Also offer to change Yubikey hsmauth Management Key if it's the default one
    if mgt_key == "00000000000000000000000000000000":
        click.echo("")
        click.echo("WARNING! You are using factory default for Yubikey hsmauth Management Key.")
        click.echo("")
        change_yubikey_hsm_mgt_key(yk_auth_ses, mgt_key_bin, ask_before_change=True)

# ---------------

@cmd_hsm.command('compare-to-config')
@click.option('--alldevs', is_flag=True, help="Compare all devices")
@click.option('--use-user-auth', is_flag=True, help="Use user auth key instead of default admin key")
@click.pass_context
def compare_to_config(ctx: click.Context, alldevs: bool, use_user_auth: bool):
    """Check that the YubiHSM configuration matches the configuration file (i.e. all keys are present)

    Lists all objects by type (auth, wrap, etc.) in the configuration file, and then checks
    that they exist in the YubiHSM(s). Shows which objects are missing and which are found.

    By default, only checks the master device, using the default admin key.
    Override with the options as needed.
    """

    conf = ctx.obj['config']
    assert isinstance(conf, HSMConfig)

    # Util function to find all instances of a certain type in a nested structure
    from typing import Type, TypeVar, Generator, Any
    T = TypeVar('T')
    def find_instances(obj: Any, target_type: Type[T]) -> Generator[T, None, None]:
        if isinstance(obj, target_type):
            yield obj
        elif isinstance(obj, (list, tuple, set)):
            for item in obj:
                yield from find_instances(item, target_type)
        elif isinstance(obj, dict):
            for value in obj.values():
                yield from find_instances(value, target_type)
        elif hasattr(obj, '__dict__'):
            for value in vars(obj).values():
                yield from find_instances(value, target_type)

    from hsm_secrets.config import HSMAsymmetricKey, HSMSymmetricKey, HSMWrapKey, OpaqueObject, HSMHmacKey, HSMAuthKey
    config_to_hsm_type = {
        HSMAuthKey: yubihsm.objects.AuthenticationKey,
        HSMWrapKey: yubihsm.objects.WrapKey,
        HSMHmacKey: yubihsm.objects.HmacKey,
        HSMSymmetricKey: yubihsm.objects.SymmetricKey,
        HSMAsymmetricKey: yubihsm.objects.AsymmetricKey,
        OpaqueObject: yubihsm.objects.Opaque,
    }
    config_items_per_type: dict = {t: list(find_instances(conf, t)) for t in config_to_hsm_type.keys()} # type: ignore

    click.echo("")
    click.echo("Reading objects from the YubiHSM(s)...")
    dev_serials = conf.general.all_devices.keys() if alldevs else [ctx.obj['devserial']]
    for serial in dev_serials:

        def do_it(conf, ses, serial):
            device_objs: list[yubihsm.objects.YhsmObject] = list(ses.list_objects())
            click.echo("")
            click.echo(f"--- YubiHSM device {serial} ---")
            objects_accounted_for = {}
            for t, items in config_items_per_type.items():
                click.echo(f"{t.__name__}")
                for it in items:
                    found = False
                    for obj in device_objs:
                        if obj.id == it.id and isinstance(obj, config_to_hsm_type[t]):
                            found = True
                            objects_accounted_for[obj.id] = True
                            break

                    checkbox = "✅" if found else "❌"
                    click.echo(f" {checkbox} '{it.label}' (0x{it.id:04x})")

            if len(objects_accounted_for) < len(device_objs):
                click.echo("EXTRA OBJECTS (on the device but not in the config)")
                for obj in device_objs:
                    if obj.id not in objects_accounted_for:
                        info = obj.get_info()
                        click.echo(f" ❓'{info.label}' (0x{obj.id:04x}) <{obj.__class__.__name__}>")
            click.echo("")

        if use_user_auth:
            with open_hsm_session_with_yubikey(ctx, device_serial=serial) as (conf, ses):
                do_it(conf, ses, serial)
        else:
            with open_hsm_session_with_default_admin(ctx, device_serial=serial) as (conf, ses):
                do_it(conf, ses, serial)



# ---------------

@cmd_hsm.command('clone-master-hsm')
@click.pass_context
def clone_master_hsm(ctx: click.Context):
    """Clone the keys from the master YubiHSM to other connected YubiHSMs"""
    raise NotImplementedError("This command is not yet implemented.")
