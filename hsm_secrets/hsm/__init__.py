import datetime
from io import BytesIO
from pathlib import Path
import sys
import tarfile
import click

from hsm_secrets.config import HSMConfig, find_all_config_items_per_type
from hsm_secrets.hsm.secret_sharing_ceremony import cli_reconstruction_ceremony, cli_splitting_ceremony
from hsm_secrets.utils import HSMAuthMethod, HsmSecretsCtx, cli_error, cli_info, cli_result, cli_ui_msg, cli_warn, hsm_generate_asymmetric_key, hsm_generate_hmac_key, hsm_generate_symmetric_key, hsm_obj_exists, hsm_put_derived_auth_key, hsm_put_wrap_key, open_hsm_session, open_hsm_session_with_password, pass_common_args, pretty_fmt_yubihsm_object, prompt_for_secret, pw_check_fromhex

import yubihsm.defs, yubihsm.exceptions, yubihsm.objects    # type: ignore [import]
from yubihsm.core import AuthSession    # type: ignore [import]

from click import style

def swear_you_are_on_airgapped_computer():
    cli_ui_msg(style(r"""
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
    click.confirm(style("Are you absolutely certain that you are on an airgapped machine?", fg='bright_white', bold=True), abort=True, err=True)


@click.group()
@click.pass_context
def cmd_hsm(ctx: click.Context):
    """YubiHSM2 device management commands

    These commands generally require a group of HSM custodians working together
    on an airgapped machine to perform security-sensitive operations on the YubiHSMs.

    `list-objects` is an exception. It can be run by anyone alone.

    HSM setup workflow:

    0. Connect all devices.
    1. Reset devices to factory defaults.
    2. Set a common wrap key to all devices.
    3. Host a Secret Sharing Ceremony to add a super admin key.
    4. Add user keys (Yubikey auth) to master device.
    5. Generate keys on master device with `compare-config --create`.
    6. Create certificates etc from the keys.
    7. Check that all configure objects are present on master (`compare-config`).
    8. Clone master device to other ones (backup + restore).
    9. Double check that all keys are present on all devices (`compare-config --alldevs`).
    10. Remove default admin key from all devices.

    Management workflow:

    1. Re-add insecure default admin key with shared/backup secret on all devices.
    2. Perform necessary management operations on master device.
    3. Clone master device to other ones.
    4. Remove default admin key from all devices.
    """
    ctx.ensure_object(dict)

# ---------------

@cmd_hsm.command('list-objects')
@pass_common_args
@click.option('--alldevs', is_flag=True, help="List objects on all devices")
def list_objects(ctx: HsmSecretsCtx, alldevs: bool):
    """List objects in the YubiHSM"""
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        with open_hsm_session(ctx, device_serial=serial) as ses:
            cli_info(f"YubiHSM Objects on device {serial}:")
            cli_info("")
            for o in ses.list_objects():
                cli_result(pretty_fmt_yubihsm_object(o))
                cli_result("")

# ---------------

@cmd_hsm.command('insecure-admin-key-enable')
@pass_common_args
@click.option('--use-backup-secret', is_flag=True, help="Use backup secret instead of shared secret")
@click.option('--alldevs', is_flag=True, help="Add on all devices")
def insecure_admin_key_enable(ctx: HsmSecretsCtx, use_backup_secret: bool, alldevs: bool):
    """Re-add insecure default admin key to HSM

    Using either a shared secret or a backup secret, (re-)create the default admin key on the YubiHSM(s).
    This is a temporary key that should be removed after the management operations are complete.
    """
    swear_you_are_on_airgapped_computer()

    def do_it(conf: HSMConfig, ses: AuthSession, serial: str):
        obj = hsm_put_derived_auth_key(ses, serial, conf, conf.admin.default_admin_key, conf.admin.default_admin_password)
        cli_ui_msg(f"OK. Default insecure admin key (0x{obj.id:04x}: '{conf.admin.default_admin_password}') added successfully.")
        cli_ui_msg("!!! DON'T FORGET TO REMOVE IT after you're done with the management operations.")

    # This command exceptionally uses shared or backup secret to authenticate, unless explicitly forced
    password = None
    if not ctx.forced_auth_method:
        # Obtain the shared (or backup) password
        try:
            if use_backup_secret:
                cli_ui_msg("Using backup secret to authenticate (instead of shared secret).")
                is_hex = click.prompt("Is the backup secret hex-encoded (instead of a direct password) [y/n]?", type=bool, err=True)

                password = prompt_for_secret("Backup secret", check_fn=(pw_check_fromhex if is_hex else None))
                if is_hex:
                    cli_ui_msg("Interpreting backup secret as hex-encoded UTF-8 string.")
                    password = bytes.fromhex(password).decode('UTF-8')
            else:
                cli_ui_msg("Using shared secret to authenticate.")
                password = cli_reconstruction_ceremony().decode('UTF-8')
        except UnicodeDecodeError:
            cli_error("Failed to decode password as UTF-8.")
            raise

    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        try:
            if not ctx.forced_auth_method:
                assert password is not None
                shared_key_id = ctx.conf.admin.shared_admin_key.id
                with open_hsm_session_with_password(ctx, shared_key_id, password, device_serial=serial ) as ses:
                    do_it(ctx.conf, ses, serial)
            else:
                with open_hsm_session(ctx, device_serial=serial) as ses:
                    do_it(ctx.conf, ses, serial)
        except yubihsm.exceptions.YubiHsmAuthenticationError as e:
            raise click.ClickException("Failed to authenticate with the provided password.")


# ---------------

@cmd_hsm.command('insecure-admin-key-disable')
@pass_common_args
@click.option('--alldevs', is_flag=True, help="Remove on all devices")
@click.option('--force', is_flag=True, help="Force removal even if no other admin key exists")
def insecure_admin_key_disable(ctx: HsmSecretsCtx, alldevs: bool, force: bool):
    """Remove insecure default admin key from the YubiHSM(s)

    Last step in the management workflow. Remove the default admin key from the YubiHSM(s).
    The command first checks that a shared admin key exists on the device(s) before removing the default one.
    """
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, serial) as ses:
            default_key = ses.get_object(ctx.conf.admin.default_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
            assert isinstance(default_key, yubihsm.objects.AuthenticationKey)

            if hsm_obj_exists(default_key):
                # Check that shared admin key exists before removing the default one
                if not force:
                    shared_key = ses.get_object(ctx.conf.admin.shared_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
                    assert isinstance(shared_key, yubihsm.objects.AuthenticationKey)
                    if not hsm_obj_exists(shared_key):
                        raise click.ClickException(f"Shared admin key not found on device {serial}. You could lose access to the device, so refusing the operation (use --force to override).")

                # Ok, it does, we can proceed
                default_key.delete()
                cli_info(f"Ok. Default admin key removed on device {serial}.")
            else:
                cli_warn(f"Default admin key not found on device {serial}. Skipping.")

            # Make sure it's really gone
            try:
                if hsm_obj_exists(default_key):
                    cli_error(f"ERROR!!! Default admin key still exists on device {serial}. Don't leave the airgapped session before removing it.")
                    click.pause("Press ENTER to continue.", err=True)
                    raise click.Abort()
            except Exception as e:
                cli_error("ERROR!! Unexpected error while checking that the key is removed. PLEASE VERIFY MANUALLY THAT IT'S GONE!")
                click.pause("Press ENTER to continue.", err=True)
                raise e

# ---------------

@cmd_hsm.command('make-shared-admin-key')
@click.option('--num-shares', type=int, required=True, help="Number of shares to generate")
@click.option('--threshold', type=int, required=True, help="Number of shares required to reconstruct the key")
@click.option('--skip-ceremony', is_flag=True, default=False, help="Skip the secret sharing ceremony, ask for password directly")
@pass_common_args
def make_shared_admin_key(ctx: HsmSecretsCtx, num_shares: int, threshold: int, skip_ceremony: bool):
    """Host an admin key Secret Sharing Ceremony

    The ceremony is a formal multi-step process where the system generates a new shared admin key
    and splits it into multiple shares. The shares are then distributed to the custodians.
    The key can be reconstructed when at least `threshold` number of shares are combined,
    regardless of `num_shares` generated.

    This is a very heavy process, and should be only done once, on the master YubiHSM.
    The resulting key can then be cloned to other devices via key wrapping operations.
    """
    swear_you_are_on_airgapped_computer()
    with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
        def apply_password_fn(new_password: str):
            hsm_put_derived_auth_key(ses, ctx.hsm_serial, ctx.conf, ctx.conf.admin.shared_admin_key, new_password)

        if skip_ceremony:
            apply_password_fn(prompt_for_secret("Enter the (new) shared admin password to store", confirm=True))
        else:
            secret = ses.get_pseudo_random(256//8)
            cli_splitting_ceremony(num_shares, threshold, apply_password_fn, pre_secret=secret)

        cli_info("OK. Shared admin key added successfully.")


# ---------------

@cmd_hsm.command('make-common-wrap-key')
@pass_common_args
def make_wrap_key(ctx: HsmSecretsCtx):
    """Set a new wrap key to all YubiHSMs

    Generate a new wrap key and set it to all configured YubiHSMs.
    It is used to export/import keys securely between the devices.
    This requires all the devices in config file to be connected and reachable.
    """
    hsm_serials = ctx.conf.general.all_devices.keys()
    assert len(hsm_serials) > 0, "No devices found in the configuration file."

    swear_you_are_on_airgapped_computer()

    with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
        cli_info("Generating secret on master device...")
        secret = ses.get_pseudo_random(256//8)

    cli_info("Secret generated. Distributing it to all devices...")
    cli_info("")

    for serial in hsm_serials:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
            hsm_put_wrap_key(ses, serial, ctx.conf, ctx.conf.admin.wrap_key, secret)

    del secret
    cli_info(f"OK. Common wrap key added to all devices (serials: {', '.join(hsm_serials)}).")

# ---------------

@cmd_hsm.command('delete-object')
@click.argument('cert_ids', nargs=-1, type=str, metavar='<id>...')
@click.option('--alldevs', is_flag=True, help="Delete on all devices")
@click.option('--force', is_flag=True, help="Force deletion without confirmation (use with caution)")
@pass_common_args
def delete_object(ctx: HsmSecretsCtx, cert_ids: tuple, alldevs: bool, force: bool):
    """Delete an object from the YubiHSM

    Deletes an object with the given ID from the YubiHSM.
    YubiHSM2 identifies objects by type in addition to ID, so the command
    asks you to confirm the type of the object before deleting it.

    With `--force` ALL objects with the given ID will be deleted
    without confirmation, regardless of their type.
    """
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, serial) as ses:
            not_found = set(cert_ids)
            for id in cert_ids:
                id_int = int(id.replace('0x', ''), 16)
                objects = ses.list_objects()
                for o in objects:
                    if o.id == id_int:
                        not_found.remove(id)
                        if not force:
                            cli_ui_msg("Object found:")
                            cli_ui_msg(pretty_fmt_yubihsm_object(o))
                            click.confirm("Delete this object?", default=False, abort=True, err=True)
                        o.delete()
                        cli_info("Object deleted.")
        if not_found:
            cli_error(f"Objects not found on device {serial}: {', '.join(not_found)}")

# ---------------

@cmd_hsm.command('compare-config')
@click.option('--alldevs', is_flag=True, help="Compare all devices")
@click.option('--create', is_flag=True, help="Create missing keys in the YubiHSM")
@pass_common_args
def compare_config(ctx: HsmSecretsCtx, alldevs: bool, create: bool):
    """Compare config file with device contents

    Lists all objects by type (auth, wrap, etc.) in the configuration file, and then checks
    that they exist in the YubiHSM(s). Shows which objects are missing and which are found.

    By default, only checks the master device, using the default admin key.
    Override with the options as needed.

    If `--create` is given, missing keys will be created in the YubiHSM.
    It only supports one device at a time, and requires the default admin key.
    """
    if create and alldevs:
        raise click.ClickException("The --create option only supports one device at a time, and requires the default admin key.")

    assert isinstance(ctx.conf, HSMConfig)
    config_items_per_type, config_to_hsm_type = find_all_config_items_per_type(ctx.conf)

    cli_info("")
    cli_info("Reading objects from the YubiHSM(s)...")
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, serial) as ses:
            device_objs = list(ses.list_objects())
            cli_info("")
            cli_result(f"--- YubiHSM device {serial} ---")
            objects_accounted_for = {}
            n_created, n_skipped = 0, 0

            for t, items in config_items_per_type.items():
                cli_result(f"{t.__name__}")
                for it in items:
                    obj: yubihsm.objects.YhsmObject|None = None
                    for o in device_objs:
                        if o.id == it.id and isinstance(o, config_to_hsm_type[t]):
                            obj = o
                            objects_accounted_for[o.id] = True
                            break
                    checkbox = "[x]" if obj else "[ ]"
                    cli_result(f" {checkbox} '{it.label}' (0x{it.id:04x})")
                    if create:
                        need_create = obj is None
                        if need_create:
                            from hsm_secrets.config import HSMAsymmetricKey, HSMSymmetricKey, HSMWrapKey, OpaqueObject, HSMHmacKey, HSMAuthKey
                            unsupported_types = (HSMWrapKey, HSMAuthKey, OpaqueObject)

                            gear_emoji = click.style("⚙️", fg='cyan')

                            if isinstance(it, unsupported_types):
                                warn_emoji = click.style("⚠️", fg='yellow')
                                cli_result(f"  └-> {warn_emoji} Cannot create '{it.__class__.__name__}' objects. Use other commands.")
                                n_skipped += 1
                            elif isinstance(it, HSMAsymmetricKey):
                                cli_result(f"  └-> {gear_emoji} Creating...")
                                hsm_generate_asymmetric_key(ses, serial, ctx.conf, it)
                                n_created += 1
                            elif isinstance(it, HSMSymmetricKey):
                                cli_result(f"  └-> {gear_emoji} Creating...")
                                hsm_generate_symmetric_key(ses, serial, ctx.conf, it)
                                n_created += 1
                            elif isinstance(it, HSMHmacKey):
                                cli_result(f"  └-> {gear_emoji} Creating...")
                                hsm_generate_hmac_key(ses, serial, ctx.conf, it)
                                n_created += 1
                            else:
                                cli_result(click.style(f"  └-> Unsupported object type: {it.__class__.__name__}. This is a bug. SKIPPING.", fg='red'))
                                n_skipped += 1

            if len(objects_accounted_for) < len(device_objs):
                cli_result("EXTRA OBJECTS (on the device but not in the config)")
                for o in device_objs:
                    if o.id not in objects_accounted_for:
                        info = o.get_info()
                        cli_result(f" ??? '{str(info.label)}' (0x{o.id:04x}) <{o.__class__.__name__}>")

            if create:
                cli_info("")
                cli_info(f"KEY CREATION REPORT: Created {n_created} objects, skipped {n_skipped} objects. Run the command again without --create to verify status.")

            cli_info("")


# ---------------

@cmd_hsm.command('attest-key')
@pass_common_args
@click.argument('cert_id', required=True, type=str, metavar='<id>')
@click.option('--out', '-o', type=click.File('w', encoding='utf8'), help='Output file (default: stdout)', default=click.get_text_stream('stdout'))
def attest_key(ctx: HsmSecretsCtx, cert_id: str, out: click.File):
    """Attest an asymmetric key in the YubiHSM

    Create an a key attestation certificate, signed by the
    Yubico attestation key, for the given key ID (in hex).
    """
    from cryptography.hazmat.primitives.serialization import Encoding

    id = int(cert_id.replace('0x', ''), 16)
    with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, ctx.hsm_serial) as ses:
        key = ses.get_object(id, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
        assert isinstance(key, yubihsm.objects.AsymmetricKey)
        if not hsm_obj_exists(key):
            raise click.ClickException(f"Key with ID 0x{id:04x} not found in the YubiHSM.")
        cert = key.attest()
        pem = cert.public_bytes(Encoding.PEM).decode('UTF-8')
        out.write(pem)  # type: ignore
        cli_info(f"Key 0x{id:04x} attestation certificate written to '{out.name}'")

# ---------------

@cmd_hsm.command('backup-hsm')
@pass_common_args
@click.option('--out', '-o', type=click.Path(exists=False, allow_dash=False), required=False, help='Output file', default=None)
def backup_hsm(ctx: HsmSecretsCtx, out: click.File|None):
    """Make a .tar.gz backup of HSM

    Exports all objects under wrap from the YubiHSM and saves them
    to a .tar.gz file. The file can be used to restore the objects
    to the same or another YubiHSM device that has the same wrap key.
    """
    cli_info("")
    cli_info(f"Reading objects from YubiHSM device {ctx.hsm_serial}...")

    # Open the output file
    fh = None
    if out is None:
        p = Path(f"yubihsm2-device-{ctx.hsm_serial}-wrapped-backup.tar.gz")
        if p.exists():
            click.confirm(f"File '{p}' already exists. Overwrite?", abort=True, err=True)
        fh = p.open('wb')
    else:
        cli_info(f"Writing tar.gz format to '{out}'")
        fh = Path(str(out)).open('wb')
    tar = tarfile.open(fileobj=fh, mode='w:gz')

    skipped = 0
    with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, ctx.hsm_serial) as ses:

        wrap_key = ses.get_object(ctx.conf.admin.wrap_key.id, yubihsm.defs.OBJECT.WRAP_KEY)
        assert isinstance(wrap_key, yubihsm.objects.WrapKey)
        if not hsm_obj_exists(wrap_key):
            raise click.ClickException("Configured wrap key not found in the YubiHSM.")

        device_objs = list(ses.list_objects())
        for obj in device_objs:

            # Try to export the object
            try:
                key_bytes = wrap_key.export_wrapped(obj)
            except yubihsm.exceptions.YubiHsmDeviceError as e:
                skipped += 1
                if e.code == yubihsm.defs.ERROR.INSUFFICIENT_PERMISSIONS:
                    cli_warn(f"- Warning: Skipping 0x{obj.id:04x}: Insufficient permissions to export object.")
                    continue
                else:
                    cli_warn(f"- Error: Failed to export object 0x{obj.id:04x}: {e}")
                    continue

            # Write to tar
            file_name = f"{obj.object_type.name}--0x{obj.id:04x}--{obj.get_info().label}.bin"
            tarinfo = tarfile.TarInfo(name=file_name)
            tarinfo.size = len(key_bytes)
            tarinfo.mtime = int(datetime.datetime.now().timestamp())
            tar.addfile(tarinfo, fileobj=BytesIO(key_bytes))

            cli_info(f"- Exported 0x{obj.id:04x}: ({obj.object_type.name}): {obj.get_info().label}")

    tar.close()
    cli_info("")
    cli_info("Backup complete.")
    if skipped:
        cli_warn(f"Skipped {skipped} objects due to errors or insufficient permissions.")


@cmd_hsm.command('restore-hsm')
@pass_common_args
@click.argument('backup_file', type=click.Path(exists=True, allow_dash=False), required=True, metavar='<backup_file>')
@click.option('--force', is_flag=True, help="Don't ask for confirmation before restoring")
def restore_hsm(ctx: HsmSecretsCtx, backup_file: str, force: bool):
    """Restore a .tar.gz backup to HSM

    Imports all objects from a .tar.gz backup file to the YubiHSM.
    The backup file must have been created with the `backup-hsm` command, file names
    must be in the format `object_type--id--label.bin`.

    The same wrap key must be present in the YubiHSM to restore the objects as they were exported with.
    """
    cli_info("")
    if not force:
        click.confirm(f"WARNING: This will overwrite existing objects in the YubiHSM device {ctx.hsm_serial}. Continue?", abort=True, err=True)
        if ctx.hsm_serial == ctx.conf.general.master_device:
            click.confirm("This is the configured master device. Are you ABSOLUTELY sure you want to continue?", abort=True, err=True)

    with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:

        wrap_key = ses.get_object(ctx.conf.admin.wrap_key.id, yubihsm.defs.OBJECT.WRAP_KEY)
        assert isinstance(wrap_key, yubihsm.objects.WrapKey)
        if not hsm_obj_exists(wrap_key):
            raise click.ClickException("Configured wrap key not found in the YubiHSM.")

        with open(backup_file, 'rb') as fh:
            tar = tarfile.open(fileobj=fh, mode='r:gz')
            for tarinfo in tar:
                name = tarinfo.name
                assert name.endswith('.bin'), f"Unexpected file extension in tar archive: '{name}'"
                assert name.count('--') == 2, f"Unexpected file name format in tar archive: '{name}'"
                obj_id = int(name.split('--')[1].replace('0x', ''), 16)
                obj_type = name.split('--')[0]

                cli_info(f"- Importing object from '{tarinfo.name}'...")

                obj_enum = yubihsm.defs.OBJECT.__members__.get(obj_type)
                if obj_enum is None:
                    cli_info(click.style(f"   └-> Skipping unknown object type '{obj_type}' in backup. File: '{name}'", fg='yellow'))
                    continue

                if obj_enum == yubihsm.defs.OBJECT.WRAP_KEY and obj_id == wrap_key.id:
                    cli_info(click.style(f"   └-> Skipping wrap key 0x{obj_id:04x} that we are currently using for restoring.", fg='yellow'))
                    continue

                obj = ses.get_object(obj_id, obj_enum)
                if hsm_obj_exists(obj):
                    if force or click.confirm(f"   └-> Object 0x{obj_id:04x} ({obj_type}) already exists. Overwrite?", default=False, err=True):
                        cli_info(f"      └-> Deleting existing {obj_type} 0x{obj_id:04x}'")
                        obj.delete()
                    else:
                        cli_info(click.style(f"      └-> Skipping existing {obj_type} 0x{obj_id:04x}'", fg='yellow'))
                        continue

                tarfh = tar.extractfile(tarinfo)
                assert tarfh is not None, f"Failed to extract file '{tarinfo.name}' from tar archive."
                key_bytes = tarfh.read()
                obj = wrap_key.import_wrapped(key_bytes)
                cli_info(f"   └-> Restored: 0x{obj.id:04x}: ({obj.object_type.name}): {str(obj.get_info().label)}")
                cli_info("")

    cli_info("")
    cli_info("Restore complete.")
