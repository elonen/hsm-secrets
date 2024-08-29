import datetime
from io import BytesIO
from pathlib import Path
import tarfile
from typing import cast
import click

from hsm_secrets.config import HSMAsymmetricKey, HSMConfig, click_hsm_obj_auto_complete, find_all_config_items_per_type, parse_keyid
from hsm_secrets.secret_sharing.ceremony import cli_reconstruction_ceremony, cli_splitting_ceremony
from hsm_secrets.log import _check_and_format_audit_conf_differences
from hsm_secrets.utils import HSMAuthMethod, HsmSecretsCtx, cli_error, cli_info, cli_result, cli_ui_msg, cli_warn, confirm_and_delete_old_yubihsm_object_if_exists, open_hsm_session, open_hsm_session_with_password, pass_common_args, pretty_fmt_yubihsm_object, prompt_for_secret, pw_check_fromhex

from hsm_secrets.x509 import x509_create_certs
import yubihsm.defs, yubihsm.exceptions, yubihsm.objects    # type: ignore [import]
from yubihsm.defs import OBJECT    # type: ignore [import]

from click import style

from hsm_secrets.yubihsm import HSMSession, MockYhsmObject

def swear_you_are_on_airgapped_computer(quiet: bool):
    if quiet:
        return
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

    `objects list` is an exception. It can be ran by anyone alone.

    HSM setup workflow:

    0. Connect all devices.
    1. Reset devices to factory defaults.
    2. Set a common wrap key to all devices.
    3. Host a admin Secret Sharing Ceremony.
    4. Add user keys (Yubikey auth) to master device.
    5. Generate keys and certs on master device with `objects create`.
    6. Check that all configure objects are present on master (`compare`).
    7. Clone master device to other ones (backup + restore).
    8. Double check that all keys are present on all devices (`compare --alldevs`).
    9. Remove default admin key from all devices.

    Management workflow:

    1. Re-add insecure default admin key with shared/backup secret on all devices.
    2. Perform necessary management operations on master device.
    3. Clone master device to other ones.
    4. Remove default admin key from all devices.
    """
    ctx.ensure_object(dict)



@cmd_hsm.group('backup')
def cmd_hsm_backup():
    """Device backup/restore commands"""
    pass

@cmd_hsm.group('admin')
def cmd_hsm_admin():
    """Admin key management commands"""
    pass

@cmd_hsm.group('objects')
def cmd_hsm_objects():
    """YubiHSM object management commands"""
    pass

# ---------------

@cmd_hsm.command('compare')
@click.option('--alldevs', is_flag=True, help="Compare all devices")
@pass_common_args
def compare_config(ctx: HsmSecretsCtx, alldevs: bool):
    """Compare config with device contents

    Lists all objects by type (auth, wrap, etc.) in the configuration file, and then checks
    that they exist in the YubiHSM(s). Shows which objects are missing and which are found.

    By default, only checks the master device, using the default admin key.
    Override with the options as needed.
    """
    return _compare_create_config(ctx, alldevs, create=False)

# ---------------

@cmd_hsm_objects.command('list')
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
                cli_result(pretty_fmt_yubihsm_object(o.get_info()))
                cli_result("")

@cmd_hsm_objects.command('delete')
@click.argument('obj_ids', nargs=-1, type=str, metavar='<id|label> ...', shell_complete=click_hsm_obj_auto_complete(None))
@click.option('--alldevs', is_flag=True, help="Delete on all devices")
@click.option('--force', is_flag=True, help="Force deletion without confirmation (use with caution)")
@pass_common_args
def delete_object(ctx: HsmSecretsCtx, obj_ids: tuple, alldevs: bool, force: bool):
    """Delete object(s) from the YubiHSM

    Deletes an object(s) with the given ID or label from the YubiHSM.
    YubiHSM2 can have the same id for different types of objects, so this command
    asks you to confirm the type of the object before deleting it.

    With `--force` ALL objects with the given ID will be deleted
    without confirmation, regardless of their type.
    """
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, serial) as ses:
            not_found = set(obj_ids)
            for id_or_label in obj_ids:
                try:
                    id_int = ctx.conf.find_def_non_typed(id_or_label).id
                except KeyError:
                    cli_warn(f"Object '{id_or_label}' not found in the configuration file. Assuming it's raw ID on the device.")
                    id_int = parse_keyid(id_or_label)
                objects = ses.list_objects()
                for o in objects:
                    if o.id == id_int:
                        not_found.remove(id_or_label)
                        if not force:
                            cli_ui_msg("Object found:")
                            cli_ui_msg(pretty_fmt_yubihsm_object(o.get_info()))
                            click.confirm("Delete this object?", default=False, abort=True, err=True)
                        o.delete()
                        cli_info("Object deleted.")
        if not_found:
            cli_error(f"Objects not found on device {serial}: {', '.join(not_found)}")

@cmd_hsm_objects.command('create-missing')
@pass_common_args
def create_missing_keys(ctx: HsmSecretsCtx):
    """Create missing keys and certs on the master YubiHSM

    Compares the configuration file with the objects in the YubiHSM and creates
    any missing keys and certificates.
    """
    _compare_create_config(ctx, alldevs=False, create=True)
    x509_create_certs(ctx, all_certs=True, dry_run=False, cert_ids=(), skip_existing=True)

# ---------------

def _compare_create_config(ctx: HsmSecretsCtx, alldevs: bool, create: bool):
    assert not (alldevs and create), "Cannot use --alldevs and --create together."

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
                items = sorted(items, key=lambda x: x.id)
                cli_result(f"{t.__name__}")
                for it in items:
                    obj: yubihsm.objects.YhsmObject|MockYhsmObject|None = None
                    for o in device_objs:
                        if o.id == it.id and (o.object_type == config_to_hsm_type[t].object_type):
                            obj = o
                            objects_accounted_for[o.id] = True
                            break
                    checkbox = "[x]" if obj else "[ ]"
                    cli_result(f" {checkbox} '{it.label}' (0x{it.id:04x})")
                    if create:
                        need_create = obj is None
                        if need_create:
                            from hsm_secrets.config import HSMAsymmetricKey, HSMSymmetricKey, HSMWrapKey, HSMOpaqueObject, HSMHmacKey, HSMAuthKey
                            warn_emoji = click.style("⚠️", fg='yellow')
                            unsupported_types = {
                                HSMWrapKey: f"{warn_emoji} Use `hsm backup make-key` to create",
                                HSMAuthKey: f"{warn_emoji} Use `hsm admin` and `user` commands to create",
                                HSMOpaqueObject: "Creating shortly..." if create else "",
                            }

                            gear_emoji = click.style("⚙️", fg='cyan')

                            if it.__class__ in unsupported_types:
                                msg = unsupported_types[it.__class__]
                                if msg:
                                    cli_result(f"  └-> {msg}")
                                n_skipped += 1

                            elif isinstance(it, HSMAsymmetricKey):
                                cli_result(f"  └-> {gear_emoji} Creating...")
                                confirm_and_delete_old_yubihsm_object_if_exists(ses, it.id, OBJECT.ASYMMETRIC_KEY)
                                cli_info(f"Generating asymmetric key, type '{it.algorithm}'...")
                                if 'rsa' in it.algorithm.lower():
                                    cli_warn("  Note! RSA key generation is very slow. Please wait. The YubiHSM2 should blinking rapidly while it works.")
                                ses.asym_key_generate(it)
                                cli_info(f"Symmetric key ID '{hex(it.id)}' ({it.label}) stored in YubiHSM device {ses.get_serial()}")
                                n_created += 1

                            elif isinstance(it, HSMSymmetricKey):
                                cli_result(f"  └-> {gear_emoji} Creating...")
                                confirm_and_delete_old_yubihsm_object_if_exists(ses, it.id, OBJECT.SYMMETRIC_KEY)
                                cli_info(f"Generating symmetric key, type '{it.algorithm}'...")
                                ses.sym_key_generate(it)
                                cli_info(f"Symmetric key ID '{hex(it.id)}' ({it.label}) generated in YubiHSM device {ses.get_serial()}")

                                n_created += 1
                            elif isinstance(it, HSMHmacKey):
                                cli_result(f"  └-> {gear_emoji} Creating...")
                                confirm_and_delete_old_yubihsm_object_if_exists(ses, it.id, OBJECT.HMAC_KEY)
                                cli_info(f"Generating HMAC key, type '{it.algorithm}'...")
                                ses.hmac_key_generate(it)
                                cli_info(f"HMAC key ID '{hex(it.id)}' ({it.label}) stored in YubiHSM device {ses.get_serial()}")
                                n_created += 1
                            else:
                                cli_result(click.style(f"  └-> Unsupported object type: {it.__class__.__name__}. This is a bug. SKIPPING.", fg='red'))
                                n_skipped += 1

            if len(objects_accounted_for) < len(device_objs):
                cli_result("EXTRA OBJECTS (on the device but not in the config)")
                for o in device_objs:
                    if o.id not in objects_accounted_for:
                        info = o.get_info()
                        cli_result(f" ??? '{str(info.label)}' (0x{o.id:04x}) <{o.object_type.name}>")

            if create:
                cli_info("")
                cli_info(f"KEY CREATION REPORT: Created {n_created} objects, skipped {n_skipped} objects.")


            # Check logging / audit settings
            cur_audit_settings, unknown_audit_commands = ses.get_audit_settings()
            if unknown_audit_commands:
                cli_result("UNKNOWN AUDIT LOG COMMANDS ON DEVICE (not necessarily a problem)")
                for k, v in unknown_audit_commands.items():
                    cli_result(f" ??? {k} = {v}")

            new_audit_setting = ctx.conf.admin.audit
            ctx.conf.admin.audit.apply_defaults()

            audit_settings_diff = _check_and_format_audit_conf_differences(cur_audit_settings, new_audit_setting, raise_if_fixed_change=False)
            if audit_settings_diff:
                cli_result("MISMATCHING AUDIT LOG SETTINGS (device -> config)")
                cli_result(audit_settings_diff)
                cli_warn("Use 'log apply-settings' to change audit settings to match the configuration.")

            cli_info("")

# ---------------

@cmd_hsm.command('attest')
@pass_common_args
@click.argument('key_id', required=True, type=str, metavar='<id|label>', shell_complete=click_hsm_obj_auto_complete(HSMAsymmetricKey))
@click.option('--out', '-o', type=click.File('w', encoding='utf8'), help='Output file (default: stdout)', default=click.get_text_stream('stdout'))
def attest_key(ctx: HsmSecretsCtx, key_id: str, out: click.File):
    """Attest an asymmetric key in the YubiHSM

    Create an a key attestation certificate, signed by the
    Yubico attestation key, for the given key ID (in hex).
    """
    from cryptography.hazmat.primitives.serialization import Encoding
    id = ctx.conf.find_def(key_id, HSMAsymmetricKey).id
    with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, ctx.hsm_serial) as ses:
        cert = ses.attest_asym_key(id)
        pem = cert.public_bytes(Encoding.PEM).decode('UTF-8')
        out.write(pem)  # type: ignore
        cli_info(f"Key 0x{id:04x} attestation certificate written to '{out.name}'")

# ---------------

@cmd_hsm_admin.command('default-enable')
@pass_common_args
@click.option('--use-backup-secret', is_flag=True, help="Use backup secret instead of shared secret")
@click.option('--alldevs', is_flag=True, help="Add on all devices")
def default_admin_enable(ctx: HsmSecretsCtx, use_backup_secret: bool, alldevs: bool):
    """Re-add insecure default admin key to HSM

    Using either a shared secret or a backup secret, (re-)create the default admin key on the YubiHSM(s).
    This is a temporary key that should be removed after the management operations are complete.
    """
    swear_you_are_on_airgapped_computer(ctx.quiet)

    def do_it(conf: HSMConfig, ses: HSMSession):
        obj = ses.auth_key_put_derived(conf.admin.default_admin_key, conf.admin.default_admin_password)
        cli_ui_msg(f"OK. Default insecure admin key (0x{obj.id:04x}: '{conf.admin.default_admin_password}') added successfully.")
        cli_ui_msg("!!! DON'T FORGET TO REMOVE IT after you're done with the management operations.")

    # This command exceptionally uses shared or backup secret to authenticate, unless explicitly forced
    password = None
    if not ctx.forced_auth_method:
        # Obtain the shared (or backup) password
        try:
            if use_backup_secret:
                cli_ui_msg("Using backup secret to authenticate (instead of shared secret).")
                is_hex = click.prompt("Is the backup secret hex-encoded (instead of a direct password) [Y/n]?", type=bool, err=True, default=True)

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
            if password and not ctx.mock_file:
                shared_key_id = ctx.conf.admin.shared_admin_key.id
                with open_hsm_session_with_password(ctx, shared_key_id, password, device_serial=serial) as ses:
                    do_it(ctx.conf, ses)
            else:
                with open_hsm_session(ctx, device_serial=serial) as ses:
                    do_it(ctx.conf, ses)
        except yubihsm.exceptions.YubiHsmAuthenticationError as e:
            raise click.ClickException("Failed to authenticate with the provided password.")


@cmd_hsm_admin.command('default-disable')
@pass_common_args
@click.option('--alldevs', is_flag=True, help="Remove on all devices")
@click.option('--force', is_flag=True, help="Force removal even if no other admin key exists")
def default_admin_disable(ctx: HsmSecretsCtx, alldevs: bool, force: bool):
    """Remove insecure default admin key from the YubiHSM(s)

    Last step in the management workflow. Remove the default admin key from the YubiHSM(s).
    The command first checks that a shared admin key exists on the device(s) before removing the default one.
    """
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, serial) as ses:
            keydef = ctx.conf.admin.default_admin_key

            if ses.object_exists(keydef):
                # Check that shared admin key exists before removing the default one
                if not force:
                    if not ses.object_exists(ctx.conf.admin.shared_admin_key):
                        raise click.ClickException(f"Shared admin key not found on device {serial}. You could lose access to the device, so refusing the operation (use --force to override).")
                # Ok, it does, we can proceed
                ses.delete_object(keydef)
                cli_info(f"Ok. Default admin key removed on device {serial}.")
            else:
                cli_warn(f"Default admin key not found on device {serial}. Skipping.")

            # Make sure it's really gone
            try:
                if ses.object_exists(keydef):
                    cli_error(f"ERROR!!! Default admin key still exists on device {serial}. Don't leave the airgapped session before removing it.")
                    click.pause("Press ENTER to continue.", err=True)
                    raise click.Abort()
            except Exception as e:
                cli_error("ERROR!! Unexpected error while checking that the key is removed. PLEASE VERIFY MANUALLY THAT IT'S GONE!")
                click.pause("Press ENTER to continue.", err=True)
                raise e


@cmd_hsm_admin.command('sharing-ceremony')
@click.option('--num-shares', '-n', type=int, required=True, help="Number of shares to generate")
@click.option('--threshold', '-t', type=int, required=True, help="Number of shares required to reconstruct the key")
@click.option('--with-backup', '-b', is_flag=True, default=False, help="Generate a backup key in addition to the shared key")
@click.option('--skip-ceremony', is_flag=True, default=False, help="Skip ceremony, store secret directly")
@pass_common_args
def make_shared_admin_key(ctx: HsmSecretsCtx, num_shares: int, threshold: int, with_backup: bool, skip_ceremony: bool):
    """Host an admin key Secret Sharing Ceremony

    The ceremony is a formal multi-step process where the system generates a new shared admin key
    and splits it into multiple shares. The shares are then distributed to the custodians.
    The key can be reconstructed when at least `threshold` number of shares are combined,
    regardless of `num_shares` generated.

    This is a very heavy process, and should be only done once, on the master YubiHSM.
    The resulting key can then be cloned to other devices via key wrapping operations.

    A backup key can be generated in addition to the shared key. It's a non-shared
    key that will be written down in parts by all custodians. You will be asked to
    seal it in an envelope and hand over for secure storage by some "uber custodian".

    If `--skip-ceremony` is given, the secret generation and sharing ceremony are skipped and
    you are asked to enter the password to store on HSM directly.
    """
    swear_you_are_on_airgapped_computer(ctx.quiet)

    def apply_password_fn(new_password: bytes):
        assert isinstance(new_password, bytes)
        pw_str = new_password.decode('ASCII')
        assert pw_str.encode('ASCII') == new_password

        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
            confirm_and_delete_old_yubihsm_object_if_exists(ses, ctx.conf.admin.shared_admin_key.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
            info = ses.auth_key_put_derived(ctx.conf.admin.shared_admin_key, pw_str)
            cli_info(f"Auth key ID '{hex(info.id)}' ({info.label}) stored in YubiHSM device {ses.get_serial()}")

    if skip_ceremony:
        pw = prompt_for_secret("Enter the (new) shared admin password to store", confirm=True)
        apply_password_fn(pw.encode('ASCII'))
    else:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
            secret = ses.get_pseudo_random(256//8)
        cli_splitting_ceremony(threshold, num_shares, apply_password_fn, with_backup_key=with_backup, rnd=secret)

    cli_info("OK. Shared admin key added successfully.")

# ---------------

@cmd_hsm_backup.command('make-key')
@pass_common_args
def make_wrap_key(ctx: HsmSecretsCtx):
    """Add backup wrap key to all YubiHSMs

    Generate a new wrap key and set it to all configured YubiHSMs.
    It is used to export/import objects securely between the devices.
    This requires all the devices in config file to be connected and reachable.

    Note that the key is NOT printed out, only stored in the devices.
    """
    hsm_serials = ctx.conf.general.all_devices.keys()
    assert len(hsm_serials) > 0, "No devices found in the configuration file."

    swear_you_are_on_airgapped_computer(ctx.quiet)

    with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
        cli_info("Generating secret on master device...")
        secret = ses.get_pseudo_random(256//8)

    cli_info("Secret generated. Distributing it to all devices...")
    cli_info("")

    for serial in hsm_serials:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, device_serial=serial) as ses:
            confirm_and_delete_old_yubihsm_object_if_exists(ses, ctx.conf.admin.wrap_key.id, yubihsm.defs.OBJECT.WRAP_KEY)
            res = ses.put_wrap_key(ctx.conf.admin.wrap_key, secret)
            cli_info(f"Wrap key ID '{hex(res.id)}' stored in YubiHSM device {ses.get_serial()}")


    del secret
    cli_info(f"OK. Common wrap key added to all devices (serials: {', '.join(hsm_serials)}).")


@cmd_hsm_backup.command('export')
@pass_common_args
@click.option('--out', '-o', type=click.Path(exists=False, allow_dash=False), required=False, help='Output file', default=None)
def backup_export(ctx: HsmSecretsCtx, out: click.File|None):
    """Export backup .tar.gz of HSM

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
        device_objs = list(ses.list_objects())
        for obj in device_objs:
            # Try to export the object
            try:
                key_bytes = ses.export_wrapped(ctx.conf.admin.wrap_key, obj.id, obj.object_type)
            except yubihsm.exceptions.YubiHsmDeviceError as e:
                skipped += 1
                if e.code == yubihsm.defs.ERROR.INSUFFICIENT_PERMISSIONS:
                    cli_error(f"- Warning: Skipping 0x{obj.id:04x}: Insufficient permissions to export object.")
                    continue
                else:
                    cli_error(f"- Error: Failed to export object 0x{obj.id:04x}: {e}")
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
        cli_error(f"Skipped {skipped} objects due to errors or insufficient permissions.")


@cmd_hsm_backup.command('import')
@pass_common_args
@click.argument('backup_file', type=click.Path(exists=True, allow_dash=False, dir_okay=False), required=True, metavar='<backup_file>')
@click.option('--force', is_flag=True, help="Don't ask for confirmation before restoring")
def backup_import(ctx: HsmSecretsCtx, backup_file: str, force: bool):
    """Restore backup .tar.gz to HSM

    Imports all objects from a .tar.gz backup file to the YubiHSM.
    The backup file must have been created with the `hsm backup` command, file names
    must be in the format `object_type--id--label.bin`.

    The same wrap key must be present in the YubiHSM to restore the objects as they were exported with.
    """
    cli_info("")
    if not force:
        click.confirm(f"WARNING: This will overwrite existing objects in the YubiHSM device {ctx.hsm_serial}. Continue?", abort=True, err=True)
        if ctx.hsm_serial == ctx.conf.general.master_device:
            click.confirm("This is the configured master device. Are you ABSOLUTELY sure you want to continue?", abort=True, err=True)

    with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
        wrap_key_def = ctx.conf.admin.wrap_key
        with open(backup_file, 'rb') as fh:
            tar = tarfile.open(fileobj=fh, mode='r:gz')
            for tarinfo in tar:
                name = tarinfo.name
                assert name.endswith('.bin'), f"Unexpected file extension in tar archive: '{name}'"
                assert name.count('--') == 2, f"Unexpected file name format in tar archive: '{name}'"
                obj_id = parse_keyid(name.split('--')[1])
                obj_type = name.split('--')[0]

                cli_info(f"- Importing object from '{tarinfo.name}'...")

                obj_enum = yubihsm.defs.OBJECT.__members__.get(obj_type)
                if obj_enum is None:
                    cli_info(click.style(f"   └-> Skipping unknown object type '{obj_type}' in backup. File: '{name}'", fg='yellow'))
                    continue

                if obj_enum == yubihsm.defs.OBJECT.WRAP_KEY and obj_id == wrap_key_def.id:
                    cli_info(click.style(f"   └-> Skipping wrap key 0x{obj_id:04x} that we are currently using for restoring.", fg='yellow'))
                    continue

                if ses.object_exists_raw(obj_id, obj_enum):
                    if force or click.confirm(f"   └-> Object 0x{obj_id:04x} ({obj_type}) already exists. Overwrite?", default=False, err=True):
                        cli_info(f"      └-> Deleting existing {obj_type} 0x{obj_id:04x}'")
                        ses.delete_object_raw(obj_id, obj_enum)
                    else:
                        cli_info(click.style(f"      └-> Skipping existing {obj_type} 0x{obj_id:04x}'", fg='yellow'))
                        continue

                tarfh = tar.extractfile(tarinfo)
                assert tarfh is not None, f"Failed to extract file '{tarinfo.name}' from tar archive."
                key_bytes = tarfh.read()
                info = ses.import_wrapped(wrap_key_def, key_bytes)
                cli_info(f"   └-> Restored: 0x{info.id:04x}: ({info.object_type.name}): {str(info.label)}")
                cli_info("")

    cli_info("")
    cli_info("Restore complete.")
