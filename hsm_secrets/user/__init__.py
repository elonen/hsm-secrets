import base64
import re
import secrets
import click
from hsm_secrets.config import HSMConfig
from hsm_secrets.utils import confirm_and_delete_old_yubihsm_object_if_exists, group_by_4, hsm_obj_exists, hsm_put_derived_auth_key, hsm_put_symmetric_auth_key, open_hsm_session_with_default_admin, open_hsm_session_with_yubikey, prompt_for_secret, pw_check_fromhex, secure_display_secret

import yubikit.hsmauth
import ykman.scripting
import yubihsm.defs, yubihsm.objects


@click.group()
@click.pass_context
def cmd_user(ctx):
    """HSM user management commands"""
    ctx.ensure_object(dict)

# ---------------

@cmd_user.command('change-yubikey-mgt')
@click.pass_context
def change_yubikey_mgt(ctx: click.Context):
    """Change hsmauth mgt key on a Yubikey

    Set a new Management Key (aka. Admin Access Code) for currently connected
    Yubikey's hsmauth slot.

    This can also be done with the `yubihsm-auth -a change-mgmkey -k <oldkey>` command.
    It's included here for convenience.
    """
    yubikey = ykman.scripting.single()    # Connect to the first Yubikey found, prompt user to insert one if not found
    auth_ses = yubikit.hsmauth.HsmAuthSession(connection=yubikey.smart_card())
    _, old_mgt_key_bin = _ask_yubikey_hsm_mgt_key("Enter the old Management Key", default=True)
    _change_yubikey_hsm_mgt_key(auth_ses, old_mgt_key_bin, ask_before_change=False)

# ---------------

@cmd_user.command('add-user-yubikey')
@click.pass_context
@click.option('--label', required=True, help="Label of the Yubikey hsmauth slot / HSM key label")
@click.option('--alldevs', is_flag=True, help="Add to all devices")
def add_user_yubikey(ctx: click.Context, label: str, alldevs: bool):
    """Register Yubikey auth for a user

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

    mgt_key, mgt_key_bin = _ask_yubikey_hsm_mgt_key("Enter the Management Key", default=True)
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
    key_enc, key_mac = None, None
    with open_hsm_session_with_yubikey(ctx) as (conf, ses):
        key_enc = ses.get_pseudo_random(128//8)
        key_mac = ses.get_pseudo_random(128//8)

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
        _change_yubikey_hsm_mgt_key(yk_auth_ses, mgt_key_bin, ask_before_change=True)


# ---------------

# ---------------

@cmd_user.command('add-service-account')
@click.pass_context
@click.argument('cert_ids', nargs=-1, type=str, metavar='<id>...')
@click.option('--all', '-a', 'all_accts', is_flag=True, help="Add all configured service users")
@click.option('--askpw', is_flag=True, help="Ask for password(s) instead of generating")
def add_service_account(ctx: click.Context, cert_ids: tuple[str], all_accts: bool, askpw: bool):
    """Add a service user(s) to master device

    Cert IDs are 16-bit hex values (e.g. '0x12af' or '12af').
    You can specify multiple IDs to add multiple service users,
    or use the --all flag to add all service users defined in the config.

    The command will generate (and show) passwords by default. Use the --askpw
    to be prompted for passwords instead.
    """
    conf: HSMConfig = ctx.obj['config']
    dev_serial = ctx.obj['devserial']

    if not all_accts and not cert_ids:
        raise click.ClickException("No service users specified for addition.")

    id_strings = [str(x.id) for x in conf.service_keys] if all_accts else cert_ids
    ids = [int(id.replace("0x", ""), 16) for id in id_strings]
    if not ids:
        raise click.ClickException("No service account ids specified.")

    acct_defs = [x for x in conf.service_keys if x.id in ids]
    if len(acct_defs) != len(ids):
        unknown_ids = [f'0x{i:04x}' for i in (set(ids) - set([x.id for x in acct_defs]))]
        raise click.ClickException(f"Service user ID(s) {', '.join(unknown_ids)} not found in the configuration file.")

    for ad in acct_defs:
        with open_hsm_session_with_default_admin(ctx) as (conf, ses):

            obj = ses.get_object(ad.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
            assert isinstance(obj, yubihsm.objects.AuthenticationKey)
            if not confirm_and_delete_old_yubihsm_object_if_exists(dev_serial, obj, abort=False):
                click.echo(f"Skipping service user '{ad.label}' (ID: 0x{ad.id:04x})...")
                continue

            click.echo(f"Adding service user '{ad.label}' (ID: 0x{ad.id:04x}) to device {dev_serial}...")
            if askpw:
                pw = prompt_for_secret(f"Enter password for service user '{ad.label}'", confirm=True)
            else:
                rnd = ses.get_pseudo_random(16)
                pw = group_by_4(rnd.hex()).replace(' ', '-')
                while True:
                    click.pause("Press ENTER to reveal the generated password.")
                    secure_display_secret(pw)
                    confirm = click.prompt("Enter the password again to confirm", hide_input=True)
                    if confirm != pw:
                        click.echo("Passwords do not match. Try again.")
                        continue
                    else:
                        break
            hsm_put_derived_auth_key(ses, dev_serial, conf, ad, pw)


# ---------------

def _ask_yubikey_hsm_mgt_key(prompt: str, confirm = False, default = False) -> tuple[str, bytes]:
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


def _change_yubikey_hsm_mgt_key(auth_ses: yubikit.hsmauth.HsmAuthSession, old_key_bin=None, ask_before_change=True):
    """Change the Yubikey hsmauth Management Key (aka. Admin Access Code)"""

    click.echo("A 'Management Key' is required to edit the Yubikey hsmauth slots.")
    click.echo("It must be a 32 hex characters long, e.g. '0011 2233 4455 6677 8899 aabb ccdd eeff'")
    click.echo("This unwieldy key is used rarely. You should probably store it in a password manager.")
    click.echo("")

    if old_key_bin is None:
        _, old_key_bin = _ask_yubikey_hsm_mgt_key("Enter the OLD Management Key", default=True)

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
            new_mgt_key, new_mgt_key_bin = _ask_yubikey_hsm_mgt_key("Enter the new Management Key", confirm=True)

        auth_ses.put_management_key(old_key_bin, new_mgt_key_bin)
        click.echo("Management Key changed.")
