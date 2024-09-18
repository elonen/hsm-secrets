import re
import secrets
import click
from hsm_secrets.config import HSMAuthKey, HSMConfig, click_hsm_obj_auto_complete
from hsm_secrets.utils import HSMAuthMethod, HsmSecretsCtx, cli_confirm, cli_info, cli_pause, cli_prompt, cli_ui_msg, cli_warn, confirm_and_delete_old_yubihsm_object_if_exists, group_by_4, open_hsm_session, pass_common_args, prompt_for_secret, pw_check_fromhex, scan_local_yubikeys, secure_display_secret

import yubikit.hsmauth
import ykman.scripting
import ykman.device
import yubihsm.defs, yubihsm.objects    # type: ignore [import]


@click.group()
@click.pass_context
def cmd_user(ctx: click.Context):
    """HSM user management commands"""
    ctx.ensure_object(dict)

# ---------------

@cmd_user.command('set-yubikey-mgt')
@pass_common_args
def change_yubikey_mgt(ctx: HsmSecretsCtx):
    """Set/change hsmauth mgt key on a Yubikey

    Set a new Management Key (aka. Admin Access Code) for currently connected
    Yubikey's hsmauth slot.

    This can also be done with the `yubihsm-auth -a change-mgmkey -k <oldkey>` command.
    It's included here for convenience.
    """
    yubikey, _ = scan_local_yubikeys(require_one_hsmauth=True)
    assert yubikey
    auth_ses = yubikit.hsmauth.HsmAuthSession(connection=yubikey.smart_card())
    _, old_mgt_key_bin = _ask_yubikey_hsm_mgt_key("Enter the old Management Key", default=True)
    _change_yubikey_hsm_mgt_key(auth_ses, old_mgt_key_bin, ask_before_change=False)

# ---------------

@cmd_user.command('add-yubikey')
@pass_common_args
@click.argument('label', type=str, metavar='<label>', shell_complete=click_hsm_obj_auto_complete(HSMAuthKey, 'user_keys', ids=False))
@click.option('--alldevs', is_flag=True, help="Add to all devices")
def add_user_yubikey(ctx: HsmSecretsCtx, label: str, alldevs: bool):
    """Register Yubikey auth for a user

    <label> is the label of the Yubikey hsmauth slot / HSM key label,
    which will be used on both devices. It must be declared in the config file.

    Generate a new password-protected public auth key, and store it in the
    YubiHSM(s) as a user key. The same label will be used on both the Yubikey and the YubiHSM.
    """
    user_key_configs = [uk for uk in ctx.conf.user_keys if uk.label == label]
    if not user_key_configs:
        raise click.ClickException(f"User key with label '{label}' not found in the configuration file.")
    elif len(user_key_configs) > 1:
        raise click.ClickException(f"Multiple user keys with label '{label}' found in the configuration file.")

    user_key_conf = user_key_configs[0]


    n_yubikeys = len(ykman.device.list_all_devices())
    if n_yubikeys > 1:
        raise click.ClickException(f"Found {n_yubikeys} Yubikeys. Can't decide which one to set HSM auth on.")
    yubikey = ykman.scripting.single(prompt = True)    # Connect to the first Yubikey found, prompt user to insert one if not found
    yk_auth_ses = yubikit.hsmauth.HsmAuthSession(connection=yubikey.smart_card())
    existing_slots = list(yk_auth_ses.list_credentials())

    old_slot = None
    for slot in existing_slots:
        if slot.label == label:
            old_slot = slot
            cli_ui_msg(f"Yubikey hsmauth slot with label '{label}' already exists.")
            cli_confirm("Overwrite the existing slot?", default=False, abort=True)    # Abort if user doesn't want to overwrite

    cli_ui_msg("Changing Yubikey hsmauth slots requires the Management Key (aka. Admin Access Code)")
    cli_ui_msg("(Note: this tool removes spaces, so you can enter the mgt key with or without grouping.)")

    mgt_key, mgt_key_bin = _ask_yubikey_hsm_mgt_key("Enter the Management Key", default=True)
    if old_slot:
        yk_auth_ses.delete_credential(mgt_key_bin, old_slot.label)
        cli_info(f"Old key in slot '{old_slot.label}' deleted.")

    cli_ui_msg("")
    cli_ui_msg("Yubikey hsmauth slots are protected by a password.")
    cli_ui_msg("It doesn't have to be very strong, as it's only used as a second factor for the Yubikey.")
    cli_ui_msg("It should be something you can remember, but also stored in a password manager.")
    cli_ui_msg("")
    cred_password = prompt_for_secret("Enter (ascii-only) password or PIN for the slot", confirm=True, enc_test='ascii')

    ykver = str(yubikey.info.version)
    if ykver >= "5.6.0":
        cli_info(f"NOTE: This Yubikey's version {ykver} would support asymmetric keys. Maybe ADD SUPPORT for this command?")
    else:
        cli_info(f"NOTE: This Yubikey's version is {ykver} (< 5.6.0). (Only symmetric keys supported.)")

    cli_info("Generating symmetric key for the slot...")
    key_enc, key_mac = None, None
    with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
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

    cli_info(f"Auth key added to the Yubikey (serial {yubikey.info.serial}) hsmauth slot '{cred.label}' (type: {repr(cred.algorithm)})")

    # Store it in the YubiHSMs
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, serial) as ses:
            confirm_and_delete_old_yubihsm_object_if_exists(ses, user_key_conf.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
            info = ses.auth_key_put(user_key_conf, key_enc=key_enc, key_mac=key_mac)
            cli_info(f"Auth key ID '{hex(info.id)}' ({str(info.label)}) stored in YubiHSM device {ses.get_serial()}")


    cli_info("OK. User key added" + (f" to all devices (serials: {', '.join(hsm_serials)})" if alldevs else "") + ".")
    cli_info("")
    cli_info("TIP! Test with the `list-objects` command to check that Yubikey hsmauth method works correctly.")

    # Also offer to change Yubikey hsmauth Management Key if it's the default one
    if mgt_key == "00000000000000000000000000000000":
        cli_ui_msg("")
        cli_ui_msg("WARNING! You are using factory default for Yubikey hsmauth Management Key.")
        cli_ui_msg("")
        _change_yubikey_hsm_mgt_key(yk_auth_ses, mgt_key_bin, ask_before_change=True)

# ---------------

@cmd_user.command('add-service')
@pass_common_args
@click.argument('obj_ids', nargs=-1, type=str, metavar='<id|label>...', shell_complete=click_hsm_obj_auto_complete(HSMAuthKey, 'service_keys'))
@click.option('--all', '-a', 'all_accts', is_flag=True, help="Add all configured service users")
@click.option('--askpw', is_flag=True, help="Ask for password(s) instead of generating")
def add_service(ctx: HsmSecretsCtx, obj_ids: tuple[str], all_accts: bool, askpw: bool):
    """Add service user(s) to master device

    Cert IDs are 16-bit hex values (e.g. '0x12af' or '12af').
    You can specify multiple IDs to add multiple service users,
    or use the --all flag to add all service users defined in the config.

    The command will generate (and show) passwords by default. Use the --askpw
    to be prompted for passwords instead.
    """
    if not all_accts and not obj_ids:
        raise click.ClickException("No service users specified for addition.")

    id_strings = [f'0x{x.id:04x}' for x in ctx.conf.service_keys] if all_accts else obj_ids
    ids = [ctx.conf.find_def(id, HSMAuthKey).id for id in id_strings]
    if not ids:
        raise click.ClickException("No service account ids specified.")

    acct_defs = [x for x in ctx.conf.service_keys if x.id in ids]
    if len(acct_defs) != len(ids):
        unknown_ids = [f'0x{i:04x}' for i in (set(ids) - set([x.id for x in acct_defs]))]
        raise click.ClickException(f"Service user ID(s) {', '.join(unknown_ids)} not found in the configuration file.")

    for ad in acct_defs:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
            if not confirm_and_delete_old_yubihsm_object_if_exists(ses, ad.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY, abort=False):
                cli_warn(f"Skipping service user '{ad.label}' (ID: 0x{ad.id:04x})...")
                continue

        cli_info(f"Adding service user '{ad.label}' (ID: 0x{ad.id:04x}) to device {ctx.hsm_serial}...")
        if askpw:
            pw = prompt_for_secret(f"Enter password for service user '{ad.label}'", confirm=True)
        else:
            rnd = secrets.token_bytes(16)
            pw = group_by_4(rnd.hex()).replace(' ', '-')
            retries = 0
            while True:
                retries += 1
                if retries > 5:
                    raise click.Abort("Too many retries. Aborting.")
                cli_pause("Press ENTER to reveal the generated password.")
                secure_display_secret(pw)
                confirm = cli_prompt("Enter the password again to confirm", hide_input=True)
                if confirm != pw:
                    cli_ui_msg("Passwords do not match. Try again.")
                    continue
                else:
                    break

        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
            #hsm_put_derived_auth_key(ses, ctx.hsm_serial, ctx.conf, ad, pw)
            confirm_and_delete_old_yubihsm_object_if_exists(ses, ad.id, yubihsm.defs.OBJECT.AUTHENTICATION_KEY)
            info = ses.auth_key_put_derived(ad, pw)
            cli_info(f"Auth key ID '{hex(info.id)}' ({str(info.label)}) stored in YubiHSM device {ses.get_serial()}")


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

    cli_ui_msg("A 'Management Key' is required to edit the Yubikey hsmauth slots.")
    cli_ui_msg("It must be a 32 hex characters long, e.g. '0011 2233 4455 6677 8899 aabb ccdd eeff'")
    cli_ui_msg("This unwieldy key is used rarely. You should probably store it in a password manager.")
    cli_ui_msg("")

    if old_key_bin is None:
        _, old_key_bin = _ask_yubikey_hsm_mgt_key("Enter the OLD Management Key", default=True)

    if not ask_before_change or cli_confirm("Change Management Key now?", default=False, abort=False):
        new_mgt_key = None
        if cli_prompt("Generate the key ('n' = enter manually)?", type=bool, default="y"):
            new_mgt_key_bin = secrets.token_bytes(16)
            new_mgt_key = new_mgt_key_bin.hex().lower()
            assert len(new_mgt_key) == 32

            cli_ui_msg("Key generated. It will be now shown on screen. Everyone else should look away.")
            cli_ui_msg("When you have stored the key, press ENTER again to continue.")
            cli_ui_msg("")
            cli_ui_msg("Press ENTER to reveal the key.")
            secure_display_secret(group_by_4(new_mgt_key))
        else:
            new_mgt_key, new_mgt_key_bin = _ask_yubikey_hsm_mgt_key("Enter the new Management Key", confirm=True)

        auth_ses.put_management_key(old_key_bin, new_mgt_key_bin)
        cli_info("Management Key changed.")
