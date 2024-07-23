from datetime import datetime
from textwrap import dedent
import click
import yubihsm.defs  # type: ignore [import]
from yubihsm.objects import HmacKey  # type: ignore [import]
import pyescrypt  # type: ignore [import]
from mnemonic import Mnemonic

from hsm_secrets.config import HSMConfig, PasswordDerivationRule, PwRotationToken, find_config_items_of_class
from hsm_secrets.utils import click_echo_colored_commands, group_by_4, hsm_obj_exists, open_hsm_session_with_yubikey, secure_display_secret


@click.group()
@click.pass_context
def cmd_pass(ctx):
    """Password derivation"""
    ctx.ensure_object(dict)


@cmd_pass.command('get')
@click.pass_context
@click.argument('name', required=True, type=str, metavar='<name>')
@click.option('--prev', '-p', required=False, type=int, help="Previous password index (default: 0)", default=0)
@click.option('--rule', '-r', required=False, type=str, help="Derivation rule to use (default: read from config)", default=None)
def get_password(ctx: click.Context, name: str, prev: int, rule: str|None):
    """Get password for given name

    Shows current password by default, or previous password if --prev is specified. For example,
    if the password has been rotated twice, `--prev 1` will show the previous password,
    and `--prev 2` the one before that.

    Password format depends on the configured "derivation rule". See config file for details.

    Derivation algorithm:
    HMAC(name.encode('utf8') + nonce_bytes, key) -> use first N bits -> encode as bip39 or hex as configured

    Before the first rotation, nonce is an empty string.
    """
    conf: HSMConfig = ctx.obj['config']
    rule_id = rule or str(conf.password_derivation.default_rule)

    if prev < 0:
        raise click.ClickException(f"Invalid previous password index: {prev}")

    rule_def, key_id = _find_rule_and_key(conf, rule_id)

    with open_hsm_session_with_yubikey(ctx) as (conf, ses):
        obj = ses.get_object(key_id, yubihsm.defs.OBJECT.HMAC_KEY)
        assert isinstance(obj, HmacKey)
        if not hsm_obj_exists(obj):
            raise click.ClickException(f"HMAC key 0x'{key_id:04x}' not found in HSM.")

        name_hmac = int.from_bytes(obj.sign_hmac(name.encode('utf8')), 'big')
        rotations = [r for r in rule_def.rotation_tokens if r.name_hmac in (None, name_hmac)]
        rotations.sort(key=lambda r: r.ts, reverse=True)
        if prev > len(rotations):
            raise click.ClickException(f"Password has not been rotated {prev} times yet.")

        nonce = rotations[prev-1].nonce if rotations else 0
        derived_secret = _derive_secret(obj, name, nonce)[:rule_def.bits//8]
        password = _(derived_secret, rule_def)

        secure_display_secret(password)

        click_echo_colored_commands(dedent(f"""
            Password for '`{name}`':
            - Previous password index: `{prev}`{' (current)' if prev == 0 else ''}
            - Derivation rule: '`{rule_id}`'
            - Rotated `{len(rotations)}` times
            - Name HMAC for rotation: `0x{name_hmac:x}`
        """).strip())

        # Show a hashed version
        yescryp_hasher = pyescrypt.Yescrypt(mode=pyescrypt.Mode.MCF)
        hashed = yescryp_hasher.digest(password=password.encode('utf8'), salt=ses.get_pseudo_random(32))
        yescryp_hasher.compare(password.encode('utf-8'), hashed)
        days_since_epoch = (datetime.now() - datetime(1970, 1, 1)).days
        shadow_line = f"root:{hashed.decode()}:{days_since_epoch}:0:99999:7:::"
        click.echo("- '/etc/shadow' line (yescrypt hash): " + click.style(shadow_line, fg='green'))


@cmd_pass.command('rotate')
@click.pass_context
@click.argument('name', required=False, nargs=-1, type=str, metavar='[name] ...', default=None)
@click.option('--rule', '-r', required=False, type=str, help="Derivation rule to use (default: read from config)", default=None)
@click.option('--all', '-a', required=False, is_flag=True, help="Rotate all passwords")
def rotate_password(ctx: click.Context, name: list[str]|None, rule: str|None, all: bool):
    """Rotate password(s) for given name(s)

    Rotates the password for the given name(s) or all names if --all is specified.
    """
    conf: HSMConfig = ctx.obj['config']
    rule_id = rule or str(conf.password_derivation.default_rule)

    if all and name:
        raise click.ClickException("Cannot specify both --all and specific names.")
    if not all and not name:
        raise click.ClickException("Must specify either --all or at least one name.")

    _, key_id = _find_rule_and_key(conf, rule_id)

    with open_hsm_session_with_yubikey(ctx) as (conf, ses):
        obj = ses.get_object(key_id, yubihsm.defs.OBJECT.HMAC_KEY)
        assert isinstance(obj, HmacKey)
        if not hsm_obj_exists(obj):
            raise click.ClickException(f"HMAC key 0x'{key_id:04x}' not found in HSM.")

        nonce = int.from_bytes(ses.get_pseudo_random(8), 'big')

        def rotate(name: str|None):
            name_hmac = int.from_bytes(obj.sign_hmac(name.encode('utf8')), 'big') if name else None
            rotation = PwRotationToken(name_hmac=name_hmac, nonce=nonce, ts=int(datetime.now().timestamp()))
            name_hmac_str = f"name_hmac: 0x{name_hmac:x}, " if name_hmac else ""
            rotation_str = f"          - {{{name_hmac_str}nonce: 0x{rotation.nonce:x}, ts: {rotation.ts}}}"
            click.echo(click.style(rotation_str, fg='green'))

        names_str = ', '.join(name) if name else '<ALL>'
        click_echo_colored_commands(f"To rotate password(s) for `{names_str}`, add the following line(s) to the `{rule_id}`'s rotation config:")
        click.echo("")
        rotate(None) if all else [rotate(n) for n in name or []]
        click.echo("")


# --- Helpers ---


def _find_rule_and_key(conf: HSMConfig, rule_id: str) -> tuple[PasswordDerivationRule, int]:
    rules: list[PasswordDerivationRule] = find_config_items_of_class(conf, PasswordDerivationRule)
    matches = [r for r in rules if r.id == rule_id]
    if not matches:
        raise click.ClickException(f"Derivation rule '{rule_id}' not found in config file.")
    rule_def = matches[0]
    key_id = next((k.id for k in conf.password_derivation.keys if k.id == rule_def.key), None)
    if not key_id:
        raise click.ClickException(f"Key '{rule_def.key}' not found in config file.")
    return rule_def, key_id


def _derive_secret(obj: HmacKey, name: str, nonce: int) -> bytes:
    name_bytes = name.encode('utf8')
    nonce_bytes = nonce.to_bytes((nonce.bit_length() + 7) // 8, 'big') if nonce else b''
    return obj.sign_hmac(name_bytes + nonce_bytes)


def _(derived_secret: bytes, rule_def: PasswordDerivationRule) -> str:
    if rule_def.format == "bip39":
        mnemo = Mnemonic("english")
        secret_padded = derived_secret + b'\x00' * max(128//8 - len(derived_secret), 0)
        bip39 = mnemo.to_mnemonic(secret_padded[:128//8])
        bip39_words = [w.lower().strip() for w in bip39.split(' ')]
        assert len(bip39_words) == 12, f"Expected 12 BIP39 words, got {len(bip39_words)}"
        if rule_def.bits == 64:
            bip39_words = bip39_words[:6]
        else:
            assert rule_def.bits == 128, f"Unsupported bits: {rule_def.bits}"
        return rule_def.separator.join(bip39_words)
    elif rule_def.format == "hex":
        return group_by_4(derived_secret.hex().lower()).replace(' ', rule_def.separator)
    else:
        raise click.ClickException(f"Unsupported password format: {rule_def.format}")
