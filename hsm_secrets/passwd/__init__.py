import click
import yubihsm.defs
from yubihsm.objects import HmacKey
from mnemonic import Mnemonic
import pyescrypt
import secrets

from hsm_secrets.utils import open_hsm_session_with_yubikey

@click.group()
@click.pass_context
def cmd_pass(ctx):
    """Password derivation"""
    ctx.ensure_object(dict)


def generate_password(conf, ses, hostname, salt, salt_file) -> str:
        # Prepare salt
        salt_bytes = b''
        if salt:
            salt_bytes = salt.encode('utf8').strip()
        elif salt_file:
            with open(salt_file, 'rb') as f:
                salts = f.readlines()
            for line in salts:
                h, s = line.split(maxsplit=1)
                if h.lower() == hostname.lower():
                    if salt_bytes:
                        raise click.ClickException(f"Duplicate salt for hostname '{hostname}' in salt file.")
                    salt_bytes = s.strip()

        # Get the HMAC key handle from the HSM
        assert len(conf.password_derivation.keys) == 1, "Exactly one password derivation key must be defined in the config file."
        key_conf = conf.password_derivation.keys[0]
        obj = ses.get_object(key_conf.id, yubihsm.defs.OBJECT.HMAC_KEY)
        assert isinstance(obj, HmacKey)

        # Derive key by HMAC
        hostname_bytes = hostname.strip().encode('utf8')
        hash_bytes = obj.sign_hmac(hostname_bytes + salt_bytes)

        first_128_bits = hash_bytes[:16]

        # Convert into BIP39 mnemonic
        mnemo = Mnemonic("english")
        return mnemo.to_mnemonic(first_128_bits)



@cmd_pass.command('get')
@click.pass_context
@click.option('--hostname', required=True, help="Hostname to derive password for")
@click.option('--salt-file', required=False, type=click.Path(), help="File containing salts per hostname")
@click.option('--salt', required=False, type=str, help="Salt to use for password derivation")
def show(ctx: click.Context, hostname: str, salt_file: str, salt: str):
    """Derive a password for a given (arbitrary) hostname.

    Uses empty salt by default, or a provided salt.
    If a salt file is provided, the salt is looked up by hostname.
    File format: one line per host, <hostname> <salt>. Hostnames are case-insensitive.

    Derivation algorithm:
    1) Hostname is lowercase UTF8,
    2) Salt is UTF8 stripped of leading/trailing whitespaces,
    3) Key = HMAC key on the HSM,
    4) Result = HMAC-SHA256(hostname + salt, key) -> get first 128 bits -> english BIP39 mnemonic
    """
    with open_hsm_session_with_yubikey(ctx) as (conf, ses):
        password = generate_password(conf, ses, hostname, salt, salt_file)

        hasher = pyescrypt.Yescrypt(mode=pyescrypt.Mode.MCF)
        hashed = hasher.digest(password=password.encode('utf8'), salt=secrets.token_bytes(32))
        hasher.compare(password.encode('utf-8'), hashed)

        click.echo(f"\nDerived 128 bit BIP39 password for '{hostname}':")
        click.echo("PLAINTEXT: " + click.style(password, fg='white'))
        click.echo("SHADOW: " + click.style(hashed.decode(), fg='green'))
