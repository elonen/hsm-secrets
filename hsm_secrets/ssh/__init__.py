from pathlib import Path
from textwrap import dedent
import time
from typing import Sequence
import click

from hsm_secrets.config import HSMConfig
from hsm_secrets.utils import HsmSecretsCtx, cli_code_info, cli_result, cli_warn, open_hsm_session, pass_common_args
from cryptography.hazmat.primitives import _serialization

import yubihsm.defs    # type: ignore [import]
from yubihsm.objects import AsymmetricKey   # type: ignore [import]


@click.group()
@click.pass_context
def cmd_ssh(ctx: click.Context):
    """OpenSSH keys and certificates"""
    ctx.ensure_object(dict)


@cmd_ssh.command('get-ca')
@pass_common_args
@click.option('--all', '-a', 'get_all', is_flag=True, help="Get all certificates")
@click.argument('cert_ids', nargs=-1, type=str, metavar='<id>...')
def get_ca(ctx: HsmSecretsCtx, get_all: bool, cert_ids: Sequence[str]):
    """Get the public keys of the SSH CA keys"""
    all_ids = set([str(ca.id) for ca in ctx.conf.ssh.root_ca_keys])
    selected_ids = all_ids if get_all else set(cert_ids)

    if not selected_ids:
        raise click.BadArgumentUsage("ERROR: specify at least one CA key ID, or use --all")

    if len(selected_ids - all_ids) > 0:
        raise click.ClickException(f"Unknown CA key IDs: {selected_ids - all_ids}")
    selected_keys = [ca for ca in ctx.conf.ssh.root_ca_keys if str(ca.id) in selected_ids]

    if not selected_keys:
        raise click.ClickException("No CA keys selected")

    with open_hsm_session(ctx) as ses:
        for key in selected_keys:
            obj = ses.get_object(key.id, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
            assert isinstance(obj, AsymmetricKey)
            pubkey = obj.get_public_key().public_bytes(encoding=_serialization.Encoding.OpenSSH, format=_serialization.PublicFormat.OpenSSH).decode('ascii')
            cli_result(f"{pubkey} {key.label}")


@cmd_ssh.command('sign-key')
@click.option('--out', '-o', type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=True), help="Output file (default: deduce from input)", default=None)
@click.option('--ca', '-c', required=False, help="CA key ID (hex) to sign with. Default: read from config", default=None)
@click.option('--username', '-u', required=False, help="Key owner's name (for auditing)", default=None)
@click.option('--certid', '-n', required=False, help="Explicit certificate ID (default: auto-generated)", default=None)
@click.option('--validity', '-t', required=False, default=365*24*60*60, help="Validity period in seconds (default: 1 year)")
@click.option('--principals', '-p', required=False, help="Comma-separated list of principals", default='')
@click.option('--extentions', '-e', help="Comma-separated list of SSH extensions", default='permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc')
@click.argument('keyfile', type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=True), default='-')
@pass_common_args
def sign_key(ctx: HsmSecretsCtx, out: str, ca: str|None, username: str|None, certid: str|None, validity: int, principals: str, extentions: str, keyfile: str):
    """Make and sign an SSH user certificate

    [keyfile]: file containing the public key to sign (default: stdin)

    If --ca is not specified, the default CA key is used (as specified in the config file).

    Either --username or explicit --certid must be specified. If --certid is not specified,
    a certificate ID is auto-generated key owner name, current time and principal list.
    Unique and clear certificate IDs are important for auditing and revocation.

    Output file is deduced from input file if not specified with --out (or '-' for stdout).
    For example, 'id_rsa.pub' will be signed to 'id_rsa-cert.pub'.
    """
    from hsm_secrets.ssh.openssh.signing import sign_ssh_cert
    from hsm_secrets.ssh.openssh.ssh_certificate import cert_for_ssh_pub_id, str_to_extension
    from hsm_secrets.key_adapters import make_private_key_adapter

    ca_key_id = int(ca.replace('0x',''), 16) if ca else ctx.conf.ssh.default_ca

    ca_def = [c for c in ctx.conf.ssh.root_ca_keys if c.id == ca_key_id]
    if not ca_def:
        raise click.ClickException(f"CA key 0x{ca_key_id:04x} not found in config")

    if not username and not certid:
        raise click.ClickException("Either --username or --certid must be specified")
    elif username and certid:
        raise click.ClickException("Only one of --username or --certid must be specified")

    # Read public key
    key_str = ""
    if keyfile == '-':
        cli_warn("Reading key from stdin...")
        key_str = click.get_text_stream('stdin').readline().strip()
    else:
        with open(keyfile, 'r') as f:
            key_str = f.read()

    # Last part of the key file, user-added comment
    # This won't be part of the certificate ID, but will added to the signed -cert.pub file for user reference
    key_comment = ""
    parts = key_str.split(' ')
    if len(parts) >= 3:
        key_comment = "__"+parts[2]

    timestamp = int(time.time())
    princ_list = [s.strip() for s in principals.split(',')] if principals else []
    certid = certid or (f"{username}-{timestamp}-{'+'.join(principals.split(','))}").strip().lower().replace(' ', '_')
    cli_code_info(f"Signing key with CA `{ca_def[0].label}` as cert ID `{certid}` with principals: `{princ_list}`")

    # Create certificate from public key
    cert = cert_for_ssh_pub_id(
        key_str,
        certid,
        valid_seconds = validity,
        principals = princ_list,
        serial = timestamp,
        extensions = {str_to_extension(s.strip()): b'' for s in extentions.split(',')})

    # Figre out output file
    out_fp = None
    path = None
    if out == '-' or (keyfile == '-' and not out):
        out_fp = click.get_text_stream('stdout')
        path = '-'
    else:
        p = Path(out) if out else (Path(keyfile).parent / (Path(keyfile).stem + "-cert.pub"))
        if p.exists():
            click.confirm(f"Overwrite existing file '{p}'?", abort=True, err=True)
        path = str(p)

    # Sign & write out
    with open_hsm_session(ctx) as ses:
        obj = ses.get_object(ca_key_id, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
        assert isinstance(obj, AsymmetricKey)

        ca_pubkey = obj.get_public_key().public_bytes(encoding=_serialization.Encoding.OpenSSH, format=_serialization.PublicFormat.OpenSSH)
        ca_key = make_private_key_adapter(obj)

        sign_ssh_cert(cert, ca_key)
        cert_str = cert.to_string_fmt().replace(certid, f"{certid}{key_comment}").strip()

        if not out_fp:
            out_fp = open(path, 'w')
        out_fp.write(cert_str.strip() + "\n")   # type: ignore
        out_fp.close()
        if str(path) != '-':
            cli_code_info(dedent(f"""
                Certificate written to: {path}
                  - Send it to the user and ask them to put it in `~/.ssh/` along with the private key
                  - To view it, run: `ssh-keygen -L -f {path}`
                  - To allow access (adapt principals as neede), add this to your server authorized_keys file(s):
                    `cert-authority,principals="{','.join(cert.valid_principals)}" {ca_pubkey.decode()} HSM_{ca_def[0].label}`
                """).strip())
