from pathlib import Path
from textwrap import dedent
import time
from typing import Sequence, cast
import click

from hsm_secrets.config import HSMAsymmetricKey, HSMKeyID, click_hsm_obj_auto_complete
from hsm_secrets.utils import HsmSecretsCtx, cli_code_info, cli_result, cli_warn, open_hsm_session, pass_common_args
from cryptography.hazmat.primitives import _serialization
from cryptography.hazmat.primitives.serialization import ssh

@click.group()
@click.pass_context
def cmd_ssh(ctx: click.Context):
    """OpenSSH keys and certificates"""
    ctx.ensure_object(dict)


@cmd_ssh.command('get-ca')
@pass_common_args
@click.option('--all', '-a', 'get_all', is_flag=True, help="Get all certificates")
@click.argument('certs', nargs=-1, type=str, metavar='<id|label>...', shell_complete=click_hsm_obj_auto_complete(HSMAsymmetricKey, 'ssh.root_ca_keys'))
def get_ca(ctx: HsmSecretsCtx, get_all: bool, certs: Sequence[str]):
    """Get the public keys of the SSH CA keys"""
    if get_all:
        selected_keys = ctx.conf.ssh.root_ca_keys
    else:
        selected_keys = [cast(HSMAsymmetricKey, ctx.conf.find_def(s, HSMAsymmetricKey, ctx.conf.ssh.root_ca_keys)) for s in certs]
    if not selected_keys:
        raise click.BadArgumentUsage("ERROR: No keys to get")

    with open_hsm_session(ctx) as ses:
        for key in selected_keys:
            assert isinstance(key, HSMAsymmetricKey)
            pubkey = ses.get_public_key(key).public_bytes(encoding=_serialization.Encoding.OpenSSH, format=_serialization.PublicFormat.OpenSSH).decode('ascii')
            cli_result(f"{pubkey} {key.label}")



@cmd_ssh.command('sign-user')
@click.option('--out', '-o', type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=True), help="Output file (default: deduce from input)", default=None)
@click.option('--ca', '-c', required=False, help="CA key ID (hex) or label to sign with. Default: read from config", default=None)
@click.option('--username', '-u', required=False, help="Key owner's name (for auditing)", default=None)
@click.option('--certid', '-n', required=False, help="Explicit certificate ID (default: auto-generated)", default=None)
@click.option('--validity', '-t', required=False, default=365*24*60*60, help="Validity period in seconds (default: 1 year)")
@click.option('--principals', '-p', required=False, help="Comma-separated list of principals", default='')
@click.option('--extensions', '-e', help="Comma-separated list of SSH extensions", default='permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc')
@click.argument('keyfile', type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=True), default='-')
@pass_common_args
def sign_ssh_user_key(ctx: HsmSecretsCtx, out: str, ca: str|None, username: str|None, certid: str|None, validity: int, principals: str, extensions: str, keyfile: str):
    """Make and sign an SSH user certificate

    TYPICAL USAGE:

        $ ssh sign-user -u john.doe -p admin,users id_ed25519_sk_jdoe.pub

    [keyfile]: file containing the public key to sign (default: stdin)

    If --ca is not specified, the default CA key is used (as specified in the config file).

    Either --username or explicit --certid must be specified. If --certid is not specified,
    a certificate ID is auto-generated using the key owner name, current time, and principal list.

    Unique and clear certificate IDs are important for auditing and revocation.

    Output file is deduced from input file if not specified with --out (or '-' for stdout).
    For example, 'id_rsa.pub' will be signed to 'id_rsa-cert.pub'.
    """
    if (not username and not certid) or (username and certid):
        raise click.ClickException("Either --username or --certid must be specified, but not both")
    timestamp = int(time.time())
    certid = certid or (f"{username}-{timestamp}-{'+'.join(principals.split(','))}").strip().lower().replace(' ', '_')
    _sign_ssh_key(ctx, out, ca, certid, validity, principals, extensions, keyfile, ssh.SSHCertificateType.USER, timestamp)


@cmd_ssh.command('sign-host')
@click.option('--out', '-o', type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=True), help="Output file (default: deduce from input)", default=None)
@click.option('--ca', '-c', required=False, help="CA key ID (hex) or label to sign with. Default: read from config", default=None)
@click.option('--hostname', '-H', required=True, help="Primary hostname of the server")
@click.option('--validity', '-t', required=False, default=365*24*60*60, help="Validity period in seconds (default: 1 year)")
@click.option('--principals', '-p', required=False, help="Comma-separated list of additional hostnames, IP addresses, or wildcards this certificate is valid for", default=None)
@click.argument('keyfile', type=click.Path(exists=False, dir_okay=False, resolve_path=True, allow_dash=True), default='-')
@pass_common_args
def sign_ssh_host_key(ctx: HsmSecretsCtx, out: str, ca: str|None, hostname: str, validity: int, principals: str|None, keyfile: str):
    """Make and sign an SSH host certificate

    TYPICAL USAGE:

        $ ssh sign-host -H wiki.example.com -p "wiki.*,192.168.80.80" ssh_host_rsa_key.pub

    [keyfile]: file containing the public key to sign (default: stdin)

    If --ca is not specified, the default CA key is used (as specified in the config file).

    The --hostname is used as the primary principal and is included in the certificate ID.

    --principals can be used to specify additional hostnames, IP addresses, or wildcards that this certificate is valid for.
    This is useful for servers with multiple names, IP addresses, or for covering entire subdomains or services.

    Wildcards are supported in principals and can be used as prefixes or suffixes. For example:
    - wiki.* would match any hostname starting with "wiki."
    - *.example.com would match any subdomain of example.com
    - 192.168.1.* would match any IP in the 192.168.1.0/24 subnet

    Output file is deduced from input file if not specified with --out (or '-' for stdout).
    For example, 'ssh_host_rsa_key.pub' will be signed to 'ssh_host_rsa_key-cert.pub'.

    Example usage:
    sign-host --hostname wiki.example.com --principals "wiki.*,*.example.com,10.0.0.*" ssh_host_rsa_key.pub
    """
    principal_list = [hostname]
    if principals:
        principal_list.extend([p.strip() for p in principals.split(',') if p.strip() != hostname])
    principals_str = ','.join(principal_list)

    timestamp = int(time.time())
    certid = f"host-{hostname}-{timestamp}+{len(principal_list)-1}-principals".strip().lower().replace(' ', '_')

    cli_code_info(f"Creating host certificate for {hostname} with certid: {certid}")
    cli_code_info(f"Principals: {principals_str}")

    timestamp = int(time.time())
    _sign_ssh_key(ctx, out, ca, certid, validity, principals_str, '', keyfile, ssh.SSHCertificateType.HOST, timestamp)



def _sign_ssh_key(ctx: HsmSecretsCtx, out: str, ca: str|None, certid: str, validity: int, principals: str, extensions: str, keyfile: str, cert_type: ssh.SSHCertificateType, timestamp: int):
    from hsm_secrets.ssh.openssh.signing import sign_ssh_cert
    from hsm_secrets.ssh.openssh.ssh_certificate import cert_for_ssh_pub_id, str_to_extension
    from hsm_secrets.key_adapters import make_private_key_adapter

    ca_key_def = ctx.conf.find_def(ca or ctx.conf.ssh.default_ca, HSMAsymmetricKey)
    assert isinstance(ca_key_def, HSMAsymmetricKey)

    ca_def = [c for c in ctx.conf.ssh.root_ca_keys if c.id == ca_key_def.id]
    if not ca_def:
        raise click.ClickException(f"CA key 0x{ca_key_def.id:04x} not found in config")

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

    princ_list = [s.strip() for s in principals.split(',')] if principals else []

    cert_type_str = "user" if cert_type == ssh.SSHCertificateType.USER else "host"
    cli_code_info(f"Signing {cert_type_str} key with CA `{ca_def[0].label}` as cert ID `{certid}` with principals: `{princ_list}`")

    # Create certificate from public key
    cert = cert_for_ssh_pub_id(
        key_str,
        certid,
        cert_type=cert_type,
        valid_seconds=validity,
        principals=princ_list,
        serial=timestamp,
        extensions={str_to_extension(s.strip()): b'' for s in extensions.split(',')} if cert_type == ssh.SSHCertificateType.USER else {})

    # Figure out output file
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
        ca_priv_key = ses.get_private_key(ca_key_def)
        sign_ssh_cert(cert, ca_priv_key)
        cert_str = cert.to_string_fmt().replace(certid, f"{certid}{key_comment}").strip()

        if not out_fp:
            out_fp = open(path, 'w')
        out_fp.write(cert_str.strip() + "\n")   # type: ignore
        out_fp.close()
        if str(path) != '-':
            ca_pub_key = ca_priv_key.public_key().public_bytes(encoding=_serialization.Encoding.OpenSSH, format=_serialization.PublicFormat.OpenSSH)
            if cert_type == ssh.SSHCertificateType.USER:
                cli_code_info(dedent(f"""
                    User certificate written to: {path}
                    - Send it to the user and ask them to put it in `~/.ssh/` along with the private key
                    - To view it, run: `ssh-keygen -L -f {path}`
                    - To allow access (adapt principals as needed), add this to your server authorized_keys file(s):
                      `cert-authority,principals="{','.join(cert.valid_principals)}" {ca_pub_key.decode()} HSM_{ca_def[0].label}`
                    """).strip())
            else:
                cli_code_info(dedent(f"""
                    Host certificate written to: {path}
                    - Install it on the host machine, typically in `/etc/ssh/`
                    - Update the SSH server config to use this certificate (e.g., `HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub`)
                    - To view it, run: `ssh-keygen -L -f {path}`
                    - To trust this CA for host certificates, add this to your client's `~/.ssh/known_hosts` file:
                      `@cert-authority * {ca_pub_key.decode()} HSM_{ca_def[0].label}`
                    """).strip())
