import os
import click

from hsm_secrets.hsm import cmd_hsm
from hsm_secrets.ssh import cmd_ssh
from hsm_secrets.tls import cmd_tls
from hsm_secrets.passwd import cmd_pass
from hsm_secrets.config import HSMAuthKey, load_hsm_config
from hsm_secrets.user import cmd_user
from hsm_secrets.utils import HSMAuthMethod, HsmSecretsCtx, cli_warn, list_yubikey_hsm_creds, pass_common_args, cli_info
from hsm_secrets.x509 import cmd_x509
from click_repl import register_repl    # type: ignore


# --- Main CLI Entrypoint ---

@click.group(context_settings={'show_default': True, 'help_option_names': ['-h', '--help']})
#@click.option('-d', '--debug', is_flag=True, help="Enable debug mode")
@click.option('-c', '--config', required=False, type=click.Path(), default=None, help="Path to configuration file")
@click.option('-q', '--quiet', is_flag=True, help="Suppress all non-essential output", default=False)
@click.option("-y", "--yklabel", required=False, help="Yubikey HSM auth key label (default: first slot)")
@click.option("-s", "--hsmserial", required=False, help="YubiHSM serial number to connect to (default: get master from config)")
@click.option("--auth-yubikey", required=False, is_flag=True, help="Use Yubikey HSM auth key for HSM login")
@click.option("--auth-default-admin", required=False, is_flag=True, help="Use default auth key for HSM login")
@click.option("--auth-password-id", required=False, type=str, help="Auth key ID (hex) to login with password from env HSM_PASSWORD")
@click.option("--mock", required=False, type=click.Path(dir_okay=False, file_okay=True, exists=False), help="Use mock HSM for testing, data in give file")
@click.version_option()
@click.pass_context
def cli(ctx: click.Context, config: str|None, quiet: bool, yklabel: str|None, hsmserial: str|None,
        auth_default_admin: str|None, auth_yubikey: str|None, auth_password_id: str|None, mock: str|None):
    """Config file driven secret management tool for YubiHSM2 devices.

    Unless --config is specified, configuration file will be searched first
    from the environment variable HSM_SECRETS_CONFIG, then from the current
    directory, and finally from the user's home directory.

    Default HSM login method depends on the command (most use yubikey),
    but can be overridden with the --auth-* options:

    --auth-yubikey: Use Yubikey HSM auth key for HSM login. If --yklabel
        is not not specified, the first hsmauth label on the Yubikey will be used.

    --auth-default-admin: Use insecure default auth key (see config).

    --auth-password-id <id|label>: Use password from environment variable
        HSM_PASSWORD with the specified auth key ID (hex) or label.
    """
    ctx.obj = {'quiet': quiet}  # early setup for cli_info and other utils to work

    # Use config file from env var or default locations if not specified
    if not config:
        env_var = "HSM_SECRETS_CONFIG"
        default_paths = ["./hsm-conf.yml", "~/.hsm-conf.yml"]
        config = os.getenv(env_var)
        if not config:
            for alt in default_paths:
                if not config and os.path.exists(os.path.expanduser(alt)):
                    config = alt
        if not config:
            raise click.UsageError(f"No configuration file found in env or {str(default_paths)}. Please specify a config file with -c/--config or set the {env_var} environment variable.")

    cli_info("Using config file: " + click.style(config, fg='cyan'), err=True)
    conf = load_hsm_config(os.path.expanduser(config))

    assert conf.general.master_device, "No master YubiHSM serial specified in config file."

    # Get first Yubikey HSM auth key label from device if not specified
    yubikey_label = yklabel
    if not yubikey_label and not (auth_default_admin or auth_password_id or mock):
        creds = list_yubikey_hsm_creds()
        if not creds:
            if not (quiet or auth_default_admin or auth_password_id):
                cli_warn("Note: No Yubikey HSM credentials found, Yubikey auth will be disabled.")
            yubikey_label = ""
        else:
            yubikey_label = creds[0].label
            if not (quiet or auth_default_admin or auth_password_id):
                cli_info("Yubikey hsmauth label (using first slot): " + click.style(yubikey_label, fg='cyan'))

    ctx.obj = {
        # 'debug': debug,
        'yubikey_label': yubikey_label,
        'config': conf,
        'quiet': quiet,
        'hsmserial': hsmserial or conf.general.master_device,
        'forced_auth_method': None,
        'auth_password_id': conf.find_def(auth_password_id, HSMAuthKey).id if auth_password_id else None,
        'auth_password': os.getenv("HSM_PASSWORD", None),
        'mock_file': mock,
    }

    # Check for forced auth method
    if sum([(1 if x else 0) for x in [auth_default_admin, auth_yubikey, auth_password_id]]) > 1:
        raise click.UsageError("Only one forced auth method can be specified.")
    if auth_default_admin:
        ctx.obj['forced_auth_method'] = HSMAuthMethod.DEFAULT_ADMIN
    elif auth_yubikey:
        ctx.obj['forced_auth_method'] = HSMAuthMethod.YUBIKEY
    elif auth_password_id:
        ctx.obj['forced_auth_method'] = HSMAuthMethod.PASSWORD
        if not ctx.obj['auth_password']:
            raise click.UsageError("HSM_PASSWORD environment variable not set for password auth method.")
        if not ctx.obj['auth_password_id']:
            raise click.UsageError("Auth key ID not specified for password auth method.")

    cli_info("")


@click.command('nop', short_help='Validate config and exit.')
@pass_common_args
def cmd_nop(ctx: HsmSecretsCtx):
    cli_info("No errors. Exiting.")


cli.add_command(cmd_ssh,  "ssh")
cli.add_command(cmd_tls,  "tls")
cli.add_command(cmd_pass, "pass")
cli.add_command(cmd_hsm,  "hsm")
cli.add_command(cmd_nop,  "nop")
cli.add_command(cmd_x509, "x509")
cli.add_command(cmd_user, "user")
register_repl(cli)

if __name__ == '__main__':
    cli()
