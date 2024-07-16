import os
import click

from click import echo

from hsm_secrets.hsm import cmd_hsm
from hsm_secrets.ssh import cmd_ssh
from hsm_secrets.tls import cmd_tls
from hsm_secrets.passwd import cmd_pass
from hsm_secrets.config import HSMConfig, load_hsm_config
from hsm_secrets.user import cmd_user
from hsm_secrets.utils import list_yubikey_hsm_creds
from hsm_secrets.x509 import cmd_x509


# --- Main CLI Entrypoint ---

@click.group(context_settings={'show_default': True, 'help_option_names': ['-h', '--help']})
#@click.option('-d', '--debug', is_flag=True, help="Enable debug mode")
@click.option('-c', '--config', required=True, type=click.Path(), default='hsm-conf.yml', help="Path to configuration file")
@click.option("-y", "--yklabel", required=False, help="Yubikey HSM auth key label")
@click.option("-s", "--devserial", required=False, help="YubiHSM serial number to connect to (default: from config)")
@click.version_option()
@click.pass_context
def cli(ctx: click.Context, config: str, yklabel: str|None, devserial: str|None):
    """HSM secret management tool with HSM integration."""

    yk_label = yklabel
    if not yk_label:
        creds = list_yubikey_hsm_creds()
        if not creds:
            click.echo("Note: No Yubikey HSM credentials found, Yubikey auth will be disabled.", err=True)
            yk_label = ""
        else:
            yk_label = creds[0].label

    conf = load_hsm_config(config)
    assert conf.general.master_device, "No master YubiHSM serial specified in config file."

    ctx.obj = {
        # 'debug': debug,
        'yk_label': yk_label,
        'config': conf,
        'devserial': devserial or conf.general.master_device
    }

    if yk_label:
        echo("Yubikey hsmauth label: " + click.style(yk_label, fg='cyan'))
        echo("")


@click.command('nop', short_help='Validate config and exit.')
@click.pass_context
def cmd_nop(ctx):
    echo("No errors. Exiting.")


cli.add_command(cmd_ssh, "ssh")
cli.add_command(cmd_tls, "tls")
cli.add_command(cmd_pass, "pass")
cli.add_command(cmd_hsm, "hsm")
cli.add_command(cmd_nop, "nop")
cli.add_command(cmd_x509, "x509")
cli.add_command(cmd_user, "user")

if __name__ == '__main__':
    cli()
