import os
import click

from click import echo

from hsm_secrets.hsm import cmd_hsm
from hsm_secrets.ssh import cmd_ssh
from hsm_secrets.tls import cmd_tls
from hsm_secrets.passwd import cmd_pass
from hsm_secrets.config import load_hsm_config
from hsm_secrets.utils import list_yubikey_hsm_creds


# --- Main CLI Entrypoint ---

@click.group(context_settings={'show_default': True})
@click.option('-d', '--debug', is_flag=True, help="Enable debug mode")
@click.option('-c', '--config', required=True, type=click.Path(), default='hsm-conf.yml', help="Path to configuration file")
@click.option("-y", "--yklabel", required=False, help="Yubikey HSM auth key label")
@click.version_option()
@click.pass_context
def cli(ctx: click.Context, debug: bool, config: str, yklabel: str|None):
    """HSM secret management tool with HSM integration."""

    yk_label = yklabel
    if not yk_label:
        creds = list_yubikey_hsm_creds()
        if not creds:
            raise click.ClickException("No Yubikey HSM credentials found.")
        yk_label = creds[0].label

    ctx.obj = {
        'debug': debug,
        'yk_label': yk_label,
        'config': load_hsm_config(config)
    }

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

if __name__ == '__main__':
    cli()
