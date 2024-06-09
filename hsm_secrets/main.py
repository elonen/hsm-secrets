import os
import click

from click import echo

from hsm_secrets.hsm import cmd_hsm
from hsm_secrets.ssh import cmd_ssh
from hsm_secrets.tls import cmd_tls
from hsm_secrets.config import load_hsm_config


# --- Main CLI Entrypoint ---

@click.group(context_settings={'show_default': True})
@click.option('-d', '--debug', is_flag=True, help="Enable debug mode")
@click.option('-c', '--config', required=True, type=click.Path(), default='hsm-conf.yml', help="Path to configuration file")
@click.option("-U", "--username", required=True, default=lambda: os.environ.get("USER", "").split(".")[0], help="Username for key labels")
@click.version_option()
@click.pass_context
def cli(ctx, debug, config, username):
    """HSM secret management tool with HSM integration."""
    ctx.obj = {
        'debug': debug,
        'user': username,
        'config': load_hsm_config(config)
    }
    echo("User identified as: " + click.style(username, fg='cyan'))
    echo("")


@click.command('nop', short_help='Validate config and exit.')
@click.pass_context
def cmd_nop(ctx):
    echo("No errors. Exiting.")


cli.add_command(cmd_ssh, "ssh")
cli.add_command(cmd_tls, "tls")
cli.add_command(cmd_hsm, "hsm")
cli.add_command(cmd_nop, "nop")

if __name__ == '__main__':
    cli()
