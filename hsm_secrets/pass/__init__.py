import click

@click.group()
@click.pass_context
def cmd_pass(ctx):
    """Password derivation"""
    ctx.ensure_object(dict)


@cmd_pass.command('show')
@click.pass_context
@click.option('--hostname', required=True, help="Hostname to derive password for")
def show(ctx: click.Context, hostname: str):
    """Create a new SSH Root CA"""
    raise NotImplementedError()
