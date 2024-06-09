import click

@click.group()
@click.pass_context
def cmd_tls(ctx):
    """TLS (x.509) keys and certificates"""
    ctx.ensure_object(dict)

@cmd_tls.command('make-root-ca')
@click.pass_context
@click.option('--name', required=True, help="Name for the new root CA")
@click.option('--validity', default=365, help="Validity period in days")
def make_root_ca(ctx, name, validity):
    """Create a new TLS Root CA"""
    raise NotImplementedError()

@cmd_tls.command('new-https-intermediate')
@click.pass_context
@click.option('--name', required=True, help="Name for the new HTTPS intermediate CA")
@click.option('--parent-ca', required=True, help="Name of the parent CA")
@click.option('--validity', default=365, help="Validity period in days")
def new_https_intermediate(ctx, name, parent_ca, validity):
    """Create a new HTTPS Intermediate CA"""
    raise NotImplementedError()

@cmd_tls.command('new-http-server-cert')
@click.pass_context
@click.option('--name', required=True, help="Name for the new HTTP server certificate")
@click.option('--domain', required=True, help="Domain name for the server certificate")
@click.option('--validity', default=365, help="Validity period in days")
def new_http_server_cert(ctx, name, domain, validity):
    """Create a new HTTP server certificate"""
    raise NotImplementedError()
