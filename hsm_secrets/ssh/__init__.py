from typing import Sequence
import click

from hsm_secrets.config import HSMConfig
from hsm_secrets.utils import connect_hsm_and_auth_with_yubikey, domains_int, encode_algorithm, encode_capabilities
from yubihsm.objects import YhsmObject, AsymmetricKey


@click.group()
@click.pass_context
def cmd_ssh(ctx: click.Context):
    """OpenSSH keys and certificates"""
    ctx.ensure_object(dict)


@cmd_ssh.command('create-ca-keys')
@click.pass_context
#@click.option('--name', required=True, help="Name for the new root CA")
@click.option('--validity', default=3650, help="Validity period in days")
def new_root_ca(ctx: click.Context, validity: int):
    """Create a new SSH Root CA"""
    # id: 0x0200, type: asymmetric-key, algo: ed25519, sequence: 0, label: ssh-ed25519-ca-root-key
    # id: 0x0201, type: asymmetric-key, algo: rsa4096, sequence: 0, label: ssh-rsa4096-ca-root-key

    conf: HSMConfig = ctx.obj['config']
    auth_key = conf.find_auth_key("full-admin")
    yubikey_hsm_slot = "ssh-mgt_" + ctx.obj['user']
    session = connect_hsm_and_auth_with_yubikey(conf, auth_key.id, yubikey_hsm_slot, None)

    root_key_defs = [d for d in conf.ssh.root_ca_keys]

    existing: Sequence[YhsmObject] = session.list_objects()
    for obj in existing:
        if isinstance(obj, AsymmetricKey) and obj.id in [d.id for d in root_key_defs]:
            click.echo(f"AsymmetricKey ID '{hex(obj.id)}' already exists")
            if click.confirm("Delete and recreate?"):
                obj.delete()
            else:
                raise click.Abort()

    for kdef in conf.ssh.root_ca_keys:
        click.echo(f"Creating key '{kdef.label}' ID '{hex(kdef.id)}' ({kdef.algorithm}) ...", nl=False)
        AsymmetricKey.generate(
            session=session,
            object_id=kdef.id,
            label=kdef.label,
            domains=domains_int(kdef.domains),
            capabilities=encode_capabilities(kdef.capabilities),
            algorithm=encode_algorithm(kdef.algorithm)
        )
        click.echo("done")


@cmd_ssh.command('sign-key')
@click.pass_context
@click.option('--key-id', required=True, help="ID of the key to sign")
@click.option('--cert-file', required=True, help="Path to the certificate file")
def sign_key(ctx, key_id, cert_file):
    """Sign an SSH key"""
    raise NotImplementedError()


# TODO: Use this lib for SSH ops? https://github.com/YubicoLabs/yubihsm-ssh-tool
# (Not updated for a long time, but low-level YubiHSM2 specific, so probably still relevant)
