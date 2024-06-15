from typing import Sequence
import click

from hsm_secrets.config import HSMConfig
from hsm_secrets.utils import connect_hsm_and_auth_with_yubikey, create_asymmetric_keys_on_hsm, domains_int, encode_algorithm, encode_capabilities, open_hsm_session
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

    with open_hsm_session(ctx, "full-admin", "ssh-mgt") as (conf, ses):
        create_asymmetric_keys_on_hsm(ses, conf.ssh.root_ca_keys)


@cmd_ssh.command('sign-key')
@click.pass_context
@click.option('--key-id', required=True, help="ID of the key to sign")
@click.option('--cert-file', required=True, help="Path to the certificate file")
def sign_key(ctx, key_id, cert_file):
    """Sign an SSH key"""
    raise NotImplementedError()


# TODO: Use this lib for SSH ops? https://github.com/YubicoLabs/yubihsm-ssh-tool
# (Not updated for a long time, but low-level YubiHSM2 specific, so probably still relevant)
