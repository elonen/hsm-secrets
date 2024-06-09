import click
from hsm_secrets.utils import connect_hsm_and_auth_with_yubikey

@click.group()
@click.pass_context
def cmd_hsm(ctx):
    """YubiHSM2 management"""
    ctx.ensure_object(dict)


@cmd_hsm.command('list-objects')
@click.pass_context
def list_objects(ctx):
    """List objects in the YubiHSM"""

    conf = ctx.obj['config']
    auth_key = conf.find_auth_key("full-admin")
    yubikey_hsm_slot = "ssh-mgt_" + ctx.obj['user']

    session = connect_hsm_and_auth_with_yubikey(conf, auth_key.id, yubikey_hsm_slot, None)

    objects = session.list_objects()
    print("YubiHSM Objects:")
    print(objects)

    session.close()
