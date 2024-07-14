from base64 import b64encode
from math import floor
import struct
import time
from typing import Sequence
import click

from hsm_secrets.ssh.ssh_utils import create_request, create_template
from hsm_secrets.utils import generate_asymmetric_keys_on_hsm, encode_algorithm, encode_capabilities, open_hsm_session_with_yubikey
from yubihsm.objects import YhsmObject, AsymmetricKey, Template
from cryptography.hazmat.primitives import (_serialization, serialization)
import yubihsm.defs


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

    with open_hsm_session_with_yubikey(ctx) as (conf, ses):
        root_keys = generate_asymmetric_keys_on_hsm(ses, conf, conf.ssh.root_ca_keys)
        pubkeys = [
            key.get_public_key().public_bytes(encoding=_serialization.Encoding.OpenSSH, format=_serialization.PublicFormat.OpenSSH)
            for key in root_keys
        ]
        print("Public keys:")
        for key in pubkeys:
            print(key)


@cmd_ssh.command('get-ca-pubkeys')
@click.pass_context
@click.option('--outdir', required=True, type=click.Path(), default='./OUT/', help="Directory to write public keys to")
def get_root_ca_pubkeys(ctx: click.Context, outdir: str):
    """Write SSH Root CA .pub files"""
    outdir = outdir.rstrip('/')
    with open_hsm_session_with_yubikey(ctx) as (conf, ses):
        for key in conf.ssh.root_ca_keys:
            obj = ses.get_object(key.id, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
            assert isinstance(obj, AsymmetricKey)
            pubkey = obj.get_public_key().public_bytes(encoding=_serialization.Encoding.OpenSSH, format=_serialization.PublicFormat.OpenSSH)
            with open(f"{outdir}/{key.label}.pub", "wb") as f:
                f.write(pubkey)
            click.echo(f"Wrote '{outdir}/{key.label}.pub'")



@cmd_ssh.command('sign-key')
@click.option('--keyfile-to-sign', required=True, type=click.Path(), help="Public key file to sign")
@click.option('--validity', default=365*24*60*60, help="Validity period in seconds (default: 1 year)")
@click.option('--principals', required=True, help="Comma-separated list of principals")
@click.option('--outfile', required=True, type=click.Path(), help="Output file for signed certificate")
@click.option('--subject', required=True, help="Name (arbitrary id) for user/host whose key is being signed")
@click.pass_context
def sign_key(ctx: click.Context, keyfile_to_sign: str, validity: int, principals: str, outfile: str, subject: str):
    """Sign an SSH key with the SSH Root CA"""
    from cryptography.hazmat.primitives.asymmetric import (ed25519, rsa)

    with open_hsm_session_with_yubikey(ctx) as (conf, ses):
        # Load the public key to sign
        with open(keyfile_to_sign, 'rb') as user_public_key_file:
            user_public_key = serialization.load_ssh_public_key(user_public_key_file.read())

        # Find the CA key that matches the user key type
        if isinstance(user_public_key, rsa.RSAPublicKey):
            key_type = "rsa"
            key_bits = user_public_key.key_size
        elif isinstance(user_public_key, ed25519.Ed25519PublicKey):
            key_type = "ed25519"
            key_bits = 32*8
        else:
            raise ValueError(f"Unsupported user key type: {type(user_public_key)}")

        click.echo(f"Read in SSH key of type '{key_type}' ({key_bits} bits) for subject '{subject}'...")

        ca_key_def = [key for key in conf.ssh.root_ca_keys if key_type in key.algorithm][0]
        assert ca_key_def is not None, f"No CA key found for user SSH key type '{key_type}'"

        # Load the CA public key
        ca_key_obj = ses.get_object(ca_key_def.id, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
        assert isinstance(ca_key_obj, AsymmetricKey)
        ca_pubkey = ca_key_obj.get_public_key()  #.public_bytes(encoding=_serialization.Encoding.OpenSSH, format=_serialization.PublicFormat.OpenSSH)
        if not isinstance(ca_pubkey, (rsa.RSAPublicKey, ed25519.Ed25519PublicKey)):
            raise ValueError(f"Unsupported CA key type: {type(ca_pubkey)}")

        # Some sanity checks
        assert validity > 0, "Validity period must be positive"
        assert not " " in principals, "Principal list must not contain spaces"
        principal_list = sorted(list(set(principals.split(','))))
        assert all(len(p) > 0 for p in principal_list), "Principal list must not contain empty strings"

        # Create a template
        template_data = create_template(
            ts_public_key = ca_pubkey,
            key_whitelist = [ca_key_obj.id],
            not_before = 5*60,  # 5 minutes ago, to allow for clock skew
            not_after = validity + 5*60,
            principals_blacklist = [])

        # Select slot for SSH template based on current HSM session ID (to avoid collisions)
        sid = ses.sid or 0
        template_id = conf.ssh.template_slots.min + sid % (conf.ssh.template_slots.max - conf.ssh.template_slots.min + 1)

        # Load the template into the HSM
        old_tmpl_obj = Template(session=ses, object_id=template_id)
        old_tmpl_data = old_tmpl_obj.get()

        if old_tmpl_data and old_tmpl_data == template_data:
            click.echo(f"Template {hex(template_id)} on HSM is current. Using it.")
        else:
            if old_tmpl_data:
                click.echo(f"Template ID {hex(template_id)} differs on HSM. Deleting old template... ", nl=False)
                old_tmpl_obj.delete()
                click.echo("Ok")

            click.echo(f"Loading new template {hex(template_id)} into HSM... ", nl=False)
            Template.put(
                session=ses,
                object_id=template_id,
                label=f"tmp-ssh-template-ses-{sid}",
                domains=domains_to_bitfield(ca_key_def.domains),
                capabilities=encode_capabilities(["exportable-under-wrap"]),
                algorithm=encode_algorithm('template-ssh'),
                data=template_data)
            click.echo("Ok")


        # Create a request
        ts_now = floor(time.time())
        allowed_ssh_extensions = ['permit-X11-forwarding','permit-agent-forwarding', 'permit-port-forwarding', 'permit-pty', 'permit-user-rc']

        req_data = create_request(
            ca_public_key = ca_pubkey,
            user_public_key = user_public_key,
            key_id = subject,
            principals = principal_list,
            options = [],
            not_before = ts_now,
            not_after = ts_now + validity,
            serial = None,       # Use timestamp for cert serial number
            host_key = False,
            extensions = [(k,b'') for k in allowed_ssh_extensions])

        def sha256(data: bytes) -> bytes:
            from hashlib import sha256
            return sha256(data).digest()

        # Build the SSH signing request from timestamp + signature + request data
        ts_bytes = struct.pack('!I', ts_now)
        request_hash = sha256(req_data)
        message_hash = sha256(request_hash + ts_bytes)
        click.echo(f"Signing current timestamp + request hash with CA key '{ca_key_def.label}'... ", nl=False)
        req_sig = ca_key_obj.sign_pkcs1v1_5(message_hash)
        click.echo("Ok")
        sig_req_message = ts_bytes + req_sig + req_data

        # Sign the request
        click.echo(f"Signing SSH key with CA key '{ca_key_def.label}'... ", nl=False)
        signature = ca_key_obj.sign_ssh_certificate(
            template_id = template_id,
            request = sig_req_message,
            algorithm = encode_algorithm('rsa-pkcs1-sha256'))
        click.echo("Ok")

        # Build the OpenSSH certificate format
        cert_data = req_data + signature
        cert_type = f"ssh-{key_type}-cert-v01@openssh.com".encode('ascii')
        comment = f"signed-by-{ca_key_def.label}-for-{subject}".encode('utf-8')
        ssh_cert = cert_type + b" " + b64encode(cert_data) + b" " + comment

        # Write the certificate to a file
        with open(outfile, "wb") as f:
            f.write(ssh_cert)
        click.echo(f"Wrote signed SSH certificate in '{outfile}'")
