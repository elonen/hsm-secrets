from pathlib import Path
from cryptography import x509
from yubihsm.core import AuthSession

from cryptography.hazmat.primitives import serialization
from hsm_secrets.config import HSMConfig, KeyID, OpaqueObject, X509Cert, find_all_config_items_per_type, find_config_items_of_class, load_hsm_config

import yubihsm.objects
import yubihsm.defs

from hsm_secrets.utils import confirm_and_delete_old_yubihsm_object_if_exists, hsm_obj_exists, open_hsm_session_with_default_admin, open_hsm_session_with_yubikey, click_echo_colored_commands

from hsm_secrets.x509.cert_builder import X509CertBuilder
from hsm_secrets.x509.def_utils import display_x509_info, merge_x509_info_with_defaults, topological_sort_x509_cert_defs

import click

from hsm_secrets.key_adapters import make_private_key_adapter


@click.group()
@click.pass_context
def cmd_x509(ctx):
    """Genral X.509 Certificate Management"""
    ctx.ensure_object(dict)

# ---------------

@cmd_x509.command('create-cert')
@click.pass_context
@click.option('--all', '-a', 'all_certs', is_flag=True, help="Create all certificates")
@click.option("--dry-run", "-n", is_flag=True, help="Dry run (do not create certificates)")
@click.argument('cert_ids', nargs=-1, type=str, metavar='<id>...')
def create_cert_cmd(ctx: click.Context, all_certs: bool, dry_run: bool, cert_ids: tuple):
    """Create certificate(s) on the HSM

    ID is a 16-bit hex value (e.g. '0x12af' or '12af').
    You can specify multiple IDs to create multiple certificates,
    or use the --all flag to create all certificates defined in the config.

    Specified certificates will be created in topological order, so that
    any dependencies are created first.
    """
    if not all_certs and not cert_ids:
        print("Error: No certificates specified for creation.")
        return
    create_certs_impl(ctx, all_certs, dry_run, cert_ids)


@cmd_x509.command('get-cert')
@click.pass_context
@click.option('--all', '-a', 'all_certs', is_flag=True, help="Get all certificates")
@click.option('--outdir', '-o', type=click.Path(), required=False, help="Write PEMs into files here")
@click.option('--bundle', '-b', type=click.Path(), required=False, help="Write a single PEM bundle file")
@click.option('--use-default-admin', is_flag=True, help="Use the default admin key (instead of Yubikey)")
@click.argument('cert_ids', nargs=-1, type=str, metavar='<id>...')
def get_cert_cmd(ctx: click.Context, all_certs: bool, outdir: str|None, bundle: str|None, cert_ids: tuple, use_default_admin: bool):
    """Get certificate(s) from the HSM

    You can specify multiple IDs to get multiple certificates,
    or use the --all flag to get all certificates defined in the config.
    Specify --bundle to get a single PEM file with all selected certificates.
    """
    conf = ctx.obj['config']

    if outdir and bundle:
        raise click.ClickException("Error: --outdir and --bundle options are mutually exclusive.")

    cert_def_for_id = {c.id: c for c in find_config_items_of_class(conf, OpaqueObject)}
    all_cert_ids = [f"0x{c.id:04x}" for c in cert_def_for_id.values()]

    selected_ids = all_cert_ids if all_certs else list(cert_ids)
    if len(set(selected_ids) - set(all_cert_ids)) > 0:
        raise click.ClickException(f"Unknown certificate ID(s): {set(selected_ids) - set(all_cert_ids)}.\nValid IDs are: {all_cert_ids}")
    if not selected_ids:
        raise click.ClickException("No certificates specified for retrieval.")

    for cd in [cert_def_for_id[int(id.replace("0x", ""), 16)] for id in selected_ids]:
        click.echo(f"- Fetching PEM for 0x{cd.id:04x}: '{cd.label}'")
    click.echo()

    def do_it(conf: HSMConfig, ses: AuthSession):
        for cert_id in selected_ids:
            cert_id_int = int(cert_id.replace("0x", ""), 16)
            obj = ses.get_object(cert_id_int, yubihsm.defs.OBJECT.OPAQUE)
            assert isinstance(obj, yubihsm.objects.Opaque)
            cert_def = cert_def_for_id[cert_id_int]
            pem = obj.get_certificate().public_bytes(encoding=serialization.Encoding.PEM).decode()
            if outdir:
                pem_file = Path(outdir) / f"{cert_def.label}.pem"
                pem_file.write_text(pem.strip() + "\n")
                click.echo(f"Wrote 0x{cert_id_int:04x} to {pem_file}")
            elif bundle:
                pem_file = Path(bundle)
                with open(pem_file, "a") as f:
                    f.write(pem.strip() + "\n")
                click.echo(f"Appended 0x{cert_id_int:04x} to {pem_file}")
            else:
                click.echo(pem)

        click_echo_colored_commands("To view certificate details, use:\n`openssl crl2pkcs7 -nocrl -certfile <CERT_FILE.pem> | openssl  pkcs7 -print_certs | openssl x509 -text -noout`")


    if use_default_admin:
        with open_hsm_session_with_default_admin(ctx) as (conf, ses):
            do_it(conf, ses)
    else:
        with open_hsm_session_with_yubikey(ctx) as (conf, ses):
            do_it(conf, ses)

# ---------------

def create_certs_impl(ctx: click.Context, all_certs: bool, dry_run: bool, cert_ids: tuple):
    """
    Create certificates on a YubiHSM2, based on the configuration file and CLI arguments.
    """
    conf = ctx.obj['config']
    dev_serial = ctx.obj['devserial']

    # Enumerate all certificate definitions in the config
    scid_to_opq_def: dict[KeyID, OpaqueObject] = {}
    scid_to_x509_def: dict[KeyID, X509Cert] = {}

    for x in find_config_items_of_class(conf, X509Cert):
        assert isinstance(x, X509Cert)
        for opq in x.signed_certs:
            scid_to_opq_def[opq.id] = opq
            scid_to_x509_def[opq.id] = x

    def _selected_defs() -> list[OpaqueObject]:
        # Based on cli arguments, select the certificates to create
        selected: list[OpaqueObject] = []
        if all_certs:
            selected = list(scid_to_opq_def.values())
        else:
            try:
                cert_ids_int = [int(id.replace("0x", ""), 16) for id in cert_ids]
                selected = [scid_to_opq_def[id] for id in cert_ids_int if id in scid_to_opq_def]
                missing = [f"0x{id:04x}" for id in (set(cert_ids_int) - set(scid_to_opq_def.keys()))]
                if missing:
                    raise click.ClickException(f"Error: Certificate ID(s) not found: {missing}")
            except ValueError:
                raise click.ClickException("Invalid certificate ID(s) specified. Must be in hex format (e.g. 0x1234).")
        return selected

    def _do_it(conf: HSMConfig, ses: AuthSession|None):
        creation_order = topological_sort_x509_cert_defs( _selected_defs())
        id_to_cert_obj: dict[KeyID, x509.Certificate] = {}

        # Create the certificates in topological order
        for cd in creation_order:
            x509_info = merge_x509_info_with_defaults(scid_to_x509_def[cd.id].x509_info, conf)
            issuer = scid_to_opq_def[cd.sign_by] if cd.sign_by and cd.sign_by != cd.id else None
            click.echo(f"Creating 0x{cd.id:04x}: '{cd.label}' ({f"signed by: '{issuer.label}'" if issuer else 'self-signed'})")
            click.echo("    " + display_x509_info(x509_info).replace("\n", "\n    "))

            if not dry_run:
                assert isinstance(ses, AuthSession)

                x509_def = scid_to_x509_def[cd.id]
                key = ses.get_object(x509_def.key.id, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
                assert isinstance(key, yubihsm.objects.AsymmetricKey)

                # If the certificate is signed by another certificate, get the issuer cert and key
                issuer_cert = None
                issuer_key = None

                if cd.sign_by and cd.sign_by != cd.id:
                    issuer_cert = id_to_cert_obj.get(cd.sign_by)
                    if not issuer_cert:
                        # Issuer cert was not created on this run, try to load it from the HSM
                        issuer_hsm_obj = ses.get_object(cd.sign_by, yubihsm.defs.OBJECT.OPAQUE)
                        assert isinstance(issuer_hsm_obj, yubihsm.objects.Opaque)
                        if not hsm_obj_exists(issuer_hsm_obj):
                            raise click.ClickException(f"ERROR: Certificate 0x{cd.sign_by:04x} not found in HSM. Create it first, to sign 0x{cd.id:04x}.")
                        issuer_cert = issuer_hsm_obj.get_certificate()

                    # Get a HSM-backed key (adapter) for the issuer cert
                    key_id = scid_to_x509_def[cd.sign_by].key.id
                    key_obj = ses.get_object(key_id, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
                    assert isinstance(key_obj, yubihsm.objects.AsymmetricKey)
                    if not hsm_obj_exists(key_obj):
                        raise click.ClickException(f"ERROR: Key 0x{key_id:04x} not found in HSM. Create it first, to sign 0x{cd.id:04x}.")
                    issuer_key = make_private_key_adapter(key_obj)

                # Create and sign the certificate
                builder = X509CertBuilder(conf, x509_def, key)
                if issuer_cert:
                    assert issuer_key
                    id_to_cert_obj[cd.id] = builder.generate_cross_signed_intermediate_cert([issuer_cert], [issuer_key])[0]
                else:
                    id_to_cert_obj[cd.id] = builder.generate_self_signed_cert()

        # Put the certificates into the HSM
        for cd in creation_order:
            if not dry_run:
                assert isinstance(ses, AuthSession)
                hsm_obj = ses.get_object(cd.id, yubihsm.defs.OBJECT.OPAQUE)
                assert isinstance(hsm_obj, yubihsm.objects.Opaque)
                if confirm_and_delete_old_yubihsm_object_if_exists(dev_serial, hsm_obj, abort=False):
                    hsm_obj.put_certificate(
                        session = ses,
                        object_id = cd.id,
                        label = cd.label,
                        domains = conf.get_domain_bitfield(cd.domains),
                        capabilities = conf.capability_from_names({'exportable-under-wrap'}),
                        certificate = id_to_cert_obj[cd.id])
                    click.echo(f"Certificate 0x{cd.id:04x} created and stored in YubiHSM (serial {dev_serial}).")

    if dry_run:
        click.echo(click.style("DRY RUN. Would create the following certificates:", fg='yellow'))
        _do_it(conf, None)
        click.echo(click.style("End of dry run. NOTHING WAS ACTUALLY DONE.", fg='yellow'))
    else:
        with open_hsm_session_with_default_admin(ctx) as (conf, ses):
            _do_it(conf, ses)
