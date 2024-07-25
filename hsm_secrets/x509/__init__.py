from pathlib import Path
from textwrap import indent
from typing import cast
from cryptography import x509

from yubihsm.core import AuthSession    # type: ignore [import]
import yubihsm.objects    # type: ignore [import]
import yubihsm.defs    # type: ignore [import]

from cryptography.hazmat.primitives import serialization
from hsm_secrets.config import HSMConfig, HSMKeyID, HSMOpaqueObject, X509Cert, find_config_items_of_class

from hsm_secrets.utils import HSMAuthMethod, HsmSecretsCtx, cli_result, cli_warn, confirm_and_delete_old_yubihsm_object_if_exists, open_hsm_session, cli_code_info, pass_common_args, cli_info

from hsm_secrets.x509.cert_builder import X509CertBuilder
from hsm_secrets.x509.def_utils import pretty_x509_info, merge_x509_info_with_defaults, topological_sort_x509_cert_defs

import click

from hsm_secrets.key_adapters import make_private_key_adapter
from hsm_secrets.yubihsm import HSMSession


@click.group()
@click.pass_context
def cmd_x509(ctx: click.Context):
    """General X.509 Certificate Management"""
    ctx.ensure_object(dict)

# ---------------

@cmd_x509.command('create')
@pass_common_args
@click.option('--all', '-a', 'all_certs', is_flag=True, help="Create all certificates")
@click.option("--dry-run", "-n", is_flag=True, help="Dry run (do not create certificates)")
@click.argument('cert_ids', nargs=-1, type=str, metavar='<id>...')
def create_cert_cmd(ctx: HsmSecretsCtx, all_certs: bool, dry_run: bool, cert_ids: tuple):
    """Create certificate(s) on the HSM

    ID is a 16-bit hex value (e.g. '0x12af' or '12af').
    You can specify multiple IDs to create multiple certificates,
    or use the --all flag to create all certificates defined in the config.

    Specified certificates will be created in topological order, so that
    any dependencies are created first.
    """
    if not all_certs and not cert_ids:
        raise click.ClickException("Error: No certificates specified for creation.")
    create_certs_impl(ctx, all_certs, dry_run, cert_ids)


@cmd_x509.command('get')
@pass_common_args
@click.option('--all', '-a', 'all_certs', is_flag=True, help="Get all certificates")
@click.option('--outdir', '-o', type=click.Path(), required=False, help="Write PEMs into files here")
@click.option('--bundle', '-b', type=click.Path(), required=False, help="Write a single PEM bundle file")
@click.argument('cert_ids', nargs=-1, type=str, metavar='<id|label>...')
def get_cert_cmd(ctx: HsmSecretsCtx, all_certs: bool, outdir: str|None, bundle: str|None, cert_ids: tuple):
    """Get certificate(s) from the HSM

    You can specify multiple IDs/labels to get multiple certificates,
    or use the --all flag to get all certificates defined in the config.
    Specify --bundle to get a single PEM file with all selected certificates.
    """
    if outdir and bundle:
        raise click.ClickException("Error: --outdir and --bundle options are mutually exclusive.")

    all_cert_defs: list[HSMOpaqueObject] = find_config_items_of_class(ctx.conf, HSMOpaqueObject)
    selected_certs = all_cert_defs if all_certs else [cast(HSMOpaqueObject, ctx.conf.find_def(id, HSMOpaqueObject)) for id in cert_ids]
    if not selected_certs:
        raise click.ClickException("Error: No certificates selected.")

    for cd in selected_certs:
        cli_info(f"- Fetching PEM for 0x{cd.id:04x}: '{cd.label}'")
    cli_info("")

    with open_hsm_session(ctx) as ses:
        for cd in selected_certs:
            pem = ses.get_certificate(cd).public_bytes(encoding=serialization.Encoding.PEM).decode()
            if outdir:
                pem_file = Path(outdir) / f"{cd.label}.pem"
                pem_file.write_text(pem.strip() + "\n")
                cli_info(f"Wrote 0x{cd.id:04x} to {pem_file}")
            elif bundle:
                pem_file = Path(bundle)
                with open(pem_file, "a") as f:
                    f.write(pem.strip() + "\n")
                cli_info(f"Appended 0x{cd.id:04x} to {pem_file}")
            else:
                cli_result(pem.strip())

        cli_code_info("To view certificate details, use:\n`openssl crl2pkcs7 -nocrl -certfile <CERT_FILE.pem> | openssl  pkcs7 -print_certs | openssl x509 -text -noout`")

# ---------------

def create_certs_impl(ctx: HsmSecretsCtx, all_certs: bool, dry_run: bool, cert_ids: tuple):
    """
    Create certificates on a YubiHSM2, based on the configuration file and CLI arguments.
    Performs a topological sort of the certificates to ensure that any dependencies are created first.
    """
    # Enumerate all certificate definitions in the config
    scid_to_opq_def: dict[HSMKeyID, HSMOpaqueObject] = {}
    scid_to_x509_def: dict[HSMKeyID, X509Cert] = {}

    for x in find_config_items_of_class(ctx.conf, X509Cert):
        assert isinstance(x, X509Cert)
        for opq in x.signed_certs:
            scid_to_opq_def[opq.id] = opq
            scid_to_x509_def[opq.id] = x

    def _do_it(ses: HSMSession|None):
        selected_defs = list(scid_to_opq_def.values()) if all_certs \
            else [cast(HSMOpaqueObject, ctx.conf.find_def(id, HSMOpaqueObject)) for id in cert_ids]

        creation_order = topological_sort_x509_cert_defs(selected_defs)
        id_to_cert_obj: dict[HSMKeyID, x509.Certificate] = {}

        # Create the certificates in topological order
        for cd in creation_order:
            x509_info = merge_x509_info_with_defaults(scid_to_x509_def[cd.id].x509_info, ctx.conf)
            issuer = scid_to_opq_def[cd.sign_by] if cd.sign_by and cd.sign_by != cd.id else None
            cli_info(f"Creating 0x{cd.id:04x}: '{cd.label}' ({f"signed by: '{issuer.label}'" if issuer else 'self-signed'})")
            cli_info(indent(pretty_x509_info(x509_info), "    "))

            if not dry_run:
                assert ses
                x509_def = scid_to_x509_def[cd.id]

                # If the certificate is signed by another certificate, get the issuer cert and key
                issuer_cert, issuer_key = None, None
                if cd.sign_by and cd.sign_by != cd.id:
                    issuer_cert = id_to_cert_obj.get(cd.sign_by)
                    if not issuer_cert:
                        # Issuer cert was not created on this run, try to load it from the HSM
                        if not ses.object_exists(cd):
                            raise click.ClickException(f"ERROR: Certificate 0x{cd.sign_by:04x} not found in HSM. Create it first, to sign 0x{cd.id:04x}.")
                        issuer_cert = ses.get_certificate(cd)

                    sign_key_def = scid_to_x509_def[cd.sign_by].key
                    if not ses.object_exists(sign_key_def):
                        raise click.ClickException(f"ERROR: Key 0x{sign_key_def.id:04x} not found in HSM. Create it first, to sign 0x{cd.id:04x}.")
                    issuer_key = ses.get_private_key(sign_key_def)

                # Create and sign the certificate
                assert x509_def.x509_info, "X.509 certificate definition is missing x509_info"
                priv_key = ses.get_private_key(x509_def.key)
                builder = X509CertBuilder(ctx.conf, x509_def.x509_info, priv_key)
                if issuer_cert:
                    assert issuer_key
                    id_to_cert_obj[cd.id] = builder.generate_cross_signed_intermediate_cert([issuer_cert], [issuer_key])[0]
                else:
                    id_to_cert_obj[cd.id] = builder.generate_self_signed_cert()

        # Put the certificates into the HSM
        for cd in creation_order:
            if not dry_run:
                assert isinstance(ses, HSMSession)
                if confirm_and_delete_old_yubihsm_object_if_exists(ses, cd.id, yubihsm.defs.OBJECT.OPAQUE, abort=False):
                    ses.put_certificate(cd, id_to_cert_obj[cd.id])
                    cli_info(f"Certificate 0x{cd.id:04x} created and stored in YubiHSM (serial {ctx.hsm_serial}).")

    if dry_run:
        cli_warn("DRY RUN. Would create the following certificates:")
        _do_it(None)
        cli_warn("End of dry run. NOTHING WAS REALLY DONE.")
    else:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
            _do_it(ses)
