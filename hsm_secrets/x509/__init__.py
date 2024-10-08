from copy import deepcopy
import re
import click
import datetime
from pathlib import Path
from textwrap import indent
from typing import cast, List, Optional
from cryptography import x509

from yubihsm.core import AuthSession    # type: ignore [import]
import yubihsm.objects    # type: ignore [import]
import yubihsm.defs    # type: ignore [import]

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from hsm_secrets.config import HSMConfig, HSMKeyID, HSMOpaqueObject, X509CA, click_hsm_obj_auto_complete, find_config_items_of_class

from hsm_secrets.utils import HSMAuthMethod, HsmSecretsCtx, cli_confirm, cli_result, cli_warn, confirm_and_delete_old_yubihsm_object_if_exists, open_hsm_session, cli_code_info, pass_common_args, cli_info

from hsm_secrets.x509.cert_builder import X509CertBuilder, sign_hash_algo_for_key
from hsm_secrets.x509.cert_checker import X509IntermediateCACertificateChecker, X509RootCACertificateChecker
from hsm_secrets.x509.def_utils import pretty_x509_info, merge_x509_info_with_defaults, topological_sort_x509_cert_defs
from hsm_secrets.config import HSMKeyID, HSMOpaqueObject, click_hsm_obj_auto_complete
from hsm_secrets.utils import HsmSecretsCtx, cli_info, cli_warn, open_hsm_session, pass_common_args
from hsm_secrets.x509.def_utils import find_ca_def
from hsm_secrets.key_adapters import Ed25519PrivateKeyHSMAdapter
from hsm_secrets.yubihsm import HSMSession


@click.group()
@click.pass_context
def cmd_x509(ctx: click.Context):
    """General X.509 commands for certs and CRLs"""
    ctx.ensure_object(dict)

@cmd_x509.group('cert')
def cmd_x509_cert():
    """On-HSM certificate management

    The YubiHSM2 can store and manage X.509 certificates, and sign them with
    private keys stored on the device. These commands allow you to create and
    retrieve certificates from the HSM. Their corresponding private keys must
    in the HSM already.
    """
    pass

@cmd_x509.group('crl')
def cmd_x509_crl():
    """Certificate Revocation List management

    These commands allow you to create, update, and display information about CRLs.
    They operate on PEM files, and require the CA certificate to be present in the HSM.
    Revoked certificates are specified by serial number only - you don't need to have the
    actual certificate at hand to revoke it.
    """
    pass

# ---------------

@cmd_x509_cert.command('create')
@pass_common_args
@click.option('--all', '-a', 'all_certs', is_flag=True, help="Create all certificates")
@click.option("--dry-run", "-n", is_flag=True, help="Dry run (do not create certificates)")
@click.argument('certs', nargs=-1, type=str, metavar='<id|label>...', shell_complete=click_hsm_obj_auto_complete(HSMOpaqueObject))
def create_cert_cmd(ctx: HsmSecretsCtx, all_certs: bool, dry_run: bool, certs: tuple):
    """Create certificate(s) on the HSM

    Specified certificates will be created in topological order, so that
    any dependencies are created first.
    """
    if not all_certs and not certs:
        raise click.ClickException("Error: No certificates specified for creation.")
    x509_create_certs(ctx, all_certs, dry_run, certs)

# ---------------

@cmd_x509_cert.command('get')
@pass_common_args
@click.option('--all', '-a', 'all_certs', is_flag=True, help="Get all certificates")
@click.option('--outdir', '-o', type=click.Path(), required=False, help="Write PEMs into files here")
@click.option('--bundle', '-b', type=click.Path(), required=False, help="Write a single PEM bundle file")
@click.argument('certs', nargs=-1, type=str, metavar='<id|label>...', shell_complete=click_hsm_obj_auto_complete(HSMOpaqueObject))
def get_cert_cmd(ctx: HsmSecretsCtx, all_certs: bool, outdir: str|None, bundle: str|None, certs: tuple):
    """Get certificate(s) from the HSM

    You can specify multiple IDs/labels to get multiple certificates,
    or use the --all flag to get all certificates defined in the config.
    Specify --bundle to get a single PEM file with all selected certificates.
    """
    if outdir and bundle:
        raise click.ClickException("Error: --outdir and --bundle options are mutually exclusive.")

    all_cert_defs: list[HSMOpaqueObject] = find_config_items_of_class(ctx.conf, HSMOpaqueObject)
    selected_certs = all_cert_defs if all_certs else [ctx.conf.find_def(id, HSMOpaqueObject) for id in certs]
    if not selected_certs:
        raise click.ClickException("Error: No certificates selected.")

    for cd in selected_certs:
        cli_info(f"- Fetching PEM for 0x{cd.id:04x}: '{cd.label}'", err=True)
    cli_info("", err=True)

    with open_hsm_session(ctx) as ses:
        pem_file = None
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

        if pem_file:
            cli_code_info(f"To view certificate, use:\n`openssl crl2pkcs7 -nocrl -certfile '{pem_file}' | openssl  pkcs7 -print_certs | openssl x509 -text -noout`")

# ---------------

def x509_create_certs(ctx: HsmSecretsCtx, all_certs: bool, dry_run: bool, cert_ids: tuple, skip_existing: bool = False):
    """
    Create certificates on a YubiHSM2, based on the configuration file and CLI arguments.
    Performs a topological sort of the certificates to ensure that any dependencies are created first.
    """
    # Enumerate all certificate definitions in the config
    scid_to_opq_def: dict[HSMKeyID, HSMOpaqueObject] = {}
    scid_to_ca: dict[HSMKeyID, X509CA] = {}

    for x in find_config_items_of_class(ctx.conf, X509CA):
        assert isinstance(x, X509CA)
        for opq in x.signed_certs:
            scid_to_opq_def[opq.id] = opq
            scid_to_ca[opq.id] = x

    def _do_it(ses: HSMSession|None):
        selected_defs = list(scid_to_opq_def.values()) if all_certs \
            else [ctx.conf.find_def(id, HSMOpaqueObject) for id in cert_ids]

        creation_order = topological_sort_x509_cert_defs(selected_defs)
        id_to_cert_obj: dict[HSMKeyID, x509.Certificate] = {}
        existing_cert_ids = set()
        cert_issues: list[tuple[HSMOpaqueObject, list]] = []

        # Create the certificates in topological order
        for cd in creation_order:
            if skip_existing:
                if ses and ses.object_exists(cd):
                    existing_cert_ids.add(cd.id)
                    continue

            x509_info = merge_x509_info_with_defaults(scid_to_ca[cd.id].x509_info, ctx.conf)
            issuer = scid_to_opq_def[cd.sign_by] if cd.sign_by and cd.sign_by != cd.id else None
            signer = f"signed by: '{issuer.label}'" if issuer else 'self-signed'

            # Get CRL distribution points from issuer (if not self-signed)
            crl_url_list = []
            if issuer:
                issuer_ca_def = find_ca_def(ctx.conf, issuer.id)
                assert issuer_ca_def, f"CA cert ID not found: 0x{issuer.id:04x}"
                crl_url_list = issuer_ca_def.crl_distribution_points

            cli_info(f"\nCreating 0x{cd.id:04x}: '{cd.label}' ({signer})")
            cli_info(indent(pretty_x509_info(x509_info), "    "))

            if not dry_run:
                assert ses
                x509_ca = scid_to_ca[cd.id]

                # If the certificate is signed by another certificate, get the issuer cert and key
                issuer_cert, issuer_key = None, None
                if cd.sign_by and cd.sign_by != cd.id:
                    issuer_cert = id_to_cert_obj.get(cd.sign_by)
                    if not issuer_cert:
                        # Issuer cert was not created on this run, try to load it from the HSM
                        issuer_def = scid_to_opq_def[cd.sign_by]
                        if not ses.object_exists(issuer_def):
                            raise click.ClickException(f"ERROR: Certificate 0x{cd.sign_by:04x} not found in HSM. Create it first to sign 0x{cd.id:04x}.")
                        issuer_cert = ses.get_certificate(issuer_def)

                    sign_key_def = scid_to_ca[cd.sign_by].key
                    if not ses.object_exists(sign_key_def):
                        raise click.ClickException(f"ERROR: Key 0x{sign_key_def.id:04x} not found in HSM. Create it first to sign 0x{cd.id:04x}.")
                    issuer_key = ses.get_private_key(sign_key_def)

                # Create and sign the certificate
                assert x509_ca.x509_info, "X.509 certificate definition is missing x509_info"
                priv_key = ses.get_private_key(x509_ca.key)
                builder = X509CertBuilder(ctx.conf, x509_ca.x509_info, priv_key)
                if issuer_cert:
                    assert issuer_key
                    id_to_cert_obj[cd.id] = builder.build_and_sign(issuer_cert, issuer_key, crl_url_list)
                    # NOTE: We'll assume all signed certs on HSM are CA -- fix this if storing leaf certs for some reason
                    issues = X509IntermediateCACertificateChecker(id_to_cert_obj[cd.id]).check_and_show_issues()
                    cert_issues.append((cd, issues))
                else:
                    id_to_cert_obj[cd.id] = builder.generate_and_self_sign()
                    cli_info(f"Self-signed certificate created; assuming it's a root CA for checks...")
                    issues = X509RootCACertificateChecker(id_to_cert_obj[cd.id]).check_and_show_issues()
                    cert_issues.append((cd, issues))

        # Put the certificates into the HSM
        for cd in creation_order:
            if skip_existing and cd.id in existing_cert_ids:
                continue
            if not dry_run:
                assert isinstance(ses, HSMSession)
                if confirm_and_delete_old_yubihsm_object_if_exists(ses, cd.id, yubihsm.defs.OBJECT.OPAQUE, abort=False):
                    ses.put_certificate(cd, id_to_cert_obj[cd.id])
                    cli_info(f"Certificate 0x{cd.id:04x} stored in YubiHSM {ctx.hsm_serial}.")

        # Show any issues found during certificate creation
        for cd, issues in cert_issues:
            if issues:
                cli_warn(f"\n-- Check results for certificate 0x{cd.id:04x} ({cd.label}) --")
                X509RootCACertificateChecker.show_issues(issues, cd.label)

    if dry_run:
        cli_warn("DRY RUN. Would create the following certificates:")
        _do_it(None)
        cli_warn("End of dry run. NOTHING WAS REALLY DONE.")
    else:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN) as ses:
            _do_it(ses)

# --------------- CRL commands ---------------

@cmd_x509_crl.command('init')
@pass_common_args
@click.argument('cacerts', nargs=-1, type=str, metavar='<cacert-id|label>...', shell_complete=click_hsm_obj_auto_complete(HSMOpaqueObject))
@click.option('--out', '-o', required=False, type=click.Path(dir_okay=False), help="Output CRL file (default: from config)")
@click.option('--period', '-v', type=int, default=None, help="CRL update period in days")
@click.option('--this-update', type=click.DateTime(), default=None, help="This Update date (default: now)")
@click.option('--next-update', type=click.DateTime(), default=None, help="Next Update date (default: cert's expiry date)")
@click.option('--crl-number', type=int, default=1, help="CRL Number (default: 1)")
@click.option('--force', '-f', is_flag=True, default=False, help="Overwrite existing CRL file(s)")
def init_crl(ctx: HsmSecretsCtx, cacerts: list[str], out: str|None, period: int|None, this_update: datetime.datetime|None,
             next_update: datetime.datetime|None, crl_number: int, force: bool):
    """Create empty CRL for a CA

    Given CA certificate must be present in the HSM, as it will be fetched and
    its subject used as the new CRL's issuer name. (For cross-signed CAs, pick any of the
    certs, as their subject will be the same.)

    Options `--validity` and `--next-update` are mutually exclusive.
    If neither is specified, the next update will be set to the CA cert's expiry date.
    Clients may check the CRL more frequently than the next update period, but it's not
    guaranteed, so if your use case has frequent revocations, set a shorter period.
    """
    if (period is not None) and (next_update is not None):
        raise click.ClickException("Error: --period and --next-update options are mutually exclusive.")

    if len(cacerts) > 1 and out is not None:
        raise click.ClickException("Error: Output file name option is not supported for multiple CA certs.")

    defs: list[tuple[HSMOpaqueObject, X509CA, Path]] = []
    for ca in cacerts:

        # Find CA definition for the given cert ID
        ca_cert_def = ctx.conf.find_def(ca, HSMOpaqueObject)
        ca_def = find_ca_def(ctx.conf, ca_cert_def.id)
        if not ca_def:
            raise click.ClickException(f"CA cert ID not found: 0x{ca_cert_def.id:04x}")

        # Determine output file name
        if not out:
            if not ca_def.crl_distribution_points:
                raise click.ClickException(f"Error: CRL DP not set for CA '{ca_cert_def.label}' (0x{ca_cert_def.id:04x}), cannot determine output file.")
            outfile = Path(ca_def.crl_distribution_points[0].split('/')[-1])
        else:
            outfile = Path(out)

        if outfile.exists() and not force:
            cli_confirm(f"Overwrite the existing file: {outfile}?", abort=True)
        defs.append((ca_cert_def, ca_def, outfile))

    # Create the CRLs
    with open_hsm_session(ctx) as ses:
        for ca_cert_def, ca_def, outfile in defs:
            ca_cert = ses.get_certificate(ca_cert_def)
            ca_key = ses.get_private_key(ca_def.key)

            this_update = this_update or datetime.datetime.now(datetime.UTC)

            if next_update is None:
                if period is not None:
                    next_update = this_update + datetime.timedelta(days=period)
                else:
                    next_update = ca_cert.not_valid_after_utc - datetime.timedelta(minutes=1)

            builder = x509.CertificateRevocationListBuilder()
            builder = builder.issuer_name(ca_cert.subject)
            builder = builder.last_update(this_update)
            builder = builder.next_update(next_update)
            builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)

            crl = builder.sign(ca_key, sign_hash_algo_for_key(ca_key))

            crl_pem = crl.public_bytes(encoding=serialization.Encoding.PEM)
            outfile.write_bytes(crl_pem)

            cli_code_info(f"Initialized CRL for `{ca_def.key.label}` (0x{ca_def.key.id:04x}), written to: `./{str(outfile)}`")

# ---------------

@cmd_x509_crl.command('update')
@pass_common_args
@click.argument('crl_file', type=click.Path(exists=True, dir_okay=False))
@click.option('--ca', '-c', required=True, help="CA cert ID or label to sign the CRL", shell_complete=click_hsm_obj_auto_complete(HSMOpaqueObject))
@click.option('--out', '-o', type=click.Path(dir_okay=False), help="Output updated CRL file (default: overwrite input)")
@click.option('--validity', '-v', default=None, help="New CRL validity period in days")
@click.option('--add', '-a', multiple=True, help="Add revoked cert: serial_number:date:reason")
@click.option('--remove', '-r', multiple=True, help="Remove revoked cert: serial_number")
def update_crl(ctx: HsmSecretsCtx, crl_file: str, ca: str, out: str, validity: Optional[int],
               add: List[str], remove: List[str]):
    """Update an existing CRL

    Add or remove revoked certificates, and update the CRL validity period.

    Example: '--add 123456:2022-12-31:privilegeWithdrawn', where
    the date is in ISO format (YYYY-MM-DD) and the reason is one of:
    'unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded',
    'cessationOfOperation', 'certificateHold', 'privilegeWithdrawn', 'aACompromise', 'removeFromCRL'.

    If you omit the date and reason, the current date and 'unspecified' will be used.

    Example: '--remove 123456'.

    Use '0x' prefix for serial numbers in hex.

    Remove and add commands can be specified multiple times.
    """
    ca_cert_def = ctx.conf.find_def(ca, HSMOpaqueObject)
    ca_x509_def = find_ca_def(ctx.conf, ca_cert_def.id)
    assert ca_x509_def, f"CA cert ID not found: 0x{ca_cert_def.id:04x}"

    with open_hsm_session(ctx) as ses:
        ca_cert = ses.get_certificate(ca_cert_def)
        ca_key = ses.get_private_key(ca_x509_def.key)

        # Read existing CRL
        existing_crl = x509.load_pem_x509_crl(Path(crl_file).read_bytes())

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)

        # Copy existing revoked certificates
        for rev_cert in existing_crl:
            if rev_cert.serial_number in [int(serial) for serial in remove]:
                cli_info(f"- Removing previous revokation: {rev_cert.serial_number}")
                continue
            builder = builder.add_revoked_certificate(rev_cert)

        if len(remove) != len(existing_crl) - len(builder._revoked_certificates):
            cli_warn("Warning: Some revoked certificates to remove were not found in the existing CRL")

        # Add new ones
        for cert_info in add:

            parts = cert_info.split(':')
            if len(parts) == 3:
                serial, date, reason = parts
            elif len(parts) == 2:
                serial, date = parts
                reason = 'unspecified'
            elif len(parts) == 1:
                serial = parts[0]
                date = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d')
                reason = 'unspecified'
            else:
                raise click.ClickException(f"Error: Invalid revocation info: {cert_info}")

            serial = serial.lower()
            if serial.startswith('0x') or (re.match(r'^[0-9a-fA-F]+$', serial) and not serial.isdigit()):
                serial = str(int(serial.lstrip('0x'), 16))
            elif not serial.isdigit():
                raise click.ClickException(f"Error: Invalid serial number: {serial}")
            if not (date and date.count('-') == 2):
                raise click.ClickException(f"Error: Invalid date format: {date} (use YYYY-MM-DD)")

            valid_reasons = {flag.value for flag in x509.ReasonFlags}
            if reason not in valid_reasons:
                raise click.ClickException(f"Error: Invalid revocation reason: {reason} - must be one of: {', '.join(valid_reasons)}")

            builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder(
                ).serial_number(int(serial)
                ).revocation_date(datetime.datetime.fromisoformat(date)
                ).add_extension(x509.CRLReason(x509.ReasonFlags(reason)), critical=False
                ).build())

        # Update CRL number
        new_crl_number = existing_crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number + 1
        builder = builder.add_extension(x509.CRLNumber(new_crl_number), critical=False)

        # Calc new validity
        if validity:
            next_update = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=validity)
        else:
            if not existing_crl.next_update_utc:
                raise click.ClickException("Error: No validity period specified and no existing CRL next_update")
            if last_update := existing_crl.next_update_utc:
                next_update = last_update + (existing_crl.next_update_utc - last_update)
                cli_info(f"Extending CRL validity to: {next_update} (same duration as previous)")
            else:
                cli_warn("Warning: Validity time not extended! No last_update in existing CRL, and no new validity period specified.")
                next_update = existing_crl.next_update_utc

        builder = builder.last_update(datetime.datetime.now(datetime.UTC))
        builder = builder.next_update(next_update)

        # Sign the CRL
        crl = builder.sign(ca_key, sign_hash_algo_for_key(ca_key))

        # Write the updated CRL
        out_file = out or crl_file
        crl_pem = crl.public_bytes(encoding=serialization.Encoding.PEM)
        Path(out_file).write_bytes(crl_pem)

        cli_info(f"Updated CRL signed by CA 0x{ca_cert_def.id:04x}")
        cli_info(f"CRL written to: {out_file}")

# ---------------

@cmd_x509_crl.command('show')
@pass_common_args
@click.argument('crl_file', type=click.Path(exists=True, dir_okay=False))
def show_crl(ctx: HsmSecretsCtx, crl_file: str):
    """Display information about a CRL"""
    crl = x509.load_pem_x509_crl(Path(crl_file).read_bytes())

    cli_info(f"CRL Issuer: {crl.issuer.rfc4514_string()}")
    cli_info(f"Last Update: {crl.last_update_utc}")
    cli_info(f"Next Update: {crl.next_update_utc}")

    crl_number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    cli_info(f"CRL Number: {crl_number}")

    cli_info(f"Number of revoked certificates: {len(crl)}")

    if len(crl) > 0:
        cli_info("Revoked Certificates:")
        for cert in crl:
            reason = cert.extensions.get_extension_for_class(x509.CRLReason).value.reason
            cli_info(f"  - Serial: 0x{cert.serial_number:x}, Revoked On: {cert.revocation_date_utc}, Reason: {reason.value}")
