import datetime
from pathlib import Path
import sqlite3
from typing import cast
import click

from hsm_secrets.config import HSMAuditSettings, HSMConfig, YubiHsm2AuditMode, YubiHsm2Command
from hsm_secrets.log import log_db, yhsm_log
from hsm_secrets.utils import HSMAuthMethod, HsmSecretsCtx, cli_code_info, cli_confirm, cli_error, cli_info, cli_result, open_hsm_session, pass_common_args


@click.group()
@click.pass_context
def cmd_log(ctx: click.Context):
    """YubiHSM2 log / audit commands"""
    ctx.ensure_object(dict)


@cmd_log.command('apply-settings')
@pass_common_args
@click.option('--alldevs', '-a', is_flag=True, help="Set on all devices")
@click.option('--force', is_flag=True, help="Don't ask for confirmation before setting")
def apply_audit_settings(ctx: HsmSecretsCtx, alldevs: bool, force: bool):
    """Apply log settings from config to HSM

    Apply the audit/logging settings from configuration file to the YubiHSM(s).
    """
    conf_settings = ctx.conf.admin.audit
    conf_settings.apply_defaults()

    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        with open_hsm_session(ctx, HSMAuthMethod.DEFAULT_ADMIN, serial) as ses:
            cli_info(f"Checking audit settings on device {serial}...")
            cur_settings, _unknown_audits = ses.get_audit_settings()
            mismatches_str = _check_and_format_audit_conf_differences(cur_settings, conf_settings)
            if not mismatches_str:
                cli_info(" └– Already ok. Audit settings match the config file.")
                continue
            else:
                cli_info(" └– Mismatching audit commands (current -> new):")
                cli_info(mismatches_str)
                if not force and not cli_confirm("Do you want to set the audit settings to match the configuration?", default=False):
                    cli_info(f"    └– Skipping device {serial}.")
                else:
                    # Remove any 'fixed' commands from the current settings before applying.
                    # The YubiHSM2 command will fail otherwise.
                    without_fixed: dict[YubiHsm2Command, YubiHsm2AuditMode] = {k:v for k,v in conf_settings.command_logging.items() if cur_settings.command_logging.get(k) != 'fixed'}
                    to_apply = HSMAuditSettings(
                        forced_audit = conf_settings.forced_audit,
                        default_command_logging = conf_settings.default_command_logging,
                        command_logging = without_fixed)
                    ses.set_audit_settings(to_apply)
                    cli_info("    └– Audit settings applied.")


def _check_and_format_audit_conf_differences(cur_settings: HSMAuditSettings, conf_settings: HSMAuditSettings, raise_if_fixed_change = True) -> str|None:
    """
    Check the audit settings in the YubiHSM against the configuration file.
    Returns a formatted string with the differences, or None if there are none.

    Raises ValueError if a fixed command is set in the device and the configuration wants to change it,
    and `raise_if_fixed_change` is True.
    """
    mismatches: dict[str, tuple[YubiHsm2AuditMode|None, YubiHsm2AuditMode|None]] = {}

    if cur_settings.forced_audit != conf_settings.forced_audit:
        mismatches['<FORCED AUDIT>'] = (cur_settings.forced_audit, conf_settings.forced_audit)

    for k, new_v in conf_settings.command_logging.items():
        cur_v = cur_settings.command_logging.get(cast(YubiHsm2Command, k), None)
        if cur_v != new_v:
            mismatches[k] = (cur_v, new_v)
            if cur_v == 'fixed' and raise_if_fixed_change:
                raise ValueError(f"Command '{k}' is set to 'fixed' in the device. Cannot change it without resetting the HSM.")

    if not mismatches:
        return None
    return '\n'.join([f"    - {mk.ljust(30)} {cv} -> {nv}" for mk, (cv, nv) in sorted(mismatches.items())])


# ---------------


@cmd_log.command('fetch')
@pass_common_args
@click.argument('db_path', type=click.Path(exists=False), required=False)
@click.option('--clear', '-c', is_flag=True, help="Clear the log entries after fetching")
@click.option('--no-verify', '-n', is_flag=True, help="Ignore log integrity verification failures")
@click.option('--alldevs', '-a', is_flag=True, help="Fetch from all devices")
@click.option('--force-clear', is_flag=True, help="Force clearing even if no new entries fetched")
def log_fetch(ctx: HsmSecretsCtx, db_path: str, clear: bool, no_verify: bool, alldevs: bool, force_clear: bool):
    """
    Fetch log entries from HSM and store in SQLite DB

    This command retrieves new log entries from the YubiHSM device and stores them in the specified SQLite database.
    If the database doesn't exist, it will be created.

    Each new entry is verified against previous one to ensure log integrity. Failure aborts the process.

    If --clear is specified, log entries will be cleared from the HSM after they are successfully verified and stored.
    """
    config: HSMConfig = ctx.conf
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        if alldevs:
            cli_info(f"----- Fetching entries from device {serial} -----")
        with open_hsm_session(ctx, HSMAuthMethod.PASSWORD, device_serial=serial) as session:
            new_log_data = session.get_log_entries()
            hsm_serial = session.get_serial()

            if not db_path:
                cli_info("No database path specified. Using in-memory database.")
                if clear:
                    raise click.ClickException("Refusing to --clear log entries from device without a persistent database.")
                db_path = ':memory:'

            with sqlite3.connect(db_path) as conn:
                log_db.init_db(conn)
                conn.row_factory = sqlite3.Row

                new, skipped = 0, 0
                for entry in new_log_data.entries:
                    try:
                        if not log_db.insert_log_entry(conn, hsm_serial, entry, datetime.datetime.now(), no_verify, lambda id: yhsm_log.find_info(id, config)):
                            cli_info(f"- Log entry {entry.number} already in DB, skipping.")
                            skipped += 1
                            continue
                        if e := log_db.get_last_log_entry(conn, hsm_serial):
                            cli_info(yhsm_log.summarize_log_entry(e))
                        new += 1
                    except ValueError as e:
                        raise click.ClickException(f"Error inserting entry {entry.number}: {str(e)}")

                cli_info(f"\nFetched {new+skipped} entries. Stored {new} in '{db_path}', skipped {skipped} pre-existing.")

                if clear and (new > 0 or force_clear):
                    last_entry = log_db.get_last_log_entry(conn, hsm_serial)
                    if last_entry:
                        session.free_log_entries(last_entry["entry_number"])
                        cli_info(f"Cleared log entries up to {last_entry['entry_number']}")
                    else:
                        cli_info("No entries to clear")
                elif clear:
                    cli_info("No new entries fetched; skipping clear operation.")


@cmd_log.command('review')
@pass_common_args
@click.argument('db_path', type=click.Path(exists=True), required=True)
@click.option('--alldevs', '-a', is_flag=True, help="Review log entries for all devices")
@click.option('--start-num', '-s', type=int, help="Start entry number", required=False)
@click.option('--end-num', '-e', type=int, help="End entry number", required=False)
@click.option('--start-id', '-S', type=int, help="Start row ID", required=False)
@click.option('--end-id', '-E', type=int, help="End row ID", required=False)
@click.option('--jsonl', is_flag=True, help="In JSONL format, not summary")
def log_review(ctx: HsmSecretsCtx, db_path: str, alldevs: bool, start_num: int|None, end_num: int|None, start_id: int|None, end_id: int|None, jsonl: bool):
    """
    Review log entries stored in DB

    This command retrieves log entries from the specified SQLite database and displays them in a human-readable format.

    YubiHSM log entry numbers wrap around at 2^16, so use the row ID to specify a range that crosses the wrap-around point.
    """
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        for serial in hsm_serials:
            if alldevs:
                cli_info(f"# ----- Entries for device {serial} -----")
            for e in log_db.get_log_entries(conn, int(serial)):
                if (start_num and e['entry_number'] < start_num) or (end_num and e['entry_number'] > end_num) or \
                (start_id and e['id'] < start_id) or (end_id and e['id'] > end_id):
                        continue
                if jsonl:
                    cli_result(yhsm_log.export_to_jsonl(e, pretty=False, with_summary=False))
                else:
                    cli_result(yhsm_log.summarize_log_entry(e))


@cmd_log.command('merge')
@pass_common_args
@click.option('--out', '-o', type=click.Path(dir_okay=False, exists=False), required=True)
@click.argument('db_paths', type=click.Path(exists=True), nargs=-1)
def log_merge(ctx: HsmSecretsCtx, out: str, db_paths: list[str]):
    """
    Merge multiple log databases into one

    Initialize `out` as a new SQLite database and merge all log
    entries from the specified databases into it.
    """
    if out in db_paths:
        raise click.ClickException("Output database cannot be the same as any of the input databases")

    with sqlite3.connect(out) as out_conn:
        log_db.init_db(out_conn)
        out_conn.row_factory = sqlite3.Row

        all_rows = []
        for db_path in db_paths:
            with sqlite3.connect(db_path) as conn:
                conn.row_factory = sqlite3.Row
                for serial in log_db.get_hsm_serials(conn):
                    for row in log_db.get_log_entries(conn, serial):
                        all_rows.append(row)

        log_db.insert_rows(out_conn, all_rows)
        cli_code_info(f"Merged {len(all_rows)} log entries from {len(db_paths)} databases into `{out}`")


@cmd_log.command('verify-all')
@pass_common_args
@click.argument('db_path', type=click.Path(exists=True))
@click.option('--initial-num', '-i', type=int, help="Entry number to treat as first in the chain", default=1)
@click.option('--alldevs', '-a', is_flag=True, help="Verify all devices")
def log_verify_all(ctx: HsmSecretsCtx, db_path: str, initial_num: int, alldevs: bool):
    """
    Verify the entire (previously stored) log chain

    This command checks the integrity of the log chain stored in the database for the specified HSM serial number.
    It verifies that each log entry correctly validates against the previous one, ensuring the chain hasn't been tampered with.

    <db_path> : Path to the SQLite database file containing the log entries.
    """
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    for serial in hsm_serials:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            entries = log_db.get_log_entries(conn, int(serial))

            try:
                yhsm_log.verify_log_chain(entries, initial_num)
                cli_info("Log chain verified successfully")
            except ValueError as e:
                cli_info(f"Log chain verification failed: {str(e)}")
                exit(1)


@cmd_log.command('export')
@pass_common_args
@click.argument('db_path', type=click.Path(exists=True))
@click.option('--out', '-o', type=click.File('a', lazy=True), default='-', help="File to append ('-' for stdout)")
@click.option('--restart', '-r', is_flag=True, help="Start exporting from the beginning")
@click.option('--no-summary', is_flag=True, help="Don't include human-readable summary in JSONL output")
@click.option('--alldevs', '-a', is_flag=True, help="Export logs for all devices")
def log_export_jsonl(ctx: HsmSecretsCtx, db_path: str, out, restart: bool, no_summary: bool, alldevs: bool):
    """
    Export new log entries from DB to JSONL format

    The command keeps track of the last exported entry and only exports new entries in subsequent runs.
    This makes it suitable for incremental exports to a log aggregator.
    Each HSM serial number has its own last exported entry ID in the database.

    This command does not connect to the HSM device at all.
    """
    hsm_serials = ctx.conf.general.all_devices.keys() if alldevs else [ctx.hsm_serial]
    with out as fh:
        with sqlite3.connect(db_path) as conn:
            for ser in hsm_serials:
                serial = int(ser)
                if restart:
                    log_db.update_last_exported_id(conn, serial, 0)

                count, last_exported_id = 0, None

                conn.row_factory = sqlite3.Row
                for e in log_db.get_non_exported_log_entries(conn, serial):
                    l = yhsm_log.export_to_jsonl(e, pretty=False, with_summary=not no_summary)
                    fh.write(l + '\n')
                    last_exported_id = e['id']
                    count += 1

                if last_exported_id:
                    log_db.update_last_exported_id(conn, serial, last_exported_id)

                if count:
                    cli_info(f"Exported {count} new entries from database {db_path} to {out.name} for device {serial}")
                else:
                    cli_info(f"No new entries to export for device {serial}")
