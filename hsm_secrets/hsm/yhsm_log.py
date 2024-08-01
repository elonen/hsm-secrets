from dataclasses import astuple
import json
import struct
import datetime
from pathlib import Path
import click
import yubihsm  # type: ignore [import]
from typing import Dict, List, Tuple
from filelock import FileLock, Timeout

from hsm_secrets.config import HSMConfig
from hsm_secrets.utils import cli_info
from hsm_secrets.yubihsm import HSMSession


def read_json_files(jsonfile: str, need_all: bool) -> dict[int, dict]:
    """Read log entries from JSON files.
    Given `jsonfile` is the latest file, and the function checks for
    older files with the same name but with a suffix '.1.json', '.2.json', etc.

    If `need_all` is not set, the function stops reading files as soon as it finds
    a file at least one entry.
    """
    prev_entries = {}
    file_i = 0
    while True:
        p = Path(jsonfile) if file_i == 0 else Path(jsonfile).with_suffix(f".{file_i}.json")
        if file_i > 0 and not p.exists():
            break
        if p.exists():
            cli_info(f"Reading old entries from '{p}'...")
            with p.open('r') as fh:
                data = json.load(fh)
                for k, v in data.items():
                    assert isinstance(int(k), int), "Entry number must be an integer."
                    assert isinstance(v, dict), "Entry data must be a dictionary."
                    if k in prev_entries:
                        raise ValueError(f"Duplicate entry number '{k}' in file {p}")
                    assert isinstance(v.get('data'), str), "Missing or invalid 'data' field in entry."
                    assert isinstance(v.get('fetch_time'), str), "Missing or invalid 'fetch_time' field in entry."
                    assert isinstance(v.get('hsm_serial'), int), "Missing or invalid 'hsm_serial' field in entry."
                    prev_entries[int(k)] = v
        if len(prev_entries) > 0 and not need_all:
            break
        file_i += 1
    return prev_entries



def decode_log_entry_to_dict(entry: yubihsm.core.LogEntry, conf: HSMConfig, hsm_serial: int) -> dict:
    """
    Convert a log entry to a JSON-serializable dictionary.
    """
    def find_info(id: int) -> str:
        try:
            if id in [0, 0xffff]:
                return f'0x{id:04x}: -'
            kd = conf.find_def(id)
            return f"0x{id:04x}: '{kd.label}' ({kd.__class__.__name__})"
        except KeyError:
            return f"0x{id:04x} (UNKNOWN)"

    return {
        "data": (struct.pack(entry.FORMAT, *astuple(entry))).hex(),
        "hsm_serial": hsm_serial,
        "fetch_time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "_info": {
            "cmd": f'{entry.command.name} ({entry.command.value})',
            "len": entry.length,
            "ses_key": find_info(entry.session_key),
            "tgt_key": find_info(entry.target_key),
            "2nd_key": find_info(entry.second_key),
            "result": entry.result,
            "tick": entry.tick,
        }
    }


def verify_log_chain(prev_entries: dict, initial_num: int) -> yubihsm.core.LogEntry|None:
    """
    Verify the log chain from the initial number to the last entry in the JSON file.
    :return: The last log entry in the chain.
    :raises: click.ClickException if the chain is broken.
    """
    if initial_num not in prev_entries:
        raise click.ClickException(f"Initial entry {initial_num} not found in the JSON file. Audit chain broken.")
    n = initial_num
    prev = None
    while n in prev_entries:
        ld_bytes = bytes.fromhex(prev_entries[n]['data'])
        ld = yubihsm.core.LogEntry.parse(ld_bytes)
        if prev:
            if prev_entries[n]['hsm_serial'] != prev_entries[n-1]['hsm_serial']:
                raise click.ClickException(f"Log entry {n} has different HSM serial than previous entry. Audit chain broken.")
            if not ld.validate(prev):
                raise click.ClickException(f"Log entry {n} FAILED validation against previous entry. Audit chain broken.")
        prev = ld
        n += 1
    cli_info(f"Ok, previously stored entries from {initial_num} to {n-1} verified successfully.")
    return prev


def update_json_file(jsonfile: Path, new_json_entries: dict[int, dict], dev_serial: int):
    """
    Merge new log entries into the JSON file.
    """
    lockfile = f"{jsonfile}.lock"
    file_entries = {}
    try:
        with FileLock(lockfile, timeout=30):
            if Path(jsonfile).exists():
                with Path(jsonfile).open('r') as fh:
                    file_entries = json.load(fh)

            if any(e['hsm_serial'] != dev_serial for e in file_entries.values()):
                raise click.ClickException("The JSON file contains entries from a different HSM serial. Cannot mix entries.")

            for jn, jdict in new_json_entries.items():
                assert jn not in file_entries, f"Duplicate entry number {jn} in JSON file. Should have been caught earlier."
                file_entries[str(jn)] = jdict

            with Path(jsonfile).open('w') as fh:
                json.dump(file_entries, fh, indent=2, sort_keys=True)
                cli_info(f"New entries added to '{jsonfile}'")

            Path(lockfile).unlink()

    except Timeout as e:
        cli_info(f"Failed to acquire file lock '{lockfile}': {e}")
        raise click.ClickException("Failed to acquire lock on the JSON file. Please try again later.")
