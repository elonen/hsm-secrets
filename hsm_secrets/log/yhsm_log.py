import datetime
import json
import sqlite3
from typing import Generator, Iterable, List, Sequence
import yubihsm  # type: ignore [import]
from hsm_secrets.config import HSMConfig

def find_info(id: int, conf: HSMConfig) -> str|None:
    """Find info for a given ID using HSMConfig."""
    try:
        if id in [0, 0xffff]:
            return None
        kd = conf.find_def(id)
        return kd.label
    except KeyError:
        return "(UNKNOWN)"


def export_to_jsonl(entry: sqlite3.Row, pretty: bool, with_summary: bool) -> str:
    """
    Export log entries to JSONL format.
    Use `pretty` to show to user, otherwise outputs a single line.
    """
    json_entry = {
        "id": entry['id'],
        "entry_number": entry['entry_number'],
        "hsm_serial": entry['hsm_serial'],
        "raw_entry": entry['raw_entry'].hex(),
        "fetch_time": entry['fetch_time'],
        "command": entry['command'],
        "command_desc": entry['command_desc'],
        "length": entry['length'],
        "session_key": entry['session_key'],
        "session_key_desc": entry['session_key_desc'],
        "target_key": entry['target_key'],
        "target_key_desc": entry['target_key_desc'],
        "second_key": entry['second_key'],
        "second_key_desc": entry['second_key_desc'],
        "result": entry['result'],
        "tick": entry['tick']
    }
    if with_summary:
        json_entry["summary"] = summarize_log_entry(entry)
    return json.dumps(json_entry, indent=4 if pretty else None)


def summarize_log_entry(e: sqlite3.Row) -> str:
    """Summarize a log entry in human-readable form."""

    def obj_info(id, desc, default):
        return f"'{desc}'" if desc else f"'{default}' (0x{id:04x})"

    txt = f'{e["entry_number"]:05}: ' + obj_info(e['command'], e['command_desc'], 'UNKNOWN COMMAND')

    objs = []
    if e['target_key'] not in (0, 0xffff, None):
        objs.append(obj_info(e['target_key'], e['target_key_desc'], 'UNKNOWN KEY'))
    if e['second_key'] not in (0, 0xffff, None):
        objs.append(obj_info(e['second_key'], e['second_key_desc'], 'UNKNOWN KEY'))
    if objs:
        txt += ' on ' + ' and '.join(objs)

    if e['session_key'] not in (0, 0xffff, None):
        txt += ' by ' + obj_info(e['session_key'], e['session_key_desc'], 'UNKNOWN KEY')

    date = datetime.datetime.fromisoformat(e["fetch_time"]).strftime("%Y-%m-%d")
    txt += f' (log fetch {date}, row id {e["id"]})'

    return txt


def verify_log_chain(entries: Iterable[sqlite3.Row], chain_start: int|None) -> None:
    """
    Verify the log chain from the initial number to the last entry.
    If `chain_start` is given, it will be compared to the first entry number.
    """
    first_num = None
    prev: yubihsm.core.LogEntry|None = None
    for entry in entries:
        if not prev:
            first_num = entry["entry_number"]
            if chain_start is not None and first_num != chain_start:
                raise ValueError(f"Initial number {chain_start} does not match the first entry number {entry['entry_number']}")

        cur = yubihsm.core.LogEntry.parse(entry["raw_entry"])
        if prev and not cur.validate(prev):
            raise ValueError(f"Log entry {entry['entry_number']} failed validation against previous entry")

        prev = cur

    if prev:
        print(f"OK. Log chain verified from entry {first_num} to {prev.number}")
    elif first_num:
        print(f"Ok. Log only contains one entry {first_num}, so trivially valid")
    else:
        print("Log chain is empty")
