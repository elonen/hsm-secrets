import sqlite3
from typing import Generator, List, Optional, Callable
import datetime
import yubihsm  # type: ignore [import]

def init_db(conn: sqlite3.Connection) -> None:
    """Initialize the database with the required schema."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS log_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_number INTEGER NOT NULL,
            hsm_serial INTEGER NOT NULL,
            raw_entry BLOB NOT NULL,
            fetch_time DATETIME NOT NULL,
            command INTEGER NOT NULL,
            command_desc TEXT,
            length INTEGER NOT NULL,
            session_key INTEGER NOT NULL,
            session_key_desc TEXT,
            target_key INTEGER NOT NULL,
            target_key_desc TEXT,
            second_key INTEGER NOT NULL,
            second_key_desc TEXT,
            result INTEGER NOT NULL,
            tick INTEGER NOT NULL,
            UNIQUE(hsm_serial, id),
            UNIQUE(hsm_serial, raw_entry)
        );

        CREATE INDEX IF NOT EXISTS idx_hsm_serial_entry_number ON log_entries(hsm_serial, entry_number);

        CREATE TABLE IF NOT EXISTS export_tracking (
            hsm_serial INTEGER PRIMARY KEY,
            last_exported_id INTEGER NOT NULL
        );
    """)


def previous_entry_number(current: int) -> int:
    """Calculate the previous entry number, handling wraparound."""
    return (current - 1) & 0xFFFF

def insert_log_entry(conn: sqlite3.Connection, hsm_serial: int, new_entry: yubihsm.core.LogEntry,
                     fetch_time: datetime.datetime, no_verify: bool, find_info_func: Callable[[int], str|None]) -> bool:
    """
    Insert a new log entry.

    YubiHSM log entry numbering wraps around at 0xFFFF, so we can't rely on the entry number alone to
    determine the previous entry in the chain => test multiple candidates for more robustness.

    If no_verify is set, the new entry is inserted without verifying it against the previous entry.
    This could result in a broken audit chain, so think twice before using this option.
    """
    cursor = conn.cursor()

    if not no_verify:
        # Get all entries with entry_number one less than the new entry
        previous_entry_number_value = previous_entry_number(new_entry.number)
        cursor.execute("SELECT id, raw_entry FROM log_entries WHERE hsm_serial = ? AND (entry_number = ? OR entry_number = ?)", (hsm_serial, new_entry.number, previous_entry_number_value))
        candidates = cursor.fetchall()

        # Pick the first entry that forms a valid chain with the new entry
        valid_previous_entry = None
        for _, raw_entry in candidates:
            if raw_entry == (new_entry.data + new_entry.digest):
                return False  # Entry already exists
            previous_entry = yubihsm.core.LogEntry.parse(raw_entry)
            if new_entry.validate(previous_entry):
                valid_previous_entry = previous_entry   # Don't break yet, the "new" entry might already exist but haven't been seen yet

        if valid_previous_entry is None and candidates:
            raise ValueError("New entry doesn't validate against any previous entry candidates")

    # Insert the new log entry
    cursor.execute("""
        INSERT INTO log_entries (entry_number, hsm_serial, raw_entry, fetch_time, command,
                                 command_desc, length, session_key, session_key_desc, target_key,
                                 target_key_desc, second_key, second_key_desc, result, tick)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (new_entry.number,
          hsm_serial,
          (new_entry.data + new_entry.digest),
          fetch_time,
          new_entry.command.value,  new_entry.command.name,
          new_entry.length,
          new_entry.session_key,    find_info_func(new_entry.session_key),
          new_entry.target_key,     find_info_func(new_entry.target_key),
          new_entry.second_key,     find_info_func(new_entry.second_key),
          new_entry.result,
          new_entry.tick))

    return True


def get_log_entries(conn: sqlite3.Connection, hsm_serial: int) -> Generator[sqlite3.Row, None, None]:
    """Retrieve all log entries for a given HSM serial."""
    cursor = conn.cursor()
    for c in cursor.execute("""
        SELECT id, entry_number, hsm_serial, raw_entry, fetch_time, command, command_desc,
               length, session_key, session_key_desc, target_key, target_key_desc,
               second_key, second_key_desc, result, tick
        FROM log_entries
        WHERE hsm_serial = ?
        ORDER BY id ASC
    """, (hsm_serial,)):
        yield c


def get_last_log_entry(conn: sqlite3.Connection, hsm_serial: int) -> Optional[sqlite3.Row]:
    """Retrieve the last log entry for a given HSM serial."""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, entry_number, hsm_serial, raw_entry, fetch_time, command, command_desc,
               length, session_key, session_key_desc, target_key, target_key_desc,
               second_key, second_key_desc, result, tick
        FROM log_entries
        WHERE hsm_serial = ?
        ORDER BY id DESC
        LIMIT 1
    """, (hsm_serial,))
    return cursor.fetchone()


def get_non_exported_log_entries(conn: sqlite3.Connection, hsm_serial: int) -> Generator[sqlite3.Row, None, None]:
    """Retrieve new log entries for a given HSM serial since the last export."""
    cursor = conn.cursor()

    # Get the last exported ID
    cursor.execute("SELECT last_exported_id FROM export_tracking WHERE hsm_serial = ?", (hsm_serial,))
    result = cursor.fetchone()
    last_exported_id = result[0] if result else 0

    # Fetch new entries
    for row in cursor.execute("""
            SELECT id, entry_number, hsm_serial, raw_entry, fetch_time, command, command_desc,
                length, session_key, session_key_desc, target_key, target_key_desc,
                second_key, second_key_desc, result, tick
            FROM log_entries
            WHERE hsm_serial = ? AND id > ?
            ORDER BY id ASC
            """, (hsm_serial, last_exported_id)):
        yield row



def update_last_exported_id(conn: sqlite3.Connection, hsm_serial: int, last_exported_id: int) -> None:
    """Update the last exported ID for a given HSM serial."""
    conn.execute("INSERT OR REPLACE INTO export_tracking (hsm_serial, last_exported_id) VALUES (?, ?)", (hsm_serial, last_exported_id))
    conn.commit()
