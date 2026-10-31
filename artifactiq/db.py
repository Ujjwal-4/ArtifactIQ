"""SQLite access layer (stdlib, no ORM) with explicit transactions."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from flask import g, current_app

SCHEMA_VERSION = 2


def get_db() -> sqlite3.Connection:
    """Per-request connection. Create the schema lazily on first use."""
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DB_PATH"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        _ensure_schema(conn)
        g.db = conn
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def _ensure_schema(conn: sqlite3.Connection) -> None:
    schema_path = Path(__file__).with_name("schema.sql")
    conn.executescript(schema_path.read_text(encoding="utf-8"))
    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if not row:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
    conn.commit()


def init_db(db_path: str) -> None:
    """Initialize a database outside of a request context (CLI/tests)."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _ensure_schema(conn)
    conn.close()


def query(sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
    return get_db().execute(sql, params).fetchall()


def one(sql: str, params: tuple | list = ()) -> sqlite3.Row | None:
    return get_db().execute(sql, params).fetchone()


def execute(sql: str, params: tuple | list = ()) -> sqlite3.Cursor:
    cur = get_db().execute(sql, params)
    get_db().commit()
    return cur


def insert(table: str, row: dict) -> None:
    cols = ", ".join(row.keys())
    marks = ", ".join(["?"] * len(row))
    execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(row.values()))


def insert_many(table: str, rows: list[dict]) -> None:
    if not rows:
        return
    cols = ", ".join(rows[0].keys())
    marks = ", ".join(["?"] * len(rows[0]))
    get_db().executemany(
        f"INSERT INTO {table} ({cols}) VALUES ({marks})", [tuple(r.values()) for r in rows]
    )
    get_db().commit()


def update(table: str, row_id: str, changes: dict) -> None:
    sets = ", ".join(f"{k} = ?" for k in changes)
    execute(f"UPDATE {table} SET {sets} WHERE id = ?", (*changes.values(), row_id))


def jdump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def jload(s, default=None):
    if not s:
        return default if default is not None else ({} if isinstance(default, dict) else [])
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return default if default is not None else []
