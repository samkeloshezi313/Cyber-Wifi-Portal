"""SQLite helpers (standard library only)."""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL UNIQUE,          -- student/staff number or email, lower-case
    email TEXT NOT NULL,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',        -- 'user' | 'admin'
    blocked_at REAL,
    block_reason TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    os TEXT, browser TEXT,
    token_hash TEXT,                          -- sha256 of the device cookie
    trusted INTEGER NOT NULL DEFAULT 0,
    first_ip TEXT,
    created_at REAL NOT NULL,
    last_seen REAL
);
CREATE TABLE IF NOT EXISTS otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    purpose TEXT NOT NULL,                    -- 'register' | 'stepup'
    code_hash TEXT NOT NULL,
    expires_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    identifier TEXT NOT NULL,
    ts REAL NOT NULL,
    ip TEXT, ip_prefix TEXT,
    result TEXT NOT NULL,                     -- 'bad_password' | 'bad_otp' | 'assessed'
    hour INTEGER, time_label TEXT,
    features_json TEXT, checks_json TEXT,
    risk REAL,
    decision TEXT,                            -- 'allow' | 'step_up' | 'block'
    outcome TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'granted' | 'denied'
    device_id INTEGER,
    location_label TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_user ON login_events(user_id, outcome);
CREATE INDEX IF NOT EXISTS idx_events_ident ON login_events(identifier, result, ts);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    device_id INTEGER,
    ip TEXT,
    risk REAL,
    ended_by TEXT,
    end_reason TEXT,
    started_at REAL NOT NULL,
    ended_at REAL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,                   -- 'high' (red) | 'medium' (orange)
    user_identifier TEXT,
    ip TEXT,
    detail TEXT,
    status TEXT NOT NULL DEFAULT 'Open'       -- 'Open' | 'Investigating' | 'Resolved'
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        conn = get_db()
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()


def add_alert(db, threat_type, severity, identifier, ip, detail, ts=None, status="Open"):
    import time
    db.execute(
        "INSERT INTO alerts(ts, threat_type, severity, user_identifier, ip, detail, status)"
        " VALUES (?,?,?,?,?,?,?)",
        (ts or time.time(), threat_type, severity, identifier, ip, detail, status),
    )
    db.commit()


def _migrate(conn):
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "blocked_at" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN blocked_at REAL")
    if "block_reason" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN block_reason TEXT")
    session_cols = {row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    if "risk" not in session_cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN risk REAL")
    if "ended_by" not in session_cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN ended_by TEXT")
    if "end_reason" not in session_cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN end_reason TEXT")
