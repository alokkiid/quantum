"""
database.py — SQLite database initialisation for Quantum-Aware Enterprise.

Responsibilities:
  - get_db()   → returns a connection to the SQLite DB
  - init_db()  → creates all 5 tables if they do not already exist
"""

import sqlite3
from config import DATABASE_PATH


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """Return a new SQLite connection with row_factory set to Row."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")  # enforce FK constraints
    return conn


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
-- Table 1: users
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table 3: encryption_keys  (declared before 'files' so we can FK to it)
CREATE TABLE IF NOT EXISTS encryption_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id      INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    key_data     BLOB    NOT NULL,
    nonce        BLOB    NOT NULL,
    algorithm    TEXT    NOT NULL CHECK(algorithm IN ('AES-128', 'AES-256')),
    status       TEXT    NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'DESTROYED')),
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    destroyed_at TIMESTAMP
);

-- Table 2: files
CREATE TABLE IF NOT EXISTS files (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name      TEXT    NOT NULL,
    stored_name        TEXT    NOT NULL,          -- UUID-based .enc filename
    file_size          INTEGER NOT NULL DEFAULT 0,
    sha256_fingerprint TEXT,
    encryption_state   TEXT    NOT NULL DEFAULT 'AES-128'
                           CHECK(encryption_state IN ('AES-128', 'AES-256', 'CONT_ROTATION')),
    current_key_id     INTEGER REFERENCES encryption_keys(id),
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table 4: access_logs
CREATE TABLE IF NOT EXISTS access_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id    INTEGER REFERENCES files(id),
    user_id    INTEGER REFERENCES users(id),
    source_ip  TEXT,
    event_type TEXT NOT NULL
                   CHECK(event_type IN ('AUTH_OK', 'AUTH_FAIL', 'DOWNLOAD', 'UPLOAD')),
    user_agent TEXT,
    timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ml_score   REAL NOT NULL DEFAULT 0.0
);

-- Table 5: audit_trail
CREATE TABLE IF NOT EXISTS audit_trail (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id        INTEGER REFERENCES files(id),
    event_type     TEXT NOT NULL
                       CHECK(event_type IN ('KEY_GENERATED', 'KEY_DESTROYED',
                                            'STATE_CHANGE', 'ROTATION')),
    old_state      TEXT,
    new_state      TEXT,
    key_id         INTEGER,
    rotation_count INTEGER NOT NULL DEFAULT 0,
    timestamp      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

# SQLite does not support forward-references in a single CREATE TABLE batch
# when FKs reference tables not yet created.  We create in dependency order:
#   users → files → encryption_keys → access_logs → audit_trail
# The SCHEMA string above re-orders accordingly; SQLite ignores the FK to
# encryption_keys inside files at creation time if FKs are deferred, but to
# be safe we split into ordered individual statements below.

_CREATE_STATEMENTS = [
    # 1. users (no dependencies)
    """CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT    UNIQUE NOT NULL,
        password_hash TEXT    NOT NULL,
        role          TEXT    NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",

    # 2. files — current_key_id nullable, FK to encryption_keys added after that table exists
    """CREATE TABLE IF NOT EXISTS files (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        original_name      TEXT    NOT NULL,
        stored_name        TEXT    NOT NULL,
        file_size          INTEGER NOT NULL DEFAULT 0,
        sha256_fingerprint TEXT,
        encryption_state   TEXT    NOT NULL DEFAULT 'AES-128'
                               CHECK(encryption_state IN ('AES-128', 'AES-256', 'CONT_ROTATION')),
        current_key_id     INTEGER,
        created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",

    # 3. encryption_keys — references files
    """CREATE TABLE IF NOT EXISTS encryption_keys (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id      INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
        key_data     BLOB    NOT NULL,
        nonce        BLOB    NOT NULL,
        algorithm    TEXT    NOT NULL CHECK(algorithm IN ('AES-128', 'AES-256')),
        status       TEXT    NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'DESTROYED')),
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        destroyed_at TIMESTAMP
    )""",

    # 4. access_logs
    """CREATE TABLE IF NOT EXISTS access_logs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id    INTEGER REFERENCES files(id),
        user_id    INTEGER REFERENCES users(id),
        source_ip  TEXT,
        event_type TEXT NOT NULL
                       CHECK(event_type IN ('AUTH_OK', 'AUTH_FAIL', 'DOWNLOAD', 'UPLOAD')),
        user_agent TEXT,
        timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ml_score   REAL NOT NULL DEFAULT 0.0
    )""",

    # 5. audit_trail
    """CREATE TABLE IF NOT EXISTS audit_trail (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id        INTEGER REFERENCES files(id),
        event_type     TEXT NOT NULL
                           CHECK(event_type IN ('KEY_GENERATED', 'KEY_DESTROYED',
                                                'STATE_CHANGE', 'ROTATION')),
        old_state      TEXT,
        new_state      TEXT,
        key_id         INTEGER,
        rotation_count INTEGER NOT NULL DEFAULT 0,
        timestamp      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
]


def init_db() -> None:
    """Create all tables (if not exists) in dependency order."""
    conn = get_db()
    try:
        with conn:
            for stmt in _CREATE_STATEMENTS:
                conn.execute(stmt)
        print("[database] All tables initialised successfully.")
    finally:
        conn.close()
