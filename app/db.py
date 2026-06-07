"""Acropolis Notes - database schema and seed data.

Run ``python db.py`` to (re)create ``acropolis.db`` with the demo accounts and
notes used by the app and by ``test_exploits.py``.

Phase 8 (remediation) hardened the app: seeded passwords are now stored as
salted hashes (werkzeug), not plaintext. The original vulnerable build — with
plaintext passwords and the planted flaws — is preserved at the git tag
``v1.0-vulnerable``; see ``writeups/phase-8-remediation.md``.
"""

import os
import sqlite3

from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "acropolis.db")

# The IDOR flag (VULN #3) lives in the admin's note. Any logged-in user can read
# it through the /notes/<id> route, which fetches by id with no ownership check.
ADMIN_FLAG = "FLAG{idor_let_me_read_the_admin_note}"

SCHEMA = """
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,                 -- salted hash (werkzeug), never plaintext
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    tags       TEXT NOT NULL DEFAULT '',      -- comma-separated
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

# (username, plaintext_password) — the plaintext here is only the seed input;
# init_db() stores a salted hash, never the plaintext itself. Login still
# accepts these same passwords as typed.
USERS = [
    ("alice", "password123"),
    ("bob", "letmein"),
    ("admin", "acropolis-admin"),
]

# (username, title, body, tags, created_at)
NOTES = [
    (
        "alice",
        "Welcome to Acropolis Notes",
        (
            "Acropolis Notes keeps your thinking in one calm place.\n\n"
            "- Write in **Markdown** - headings, lists and `code` all render.\n"
            "- Organise with **tags**.\n"
            "- Find anything fast with the **search** box.\n\n"
            "Click **New note** in the sidebar to get started."
        ),
        "welcome, getting-started",
        "2026-05-12 09:14:00",
    ),
    (
        "alice",
        "Q2 project ideas",
        (
            "## Shortlist\n\n"
            "1. Migrate the build to multi-arch images\n"
            "2. Publish a public changelog\n"
            "3. Run the quarterly security review\n\n"
            "> Size each item before planning the sprint."
        ),
        "work, ideas",
        "2026-05-18 16:40:00",
    ),
    (
        "alice",
        "Reading list",
        (
            "## To read\n\n"
            "- *The Pragmatic Programmer*\n"
            "- *Designing Data-Intensive Applications*\n"
            "- *Project Hail Mary*\n\n"
            "Currently reading: **Thinking in Systems**."
        ),
        "personal, reading",
        "2026-05-24 20:05:00",
    ),
    (
        "bob",
        "Standup - Monday",
        (
            "- **Done:** shipped the export endpoint\n"
            "- **Today:** review the import flow\n"
            "- **Blockers:** none"
        ),
        "work, standup",
        "2026-05-25 09:02:00",
    ),
    (
        "bob",
        "Grocery list",
        "- Olive oil\n- Coffee\n- Sourdough\n- Greek yoghurt",
        "personal",
        "2026-05-26 18:30:00",
    ),
    (
        "admin",
        "Production infrastructure credentials",
        (
            "**Internal only - do not share.**\n\n"
            "- DB host: `db.internal.acropolis.lab`\n"
            "- Backup key rotated 2026-05-01\n\n"
            "Master recovery token:\n\n"
            "    " + ADMIN_FLAG
        ),
        "admin, infra, secret",
        "2026-05-28 07:45:00",
    ),
]


def get_connection():
    """Return a SQLite connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the schema and load the seed data (drops any existing tables)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.executescript(SCHEMA)

    user_ids = {}
    for username, password in USERS:
        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        user_ids[username] = cur.lastrowid

    admin_note_id = None
    for username, title, body, tags, created_at in NOTES:
        cur.execute(
            "INSERT INTO notes (user_id, title, body, tags, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_ids[username], title, body, tags, created_at, created_at),
        )
        if username == "admin":
            admin_note_id = cur.lastrowid

    conn.commit()
    conn.close()

    print(f"Initialised {DB_PATH}")
    print(f"  users: {', '.join(u for u, _ in USERS)}")
    print(f"  notes: {len(NOTES)}")
    print(f"  admin flag note id: {admin_note_id}  (read it via /notes/{admin_note_id})")


if __name__ == "__main__":
    init_db()
