"""
migrate_db.py
--------------
Adds missing columns to the existing SQLite database.

Run once with:
    python migrate_db.py

Safe to re-run — uses IF NOT EXISTS / catches "duplicate column" errors.
"""

import sqlite3
import os
from dotenv import load_dotenv

load_dotenv(".env.oauth")
load_dotenv(".env")

# Resolve DB file path from DATABASE_URL env
db_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./data/gateway.db")

# Strip the async driver prefix to get a plain file path
# e.g. "sqlite+aiosqlite:///./data/gateway.db" → "./data/gateway.db"
db_path = db_url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "")

if not os.path.exists(db_path):
    # Try the legacy root-level file
    alt = "zero_trust.db"
    if os.path.exists(alt):
        db_path = alt
        print(f"[migrate] Using legacy DB file: {db_path}")
    else:
        print(f"[migrate] ERROR: DB file not found at '{db_path}' or '{alt}'.")
        print("          Start the server once first so it creates the DB, then re-run this script.")
        exit(1)
else:
    print(f"[migrate] Using DB file: {db_path}")

conn = sqlite3.connect(db_path)
cur = conn.cursor()

MIGRATIONS = [
    # users table — MFA columns
    "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN mfa_secret TEXT",
    # audit_logs table — event_type column
    "ALTER TABLE audit_logs ADD COLUMN event_type TEXT",
]

for sql in MIGRATIONS:
    try:
        cur.execute(sql)
        conn.commit()
        print(f"[migrate] ✅ Applied: {sql}")
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e).lower():
            print(f"[migrate] ⏭  Already exists (skip): {sql}")
        else:
            print(f"[migrate] ❌ Error: {e}  →  SQL: {sql}")

conn.close()
print("\n[migrate] Done. Restart uvicorn now.")
