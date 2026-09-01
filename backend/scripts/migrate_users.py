"""
migrate_users.py — One-time migration script.

Adds the users, sessions, ingest_keys, and app_settings tables to the
existing production database. It never creates predictable demo accounts.

Run from the backend/ directory:
    python scripts/migrate_users.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import get_db, init_db
from auth import hash_password

print("Running database migration...")
init_db()   # creates all tables idempotently (uses IF NOT EXISTS)

db = get_db()

# Check if users table has any rows
count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
print(f"  Found {count} existing user(s)")

if count == 0:
    print("  No users found. Set ADMIN_EMAIL and ADMIN_PASSWORD, then run the application once.")
else:
    print("  Users already exist — checking for unhashed passwords...")
    # Safety check: if any password_hash looks like a plaintext password, rehash it
    rows = db.execute("SELECT id, email, password_hash FROM users").fetchall()
    updated = 0
    plaintext_signals = ["admin123", "analyst123", "junior123"]
    for row in rows:
        ph = row["password_hash"] or ""
        # Werkzeug hashes start with "scrypt:" or "pbkdf2:" — plaintext won't
        if not (ph.startswith("scrypt:") or ph.startswith("pbkdf2:") or ph.startswith("$")):
            # It looks like plaintext — rehash it
            new_hash = hash_password(ph)
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, row["id"]))
            print(f"  Rehashed password for {row['email']}")
            updated += 1
    if updated:
        db.commit()
        print(f"  Rehashed {updated} password(s)")
    else:
        print("  All passwords are already hashed — nothing to do")

db.close()
print("\nMigration complete.")
