"""Reset demo account passwords to the simple versions shown in the UI."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_db
from auth import hash_password

resets = [
    ("admin@soc.local",   "admin123"),
    ("analyst@soc.local", "analyst123"),
    ("junior@soc.local",  "junior123"),
]

db = get_db()
for email, password in resets:
    db.execute(
        "UPDATE users SET password_hash=?, updated_at=datetime('now') WHERE email=?",
        (hash_password(password), email),
    )
    print(f"Reset password for {email} → {password}")
db.commit()
db.close()
print("Done.")
