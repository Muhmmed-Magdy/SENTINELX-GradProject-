import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_db
from auth import verify_password

db = get_db()
rows = db.execute("SELECT email, password_hash, role, is_active FROM users").fetchall()
for r in rows:
    print(f"\nemail: {r['email']}  role: {r['role']}  active: {r['is_active']}")
    print(f"  hash prefix: {r['password_hash'][:30]}...")
    for pw in ["admin123", "admin123!demo", "analyst123", "analyst123!demo", "junior123", "junior123!demo"]:
        if verify_password(pw, r['password_hash']):
            print(f"  ✅ password matches: {pw}")
            break
    else:
        print("  ❌ none of the test passwords match")
db.close()
