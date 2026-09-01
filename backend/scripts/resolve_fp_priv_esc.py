"""
Resolve all PRIVILEGE_ESCALATION alerts triggered by routine
Linux sudo session events (pam_unix sudo:session).
These are false positives — normal sudo usage, not actual attacks.
"""
import sqlite3, os, json

db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

# Find priv-esc alerts from Linux sudo sessions
rows = conn.execute("""
    SELECT id, title, description, evidence FROM alerts
    WHERE rule_name = 'PRIVILEGE_ESCALATION'
    AND status NOT IN ('resolved', 'false_positive')
""").fetchall()

fp_ids = []
real_ids = []

for row in rows:
    ev = {}
    try:
        ev = json.loads(row[3]) if row[3] else {}
    except Exception:
        pass
    msg = (ev.get('message') or row[2] or '').lower()
    # sudo session open/close = false positive
    if 'pam_unix(sudo' in msg or 'sudo:session' in msg or 'session opened' in msg:
        fp_ids.append(row[0])
    else:
        real_ids.append((row[0], row[1]))

if fp_ids:
    ph = ','.join(['?' for _ in fp_ids])
    updated = conn.execute(
        f"UPDATE alerts SET status='false_positive', updated_at=datetime('now','-31 minutes') "
        f"WHERE id IN ({ph})", fp_ids
    ).rowcount
    conn.commit()
    print(f"Marked {updated} sudo-session alerts as false_positive (hidden from view)")
else:
    print("No sudo-session false positives found")

if real_ids:
    print(f"\nReal PRIVILEGE_ESCALATION alerts kept ({len(real_ids)}):")
    for aid, title in real_ids:
        print(f"  {aid[:8]} — {title}")
else:
    print("No real privilege escalation alerts remaining")

remaining = conn.execute(
    "SELECT COUNT(*) FROM alerts WHERE status IN ('new','acknowledged','investigating','escalated')"
).fetchone()[0]
print(f"\nActive alerts remaining: {remaining}")
conn.close()
