import sqlite3, os
db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)
print("=== Linux log samples ===")
rows = conn.execute("""
    SELECT timestamp, source, event_type, severity, message
    FROM log_entries WHERE source_type='linux'
    ORDER BY created_at DESC LIMIT 10
""").fetchall()
for r in rows:
    print(f"  time={r[0][:19]}  event_type='{r[2]}'  sev={r[3]}")
    print(f"  msg={r[4][:100]}")
    print()
conn.close()
