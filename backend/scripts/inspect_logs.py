import sqlite3, os, json

db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

print("=== SAMPLE RAW MESSAGES (last 5) ===")
rows = conn.execute("""
    SELECT timestamp, source, event_type, event_id, severity, message
    FROM log_entries ORDER BY created_at DESC LIMIT 5
""").fetchall()
for r in rows:
    print(f"\n  Time    : {r[0]}")
    print(f"  Source  : {r[1]}")
    print(f"  Provider: {r[2]}")
    print(f"  EventID : {r[3]}")
    print(f"  Severity: {r[4]}")
    print(f"  Message : {r[5][:300]}")

print("\n=== EVENT ID 4100 SAMPLE (PowerShell errors) ===")
rows = conn.execute("""
    SELECT message FROM log_entries WHERE event_id='4100' LIMIT 3
""").fetchall()
for r in rows:
    print(r[0][:400])
    print("---")

print("\n=== SECURITY EVENTS SAMPLE ===")
rows = conn.execute("""
    SELECT event_id, message FROM log_entries
    WHERE event_type LIKE '%Security%' LIMIT 5
""").fetchall()
for r in rows:
    print(f"  EventID {r[0]}: {r[1][:200]}")

print("\n=== EVENT ID DISTRIBUTION ===")
rows = conn.execute("""
    SELECT event_id, event_type, COUNT(*) c
    FROM log_entries GROUP BY event_id, event_type ORDER BY c DESC LIMIT 20
""").fetchall()
for r in rows:
    print(f"  {str(r[0]):8s}  {str(r[1]):45s}  {r[2]} events")

conn.close()
