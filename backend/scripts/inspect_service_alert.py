import sqlite3, os, json

db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

print("=== SERVICE_INSTALLATION alert details ===")
rows = conn.execute(
    "SELECT id, title, description, status, evidence, created_at FROM alerts WHERE rule_name='SERVICE_INSTALLATION'"
).fetchall()
for r in rows:
    print(f"id       : {r[0]}")
    print(f"title    : {r[1]}")
    print(f"status   : {r[3]}")
    print(f"created  : {r[5]}")
    try:
        ev = json.loads(r[4]) if r[4] else {}
        print(f"evidence :")
        for k, v in ev.items():
            print(f"  {k}: {str(v)[:200]}")
    except Exception:
        print(f"evidence : {r[4]}")

print("\n=== Related log entry ===")
# find the log that triggered it
alert_row = conn.execute(
    "SELECT related_log_ids FROM alerts WHERE rule_name='SERVICE_INSTALLATION'"
).fetchone()
if alert_row:
    try:
        ids = json.loads(alert_row[0])
        for lid in ids[:3]:
            log = conn.execute(
                "SELECT event_id, event_type, message FROM log_entries WHERE id=?", (lid,)
            ).fetchone()
            if log:
                print(f"event_id  : {log[0]}")
                print(f"event_type: {log[1]}")
                print(f"message   : {log[2][:400]}")
    except Exception as e:
        print(f"Could not load related logs: {e}")

conn.close()
