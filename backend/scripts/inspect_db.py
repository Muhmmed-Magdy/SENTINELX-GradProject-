import sqlite3, os
db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

print("=== Log Entry Summary ===")
total = conn.execute('SELECT COUNT(*) FROM log_entries').fetchone()[0]
print(f"Total entries: {total}")

print("\nTop event IDs:")
for r in conn.execute('SELECT event_id, COUNT(*) c FROM log_entries GROUP BY event_id ORDER BY c DESC LIMIT 15').fetchall():
    print(f"  {str(r[0]):10s} -> {r[1]}")

print("\nEvent types (provider names):")
for r in conn.execute('SELECT event_type, COUNT(*) c FROM log_entries GROUP BY event_type ORDER BY c DESC LIMIT 10').fetchall():
    print(f"  {str(r[0]):40s} -> {r[1]}")

print("\nSeverity breakdown:")
for r in conn.execute('SELECT severity, COUNT(*) FROM log_entries GROUP BY severity').fetchall():
    print(f"  {r[0]:10s} -> {r[1]}")

print("\nDate range:")
oldest = conn.execute('SELECT MIN(timestamp) FROM log_entries').fetchone()[0]
newest = conn.execute('SELECT MAX(timestamp) FROM log_entries').fetchone()[0]
print(f"  Oldest: {oldest}")
print(f"  Newest: {newest}")

upload = conn.execute("SELECT COUNT(*) FROM log_entries WHERE upload_session_id != '' AND upload_session_id IS NOT NULL").fetchone()[0]
live   = conn.execute("SELECT COUNT(*) FROM log_entries WHERE (upload_session_id = '' OR upload_session_id IS NULL)").fetchone()[0]
print(f"\nSource: uploaded={upload}  live/forwarder={live}")

print("\n=== Alert Summary ===")
alerts_total = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
print(f"Total alerts: {alerts_total}")
for r in conn.execute('SELECT rule_name, severity, COUNT(*) c FROM alerts GROUP BY rule_name, severity ORDER BY c DESC').fetchall():
    print(f"  {str(r[0]):35s} {str(r[1]):10s} -> {r[2]}")

conn.close()
