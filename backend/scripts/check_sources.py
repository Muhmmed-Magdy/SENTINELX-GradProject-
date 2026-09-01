import sqlite3, os

db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

print("=== ALL source_types in DB ===")
rows = conn.execute(
    "SELECT source_type, COUNT(*) c FROM log_entries GROUP BY source_type ORDER BY c DESC"
).fetchall()
for r in rows:
    print(f"  {r[0]:25s} -> {r[1]:>6} logs")

print()
print("=== Breakdown by type ===")
for t in ['windows', 'linux', 'firewall', 'ids', 'network', 'unknown']:
    n = conn.execute(
        "SELECT COUNT(*) FROM log_entries WHERE source_type=?", (t,)
    ).fetchone()[0]
    status = "✓ ACTIVE" if n > 0 else "✗ NONE"
    print(f"  {t:12s}: {n:>6} logs  {status}")

print()
total = conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
print(f"  TOTAL: {total} log entries")
conn.close()
