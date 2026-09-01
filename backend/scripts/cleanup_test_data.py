import sqlite3, os

db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

# Remove test fixture rows that leaked from the test suite into production DB
deleted = conn.execute("DELETE FROM alerts WHERE rule_name = 'TEST_RULE'").rowcount
conn.commit()
print(f"Deleted {deleted} test fixture alert(s) with rule_name=TEST_RULE")

# Show what remains
rows = conn.execute("SELECT id, title, severity, status, rule_name FROM alerts").fetchall()
print(f"\nRemaining alerts ({len(rows)}):")
for r in rows:
    print(f"  {r[0][:8]}  status={r[3]:20s}  sev={r[2]:8s}  rule={r[4]}  title={r[1][:50]}")

conn.close()
