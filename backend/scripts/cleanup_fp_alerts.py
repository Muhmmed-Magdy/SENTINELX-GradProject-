"""
Remove false-positive and resolved alerts that are older than 30 minutes
from the production database. Safe to run at any time.
"""
import sqlite3, os

db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

deleted = conn.execute("""
    DELETE FROM alerts
    WHERE status IN ('false_positive', 'resolved')
      AND updated_at <= datetime('now', '-30 minutes')
""").rowcount
conn.commit()
print(f"Removed {deleted} stale false-positive/resolved alert(s)")

remaining = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
active = conn.execute(
    "SELECT COUNT(*) FROM alerts WHERE status IN ('new','acknowledged','investigating','escalated')"
).fetchone()[0]
print(f"Remaining: {remaining} total  |  {active} active")
conn.close()
