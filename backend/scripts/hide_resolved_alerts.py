"""
Push all resolved/false_positive alerts past the 30-minute grace window
so they immediately disappear from the Alerts page and Dashboard.
"""
import sqlite3, os

db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

updated = conn.execute("""
    UPDATE alerts
    SET updated_at = datetime(updated_at, '-31 minutes')
    WHERE status IN ('resolved', 'false_positive')
""").rowcount
conn.commit()

active = conn.execute(
    "SELECT COUNT(*) FROM alerts WHERE status IN ('new','acknowledged','investigating','escalated')"
).fetchone()[0]
total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

print(f"Pushed {updated} closed alerts past the 30-min grace window")
print(f"Active alerts now visible: {active}")
print(f"Total alerts in DB: {total}")
conn.close()
