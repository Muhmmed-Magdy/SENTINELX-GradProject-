import sqlite3, os
from datetime import datetime, timezone

db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

print("=== Most recent log per source ===")
rows = conn.execute("""
    SELECT source_type, source, MAX(created_at) as last_seen,
           COUNT(*) as total
    FROM log_entries
    GROUP BY source_type, source
    ORDER BY last_seen DESC
""").fetchall()

now = datetime.now(timezone.utc)
for r in rows:
    try:
        last = datetime.fromisoformat(r[2].replace('Z','+00:00'))
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        age_sec = int((now - last).total_seconds())
        age_str = f"{age_sec}s ago" if age_sec < 120 else f"{age_sec//60}m ago"
    except Exception:
        age_str = "unknown"
    status = "✓ LIVE" if age_sec < 30 else "⚠ SLOW" if age_sec < 120 else "✗ STOPPED"
    print(f"  {r[0]:12s}  {r[1]:20s}  last={age_str:12s}  total={r[3]:5d}  {status}")

print()
print("=== Last 5 logs received ===")
rows2 = conn.execute("""
    SELECT source_type, source, created_at, message
    FROM log_entries ORDER BY created_at DESC LIMIT 5
""").fetchall()
for r in rows2:
    print(f"  [{r[0]:8s}] {r[1]:15s} @ {r[2]}  {r[3][:60]}")

conn.close()
