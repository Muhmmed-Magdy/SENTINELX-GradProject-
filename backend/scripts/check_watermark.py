import sqlite3, os, datetime

db = os.path.join(os.path.dirname(__file__), '..', 'soc_dashboard.db')
conn = sqlite3.connect(db)

try:
    row = conn.execute(
        "SELECT value FROM app_settings WHERE key='live_cleared_at'"
    ).fetchone()
    if row:
        ts = float(row[0])
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        age_hours = (now.timestamp() - ts) / 3600
        print(f"Watermark set at : {dt.isoformat()}")
        print(f"Age              : {age_hours:.1f} hours ago")
        print()
        print("IMPACT: The ingest endpoint REJECTS any log with a timestamp")
        print(f"        older than {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print()
        print("This is why Windows logs are slow - if the forwarder sends")
        print("events that have timestamps before the watermark they are dropped.")
    else:
        print("No watermark set - ingest accepts all logs")
except Exception as e:
    print(f"app_settings table not found or error: {e}")

conn.close()
