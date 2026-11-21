
import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from getpass import getpass

url = "http://127.0.0.1:8001/api/logs/ingest"
key = getpass("Enter your saved SentinelX ingest key (input hidden): ")

event = {
    "id": "sentinelx-test-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "source": "SentinelX-Synthetic-Test",
    "source_type": "windows_event",
    "event_type": "windows_event",
    "event_id": "4720",
    "severity": "info",
    "message": "Synthetic test event: a new user account was created",
    "username": "sentinelx_test",
    "hostname": "localhost",
    "tags": ["synthetic_test"]
}

payload = json.dumps({"logs": [event]}).encode("utf-8")
request = urllib.request.Request(
    url,
    data=payload,
    headers={
        "Content-Type": "application/json",
        "X-Ingest-Key": key
    },
    method="POST"
)

try:
    with urllib.request.urlopen(request, timeout=10) as response:
        print("HTTP status:", response.status)
        print("Backend response:", response.read().decode("utf-8"))
except urllib.error.HTTPError as error:
    print("HTTP error:", error.code)
    print(error.read().decode("utf-8"))
except Exception as error:
    print("Request failed:", type(error).__name__, str(error))
