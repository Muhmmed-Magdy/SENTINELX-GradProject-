"""
conftest.py — shared pytest fixtures for the AI SOC Dashboard backend test suite.

Key design decisions
--------------------
* Each test gets a fresh, isolated SQLite database so tests are fully independent.
* We monkey-patch database.DB_PATH and config.settings.DATABASE_PATH to point at a
  temporary file rather than the production soc_dashboard.db.
* The Flask test client is exposed as a session-scoped fixture plus a convenience
  auth_client fixture that already holds a valid Bearer token.
* Users are created with hashed passwords; no plaintext passwords in DB.
"""
import json
import os
import sys
import tempfile
from pathlib import Path
from collections import defaultdict

import pytest

# Make sure the backend package is importable regardless of how pytest is invoked
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ---------------------------------------------------------------------------
# Isolated database fixture
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """
    Redirect every database call to a fresh temporary SQLite file.
    """
    db_file = str(tmp_path / "test_soc.db")

    import database
    import config

    monkeypatch.setattr(database, "DB_PATH", db_file)
    monkeypatch.setattr(config.settings, "DATABASE_PATH", db_file)

    database.init_db()

    # Seed test users with hashed passwords
    from auth import hash_password
    import uuid
    db = database.get_db()
    test_users = [
        (str(uuid.uuid4()), "admin@soc.local",   "Admin User",     hash_password("admin123"),    "admin",          1),
        (str(uuid.uuid4()), "analyst@soc.local",  "Senior Analyst", hash_password("analyst123"),  "senior_analyst", 1),
        (str(uuid.uuid4()), "junior@soc.local",   "Junior Analyst", hash_password("junior123"),   "analyst",        1),
        (str(uuid.uuid4()), "readonly@soc.local", "Read Only User", hash_password("readonly123"), "readonly",       1),
        (str(uuid.uuid4()), "disabled@soc.local", "Disabled User",  hash_password("disabled123"), "analyst",        0),
    ]
    for uid, email, name, ph, role, active in test_users:
        db.execute(
            "INSERT INTO users (id, email, name, password_hash, role, is_active) VALUES (?,?,?,?,?,?)",
            (uid, email, name, ph, role, active),
        )

    # Seed one active ingest key for tests
    from auth import create_ingest_key
    TEST_INGEST_KEY = "soc-test-ingest-key-fixed-for-tests-0000"
    import hashlib
    key_hash = hashlib.sha256(TEST_INGEST_KEY.encode()).hexdigest()
    db.execute(
        "INSERT INTO ingest_keys (id, name, key_hash, is_active) VALUES (?,?,?,1)",
        (str(uuid.uuid4()), "test-forwarder", key_hash),
    )

    db.commit()
    db.close()

    # Expose the fixed ingest key for tests
    monkeypatch.setattr(config.settings, "INGEST_KEY", "")  # force DB-only path
    os.environ["_TEST_INGEST_KEY"] = TEST_INGEST_KEY

    yield db_file

    os.environ.pop("_TEST_INGEST_KEY", None)


# ---------------------------------------------------------------------------
# Rule engine counter reset
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_rule_counters():
    from rule_engine import reset_counters
    reset_counters()
    yield
    reset_counters()


# ---------------------------------------------------------------------------
# Rate-limiter reset
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_login_attempts():
    from run import _LOGIN_ATTEMPTS
    _LOGIN_ATTEMPTS.clear()
    yield
    _LOGIN_ATTEMPTS.clear()


# ---------------------------------------------------------------------------
# Flask test client fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    from run import app
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture()
def auth_client(client):
    """Admin Bearer token client."""
    resp = client.post(
        "/api/auth/login",
        json={"email": "admin@soc.local", "password": "admin123"},
    )
    assert resp.status_code == 200, f"Login failed in auth_client fixture: {resp.data}"
    token = resp.get_json()["access_token"]
    return client, token


@pytest.fixture()
def analyst_client(client):
    """Senior analyst Bearer token client."""
    resp = client.post(
        "/api/auth/login",
        json={"email": "analyst@soc.local", "password": "analyst123"},
    )
    assert resp.status_code == 200
    token = resp.get_json()["access_token"]
    return client, token


@pytest.fixture()
def readonly_client(client):
    """Read-only Bearer token client."""
    resp = client.post(
        "/api/auth/login",
        json={"email": "readonly@soc.local", "password": "readonly123"},
    )
    assert resp.status_code == 200
    token = resp.get_json()["access_token"]
    return client, token


# ---------------------------------------------------------------------------
# Ingest key fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def ingest_headers():
    """Returns headers dict with the test ingest key."""
    key = os.environ.get("_TEST_INGEST_KEY", "soc-test-ingest-key-fixed-for-tests-0000")
    return {"X-Ingest-Key": key, "Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Convenience DB seeding helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def seed_alert(isolated_db):
    import database

    def _seed(**overrides):
        import uuid
        defaults = dict(
            id=str(uuid.uuid4()),
            title="Test Alert",
            description="A test alert",
            severity="high",
            status="new",
            rule_name="TEST_RULE",
            confidence=80,
            source_ip="10.0.0.1",
            username="testuser",
            hostname="host-1",
            related_log_ids=json.dumps([]),
            evidence=json.dumps({}),
            ai_analysis=json.dumps({}),
            threat_score=70,
            updated_at=None,
        )
        defaults.update(overrides)
        db = database.get_db()
        cols = [
            "id", "title", "description", "severity", "status", "rule_name",
            "confidence", "source_ip", "username", "hostname",
            "related_log_ids", "evidence", "ai_analysis", "threat_score",
        ]
        values = [defaults[c] for c in cols]
        if defaults.get("updated_at") is not None:
            cols.append("updated_at")
            values.append(defaults["updated_at"])
        placeholders = ", ".join(["?" for _ in cols])
        col_names = ", ".join(cols)
        db.execute(
            f"INSERT INTO alerts ({col_names}) VALUES ({placeholders})",
            values,
        )
        db.commit()
        db.close()
        return defaults["id"]

    return _seed


@pytest.fixture()
def seed_log(isolated_db):
    import database

    def _seed(**overrides):
        import uuid
        defaults = dict(
            id=str(uuid.uuid4()),
            timestamp="2024-01-01T00:00:00Z",
            source="DC-01",
            source_type="windows",
            event_type="Security",
            event_id="4624",
            severity="info",
            message="Normal logon",
            source_ip="10.0.0.5",
            username="jdoe",
            hostname="DC-01",
            tags="[]",
        )
        defaults.update(overrides)
        db = database.get_db()
        db.execute(
            """INSERT INTO log_entries
               (id, timestamp, source, source_type, event_type, event_id,
                severity, message, source_ip, username, hostname, tags)
               VALUES (:id, :timestamp, :source, :source_type, :event_type,
                       :event_id, :severity, :message, :source_ip,
                       :username, :hostname, :tags)""",
            defaults,
        )
        db.commit()
        db.close()
        return defaults["id"]

    return _seed
