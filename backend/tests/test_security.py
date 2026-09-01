"""
test_security.py — Authentication, authorisation, rate-limiting, and
input-validation tests for the AI SOC Dashboard backend.
"""
import json
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run import app, socketio, _LOGIN_ATTEMPTS
from database import get_db, init_db


# ── fixtures live in conftest.py ──────────────────────────────────────────────


# =============================================================================
# Authentication
# =============================================================================

class TestAuthentication:
    def test_valid_login_returns_token(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"email": "admin@soc.local", "password": "admin123"},
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert "access_token" in body
        assert body["user"]["role"] == "admin"

    def test_wrong_password_returns_401(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"email": "admin@soc.local", "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    def test_unknown_email_returns_401(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"email": "ghost@soc.local", "password": "admin123"},
        )
        assert resp.status_code == 401

    def test_missing_body_returns_401(self, client):
        resp = client.post("/api/auth/login", json={})
        assert resp.status_code == 401

    def test_disabled_user_cannot_login(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"email": "disabled@soc.local", "password": "disabled123"},
        )
        assert resp.status_code == 401

    def test_me_endpoint_returns_user_info(self, auth_client):
        c, token = auth_client
        resp = c.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.get_json()["email"] == "admin@soc.local"

    def test_me_requires_auth(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_alert_detail_requires_auth(self, client):
        assert client.get('/api/alerts/missing').status_code == 401

    def test_expired_session_cannot_read_alert_detail(self, auth_client, seed_alert):
        c, token = auth_client
        alert_id = seed_alert()
        import database
        db = database.get_db()
        db.execute(
            "UPDATE sessions SET expires_at=? WHERE id=?",
            ("2000-01-01T00:00:00+00:00", hashlib.sha256(token.encode()).hexdigest()),
        )
        db.commit()
        db.close()
        assert c.get(f'/api/alerts/{alert_id}', headers={'Authorization': f'Bearer {token}'}).status_code == 401

    def test_token_reuse_works_across_requests(self, auth_client):
        c, token = auth_client
        headers = {"Authorization": f"Bearer {token}"}
        for _ in range(3):
            resp = c.get("/api/auth/me", headers=headers)
            assert resp.status_code == 200

    def test_analyst_role_returned_correctly(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"email": "analyst@soc.local", "password": "analyst123"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["user"]["role"] == "senior_analyst"

    def test_logout_revokes_token(self, auth_client):
        c, token = auth_client
        headers = {"Authorization": f"Bearer {token}"}
        # Verify working before logout
        assert c.get("/api/auth/me", headers=headers).status_code == 200
        # Logout
        resp = c.post("/api/auth/logout", headers=headers)
        assert resp.status_code == 200
        # Token should now be invalid
        assert c.get("/api/auth/me", headers=headers).status_code == 401

    def test_expired_session_rejected(self, auth_client):
        c, token = auth_client
        import database
        db = database.get_db()
        db.execute(
            "UPDATE sessions SET expires_at=? WHERE id=?",
            ("2000-01-01T00:00:00+00:00", hashlib.sha256(token.encode()).hexdigest()),
        )
        db.commit()
        db.close()
        assert c.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    def test_inactive_user_session_rejected(self, auth_client):
        c, token = auth_client
        import database
        db = database.get_db()
        db.execute(
            "UPDATE users SET is_active=0 WHERE id=(SELECT user_id FROM sessions WHERE id=?)",
            (hashlib.sha256(token.encode()).hexdigest(),),
        )
        db.commit()
        db.close()
        assert c.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    def test_session_persists_in_db(self, client):
        """Session token hash must be stored in DB, not in memory."""
        resp = client.post(
            "/api/auth/login",
            json={"email": "admin@soc.local", "password": "admin123"},
        )
        token = resp.get_json()["access_token"]
        import hashlib
        import database
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        db = database.get_db()
        row = db.execute("SELECT id FROM sessions WHERE id=?", (token_hash,)).fetchone()
        db.close()
        assert row is not None, "Session hash should be stored in DB"


# =============================================================================
# Protected endpoint enforcement
# =============================================================================

class TestProtectedEndpoints:
    _PROTECTED = [
        ("GET", "/api/alerts"),
        ("GET", "/api/alerts/stats"),
        ("GET", "/api/logs"),
        ("GET", "/api/logs/stats"),
        ("GET", "/api/logs/sources"),
        ("GET", "/api/dashboard/stats"),
        ("GET", "/api/incidents"),
        ("GET", "/api/ai/status"),
        ("GET", "/api/reports/summary"),
        ("POST", "/api/ai/chat"),
        ("POST", "/api/incidents"),
    ]

    @pytest.mark.parametrize("method,path", _PROTECTED)
    def test_endpoint_requires_auth(self, client, method, path):
        resp = getattr(client, method.lower())(path, json={})
        assert resp.status_code == 401, (
            f"{method} {path} should return 401 without auth, got {resp.status_code}"
        )

    def test_malformed_bearer_token_rejected(self, client):
        resp = client.get(
            "/api/alerts", headers={"Authorization": "Bearer notarealtoken"}
        )
        assert resp.status_code == 401

    def test_empty_authorization_header_rejected(self, client):
        resp = client.get("/api/alerts", headers={"Authorization": ""})
        assert resp.status_code == 401


# =============================================================================
# Rate limiting
# =============================================================================

class TestRateLimiting:
    def test_login_rate_limited_after_10_attempts(self, client):
        for _ in range(11):
            resp = client.post(
                "/api/auth/login",
                json={"email": "admin@soc.local", "password": "wrong"},
            )
        assert resp.status_code == 429

    def test_rate_limit_error_message_present(self, client):
        for _ in range(11):
            resp = client.post(
                "/api/auth/login",
                json={"email": "x@y.z", "password": "x"},
            )
        assert "attempts" in (resp.get_json().get("error") or "").lower()

    def test_rate_limit_allows_under_threshold(self, client):
        # 9 attempts should not yet be rate-limited
        for i in range(9):
            resp = client.post(
                "/api/auth/login",
                json={"email": "admin@soc.local", "password": "wrong"},
            )
        assert resp.status_code == 401   # still auth failure, not 429


# =============================================================================
# Payload / size limits
# =============================================================================

class TestPayloadLimits:
    def test_ingest_rejects_oversized_payload(self, client, ingest_headers):
        large_payload = {"logs": [{"source": "test", "message": "x" * 3_000_000}]}
        resp = client.post("/api/logs/ingest", json=large_payload, headers=ingest_headers)
        assert resp.status_code == 413

    def test_ingest_accepts_normal_payload(self, client, ingest_headers):
        payload = {"logs": [{"source": "test", "message": "normal log line"}]}
        resp = client.post("/api/logs/ingest", json=payload, headers=ingest_headers)
        assert resp.status_code == 200


# =============================================================================
# WebSocket authentication
# =============================================================================

class TestWebSocket:
    def test_unauthenticated_ws_rejected(self, client):
        from run import app, socketio
        sc = socketio.test_client(
            app, flask_test_client=client, query_string="token=invalid-token"
        )
        assert not sc.is_connected()

    def test_authenticated_ws_accepted(self, auth_client):
        from run import app, socketio
        c, token = auth_client
        sc = socketio.test_client(
            app, flask_test_client=c, query_string=f"token={token}"
        )
        assert sc.is_connected()
        sc.disconnect()

    def test_empty_token_ws_rejected(self, client):
        from run import app, socketio
        sc = socketio.test_client(
            app, flask_test_client=client, query_string="token="
        )
        assert not sc.is_connected()


# =============================================================================
# Role-based authorization
# =============================================================================

class TestRoleAuthorization:
    def test_readonly_cannot_delete_live_logs(self, readonly_client):
        c, token = readonly_client
        resp = c.delete(
            "/api/data/live-logs",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_analyst_cannot_delete_live_logs(self, analyst_client):
        c, token = analyst_client
        resp = c.delete(
            "/api/data/live-logs",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_admin_can_delete_live_logs(self, auth_client):
        c, token = auth_client
        resp = c.delete(
            "/api/data/live-logs",
            headers={"Authorization": f"Bearer {token}"},
        )
        # 200 OK (no live logs to delete, but permission is granted)
        assert resp.status_code == 200

    def test_readonly_cannot_update_alert_status(self, readonly_client, seed_alert):
        c, token = readonly_client
        alert_id = seed_alert()
        resp = c.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "investigating"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_analyst_can_update_alert_status(self, analyst_client, seed_alert):
        c, token = analyst_client
        alert_id = seed_alert()
        resp = c.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "investigating"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_readonly_cannot_create_incident(self, readonly_client):
        c, token = readonly_client
        resp = c.post(
            "/api/incidents",
            json={"title": "Test incident", "severity": "high"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_admin_can_list_users(self, auth_client):
        c, token = auth_client
        resp = c.get(
            "/api/auth/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_analyst_cannot_list_users(self, analyst_client):
        c, token = analyst_client
        resp = c.get(
            "/api/auth/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_admin_can_create_ingest_key(self, auth_client):
        c, token = auth_client
        resp = c.post(
            "/api/auth/ingest-keys",
            json={"name": "test-agent"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201
        body = resp.get_json()
        assert "key" in body
        assert body["key"].startswith("soc-")

    def test_analyst_cannot_manage_ingest_keys(self, analyst_client):
        c, token = analyst_client
        resp = c.post(
            "/api/auth/ingest-keys",
            json={"name": "test-agent"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


# =============================================================================
# Ingest key authentication
# =============================================================================

class TestIngestKeyAuth:
    def test_valid_key_accepted(self, client, ingest_headers):
        resp = client.post(
            "/api/logs/ingest",
            json={"logs": []},
            headers=ingest_headers,
        )
        assert resp.status_code == 200

    def test_missing_key_rejected(self, client):
        resp = client.post("/api/logs/ingest", json={"logs": []})
        assert resp.status_code == 401

    def test_wrong_key_rejected(self, client):
        resp = client.post(
            "/api/logs/ingest",
            json={"logs": []},
            headers={"X-Ingest-Key": "wrong-key-value"},
        )
        assert resp.status_code == 401

    def test_key_in_url_not_accepted(self, client):
        """Key must come via header, never URL."""
        resp = client.post(
            "/api/logs/ingest?key=soc-test-ingest-key-fixed-for-tests-0000",
            json={"logs": []},
        )
        assert resp.status_code == 401

    def test_revoked_key_rejected(self, auth_client, client):
        c, token = auth_client
        # Create a new key
        create_resp = c.post(
            "/api/auth/ingest-keys",
            json={"name": "revoke-test"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert create_resp.status_code == 201
        raw_key = create_resp.get_json()["key"]

        # Verify it works
        ok_resp = client.post(
            "/api/logs/ingest",
            json={"logs": []},
            headers={"X-Ingest-Key": raw_key},
        )
        assert ok_resp.status_code == 200

        # Get the key ID and revoke it
        keys_resp = c.get(
            "/api/auth/ingest-keys",
            headers={"Authorization": f"Bearer {token}"},
        )
        key_id = next(
            k["id"] for k in keys_resp.get_json() if k["name"] == "revoke-test"
        )
        revoke_resp = c.delete(
            f"/api/auth/ingest-keys/{key_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert revoke_resp.status_code == 200

        # Should now be rejected
        bad_resp = client.post(
            "/api/logs/ingest",
            json={"logs": []},
            headers={"X-Ingest-Key": raw_key},
        )
        assert bad_resp.status_code == 401


# =============================================================================
# Alert status validation
# =============================================================================

class TestAlertStatusValidation:
    def test_valid_status_update_accepted(self, auth_client, seed_alert):
        c, token = auth_client
        alert_id = seed_alert()
        resp = c.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "investigating"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "investigating"

    def test_invalid_status_returns_400(self, auth_client, seed_alert):
        c, token = auth_client
        alert_id = seed_alert()
        resp = c.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "hacked"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400
        assert "invalid" in resp.get_json()["error"].lower()

    def test_empty_status_returns_400(self, auth_client, seed_alert):
        c, token = auth_client
        alert_id = seed_alert()
        resp = c.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": ""},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    def test_nonexistent_alert_returns_404(self, auth_client):
        c, token = auth_client
        resp = c.patch(
            "/api/alerts/does-not-exist/status",
            json={"status": "resolved"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404

    @pytest.mark.parametrize("status", ["new", "investigating", "resolved", "false_positive", "escalated"])
    def test_all_valid_statuses_accepted(self, auth_client, seed_alert, status):
        c, token = auth_client
        alert_id = seed_alert()
        resp = c.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": status},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200, f"Status '{status}' was unexpectedly rejected"


# =============================================================================
# Incident creation validation
# =============================================================================

class TestIncidentValidation:
    def test_create_incident_requires_title(self, auth_client):
        c, token = auth_client
        resp = c.post(
            "/api/incidents",
            json={"description": "no title here"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400
        assert "title" in resp.get_json()["error"].lower()

    def test_create_incident_rejects_oversized_title(self, auth_client):
        c, token = auth_client
        resp = c.post(
            "/api/incidents",
            json={"title": "x" * 301, "severity": "high"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    def test_create_incident_rejects_invalid_severity(self, auth_client):
        c, token = auth_client
        resp = c.post(
            "/api/incidents",
            json={"title": "Test incident", "severity": "extreme"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    def test_create_incident_valid_payload(self, auth_client):
        c, token = auth_client
        resp = c.post(
            "/api/incidents",
            json={"title": "New incident", "severity": "high", "description": "Details"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code in (200, 201)
        body = resp.get_json()
        assert body["status"] in ("new", "open")  # 'new' is the current default
        assert "id" in body


# =============================================================================
# AI chat validation
# =============================================================================

class TestAIChatValidation:
    def test_empty_message_returns_400(self, auth_client):
        c, token = auth_client
        resp = c.post(
            "/api/ai/chat",
            json={"message": ""},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    def test_missing_message_key_returns_400(self, auth_client):
        c, token = auth_client
        resp = c.post(
            "/api/ai/chat",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    def test_oversized_message_returns_400(self, auth_client):
        c, token = auth_client
        resp = c.post(
            "/api/ai/chat",
            json={"message": "a" * 4001},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    def test_valid_message_returns_response(self, auth_client):
        c, token = auth_client
        resp = c.post(
            "/api/ai/chat",
            json={"message": "What are the top threats?"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "response" in resp.get_json()


# =============================================================================
# Pagination param safety
# =============================================================================

class TestPaginationValidation:
    def test_non_integer_limit_uses_default(self, auth_client):
        c, token = auth_client
        resp = c.get(
            "/api/alerts?limit=abc",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200   # should not crash

    def test_non_integer_offset_uses_default(self, auth_client):
        c, token = auth_client
        resp = c.get(
            "/api/alerts?offset=xyz",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_negative_offset_clamped_to_zero(self, auth_client):
        c, token = auth_client
        resp = c.get(
            "/api/logs?offset=-100",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_limit_capped_at_maximum(self, auth_client):
        c, token = auth_client
        resp = c.get(
            "/api/alerts?limit=99999",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200   # should clamp, not crash

    def test_invalid_severity_filter_returns_400(self, auth_client):
        c, token = auth_client
        resp = c.get(
            "/api/alerts?severity=extreme",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    def test_invalid_status_filter_returns_400(self, auth_client):
        c, token = auth_client
        resp = c.get(
            "/api/alerts?status=hacked",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400


# =============================================================================
# Alert hide-closed behaviour (regression)
# =============================================================================

class TestAlertVisibility:
    def test_stale_resolved_alert_hidden_by_default(self, auth_client, seed_alert):
        c, token = auth_client
        alert_id = seed_alert(status="resolved", updated_at="2024-01-01T00:00:00Z")
        resp = c.get(
            "/api/alerts",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        ids = [a["id"] for a in resp.get_json()]
        assert alert_id not in ids

    def test_stale_resolved_alert_visible_with_hide_closed_false(self, auth_client, seed_alert):
        c, token = auth_client
        alert_id = seed_alert(status="resolved", updated_at="2024-01-01T00:00:00Z")
        resp = c.get(
            "/api/alerts?hide_closed=false",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        ids = [a["id"] for a in resp.get_json()]
        assert alert_id in ids

    def test_active_alert_always_visible(self, auth_client, seed_alert):
        c, token = auth_client
        alert_id = seed_alert(status="new")
        resp = c.get(
            "/api/alerts",
            headers={"Authorization": f"Bearer {token}"},
        )
        ids = [a["id"] for a in resp.get_json()]
        assert alert_id in ids
