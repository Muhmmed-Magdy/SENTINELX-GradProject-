"""
test_mvp_completion.py — Tests for Phase 3 MVP completion features.

Covers:
  - Alert FP classification endpoint
  - Alert correlations endpoint
  - SOC metrics endpoint
  - Enhanced incident PATCH (notes, resolution, assigned_analyst, affected_hosts, timeline)
  - Incident status uses expanded status set (new, triaged, investigating, contained, resolved)
"""
import json
import uuid
import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _auth(client, token):
    return {"Authorization": f"Bearer {token}"}


def _create_alert(client, token, **overrides):
    """Seed an alert via the DB directly using seed_alert fixture."""
    pass  # Use seed_alert fixture instead


# ══════════════════════════════════════════════════════════════════════════════
# 1. FP CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════

class TestFPClassification:
    def test_classify_true_positive(self, auth_client, seed_alert):
        client, token = auth_client
        alert_id = seed_alert()
        resp = client.post(
            f"/api/alerts/{alert_id}/classify",
            json={"classification": "TRUE_POSITIVE", "reason": "Confirmed malicious activity"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["classification"] == "TRUE_POSITIVE"
        assert data["reason"] == "Confirmed malicious activity"
        assert "classified_by" in data
        assert data["status_changed"] is False  # TRUE_POSITIVE doesn't change status

    def test_classify_false_positive_changes_status(self, auth_client, seed_alert):
        client, token = auth_client
        alert_id = seed_alert(status="investigating")
        resp = client.post(
            f"/api/alerts/{alert_id}/classify",
            json={"classification": "FALSE_POSITIVE", "reason": "Scheduled maintenance task"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["classification"] == "FALSE_POSITIVE"
        assert data["status_changed"] is True
        assert data["new_status"] == "false_positive"

    def test_classify_benign_changes_status(self, auth_client, seed_alert):
        client, token = auth_client
        alert_id = seed_alert(status="new")
        resp = client.post(
            f"/api/alerts/{alert_id}/classify",
            json={"classification": "BENIGN", "reason": "Expected admin activity"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["classification"] == "BENIGN"
        assert data["status_changed"] is True

    def test_classify_needs_investigation(self, auth_client, seed_alert):
        client, token = auth_client
        alert_id = seed_alert()
        resp = client.post(
            f"/api/alerts/{alert_id}/classify",
            json={"classification": "NEEDS_INVESTIGATION", "reason": "Unclear context, needs more data"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["classification"] == "NEEDS_INVESTIGATION"
        assert data["status_changed"] is False

    def test_classify_invalid_value(self, auth_client, seed_alert):
        client, token = auth_client
        alert_id = seed_alert()
        resp = client.post(
            f"/api/alerts/{alert_id}/classify",
            json={"classification": "MAYBE", "reason": "Some reason"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 400

    def test_classify_missing_reason(self, auth_client, seed_alert):
        client, token = auth_client
        alert_id = seed_alert()
        resp = client.post(
            f"/api/alerts/{alert_id}/classify",
            json={"classification": "TRUE_POSITIVE"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 400

    def test_classify_readonly_forbidden(self, readonly_client, seed_alert):
        client, token = readonly_client
        alert_id = seed_alert()
        resp = client.post(
            f"/api/alerts/{alert_id}/classify",
            json={"classification": "BENIGN", "reason": "test"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 403

    def test_classify_appears_in_alert_detail(self, auth_client, seed_alert):
        client, token = auth_client
        alert_id = seed_alert()
        # Classify
        client.post(
            f"/api/alerts/{alert_id}/classify",
            json={"classification": "TRUE_POSITIVE", "reason": "Verified by SOC"},
            headers=_auth(client, token),
        )
        # Fetch alert
        resp = client.get(f"/api/alerts/{alert_id}", headers=_auth(client, token))
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["fp_classification"] == "TRUE_POSITIVE"
        assert data["fp_reason"] == "Verified by SOC"
        assert data["fp_classified_by"] != ""

    def test_classify_not_found(self, auth_client):
        client, token = auth_client
        resp = client.post(
            "/api/alerts/nonexistent-id/classify",
            json={"classification": "BENIGN", "reason": "test"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 2. ALERT CORRELATIONS
# ══════════════════════════════════════════════════════════════════════════════

class TestAlertCorrelations:
    def test_correlations_returns_structure(self, auth_client, seed_alert):
        client, token = auth_client
        alert_id = seed_alert(source_ip="10.0.0.50")
        resp = client.get(f"/api/alerts/{alert_id}/correlations", headers=_auth(client, token))
        assert resp.status_code == 200
        data = resp.get_json()
        assert "correlations" in data
        assert "total" in data
        assert "alert_id" in data
        assert data["alert_id"] == alert_id

    def test_correlations_finds_same_ip(self, auth_client, seed_alert):
        client, token = auth_client
        ip = "192.168.1.200"
        a1 = seed_alert(source_ip=ip, title="Alert A", rule_name="BRUTE_FORCE")
        a2 = seed_alert(source_ip=ip, title="Alert B", rule_name="PRIVILEGE_ESCALATION")
        resp = client.get(f"/api/alerts/{a1}/correlations", headers=_auth(client, token))
        assert resp.status_code == 200
        data = resp.get_json()
        ids = [c["alert_id"] for c in data["correlations"]]
        assert a2 in ids
        reasons = [c["relationship_reason"] for c in data["correlations"] if c["alert_id"] == a2]
        assert any("IP" in r for r in reasons)

    def test_correlations_finds_same_user(self, auth_client, seed_alert):
        client, token = auth_client
        a1 = seed_alert(username="jdoe", source_ip="10.1.1.1")
        a2 = seed_alert(username="jdoe", source_ip="10.2.2.2")
        resp = client.get(f"/api/alerts/{a1}/correlations", headers=_auth(client, token))
        data = resp.get_json()
        ids = [c["alert_id"] for c in data["correlations"]]
        assert a2 in ids

    def test_correlations_excludes_self(self, auth_client, seed_alert):
        client, token = auth_client
        alert_id = seed_alert(source_ip="10.5.5.5")
        resp = client.get(f"/api/alerts/{alert_id}/correlations", headers=_auth(client, token))
        data = resp.get_json()
        ids = [c["alert_id"] for c in data["correlations"]]
        assert alert_id not in ids

    def test_correlations_not_found(self, auth_client):
        client, token = auth_client
        resp = client.get("/api/alerts/bad-id/correlations", headers=_auth(client, token))
        assert resp.status_code == 404

    def test_correlations_unauthenticated(self, client, seed_alert):
        alert_id = seed_alert()
        resp = client.get(f"/api/alerts/{alert_id}/correlations")
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# 3. SOC METRICS
# ══════════════════════════════════════════════════════════════════════════════

class TestSocMetrics:
    def test_metrics_returns_all_fields(self, auth_client):
        client, token = auth_client
        resp = client.get("/api/soc/metrics", headers=_auth(client, token))
        assert resp.status_code == 200
        data = resp.get_json()
        required = [
            "total_events", "total_alerts", "critical_alerts", "high_alerts",
            "open_alerts", "resolved_alerts", "false_positive_alerts",
            "total_incidents", "open_incidents", "resolved_incidents",
            "false_positive_rate", "analyst_workload",
            "top_detection_rules", "top_mitre", "by_severity", "by_status",
        ]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_metrics_values_are_real(self, auth_client, seed_alert):
        client, token = auth_client
        # Seed some alerts
        seed_alert(severity="critical", status="new")
        seed_alert(severity="high", status="investigating")
        seed_alert(severity="medium", status="resolved")
        resp = client.get("/api/soc/metrics", headers=_auth(client, token))
        data = resp.get_json()
        # Must reflect real DB data
        assert data["total_alerts"] >= 3
        assert data["critical_alerts"] >= 1
        assert data["resolved_alerts"] >= 1

    def test_metrics_fp_rate_null_when_no_classifications(self, auth_client):
        client, token = auth_client
        resp = client.get("/api/soc/metrics", headers=_auth(client, token))
        data = resp.get_json()
        # No classifications seeded, so rate should be None
        assert data["false_positive_rate"] is None

    def test_metrics_fp_rate_calculated(self, auth_client, seed_alert):
        client, token = auth_client
        a1 = seed_alert()
        a2 = seed_alert()
        # Classify one as FP
        client.post(
            f"/api/alerts/{a1}/classify",
            json={"classification": "FALSE_POSITIVE", "reason": "Noise"},
            headers=_auth(client, token),
        )
        client.post(
            f"/api/alerts/{a2}/classify",
            json={"classification": "TRUE_POSITIVE", "reason": "Real"},
            headers=_auth(client, token),
        )
        resp = client.get("/api/soc/metrics", headers=_auth(client, token))
        data = resp.get_json()
        assert data["false_positive_rate"] == 50.0  # 1 FP out of 2 classified

    def test_metrics_unauthenticated(self, client):
        resp = client.get("/api/soc/metrics")
        assert resp.status_code == 401

    def test_metrics_never_hardcodes(self, auth_client):
        """Metrics on empty DB should be all zeros / null, not hardcoded values."""
        client, token = auth_client
        resp = client.get("/api/soc/metrics", headers=_auth(client, token))
        data = resp.get_json()
        assert data["total_events"] == 0
        assert data["total_alerts"] == 0
        assert data["total_incidents"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# 4. ENHANCED INCIDENT PATCH
# ══════════════════════════════════════════════════════════════════════════════

class TestEnhancedIncidentPatch:
    def _create_incident(self, client, token, **kwargs):
        data = {"title": "Test Incident", "severity": "high", **kwargs}
        resp = client.post("/api/incidents", json=data, headers=_auth(client, token))
        assert resp.status_code in (200, 201)
        return resp.get_json()["id"]

    def test_update_notes(self, auth_client):
        client, token = auth_client
        iid = self._create_incident(client, token)
        resp = client.patch(
            f"/api/incidents/{iid}",
            json={"notes": "Investigation notes here"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 200
        # Fetch and verify
        detail = client.get(f"/api/incidents/{iid}", headers=_auth(client, token)).get_json()
        assert detail["notes"] == "Investigation notes here"

    def test_update_resolution(self, auth_client):
        client, token = auth_client
        iid = self._create_incident(client, token)
        resp = client.patch(
            f"/api/incidents/{iid}",
            json={"resolution": "Blocked IP at firewall", "status": "resolved"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 200
        detail = client.get(f"/api/incidents/{iid}", headers=_auth(client, token)).get_json()
        assert detail["resolution"] == "Blocked IP at firewall"

    def test_update_assigned_analyst(self, auth_client):
        client, token = auth_client
        iid = self._create_incident(client, token)
        resp = client.patch(
            f"/api/incidents/{iid}",
            json={"assigned_analyst": "analyst@soc.local"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 200
        detail = client.get(f"/api/incidents/{iid}", headers=_auth(client, token)).get_json()
        assert detail["assigned_analyst"] == "analyst@soc.local"

    def test_expanded_statuses(self, auth_client):
        client, token = auth_client
        for status in ["triaged", "investigating", "contained", "resolved"]:
            iid = self._create_incident(client, token)
            resp = client.patch(
                f"/api/incidents/{iid}",
                json={"status": status},
                headers=_auth(client, token),
            )
            assert resp.status_code == 200, f"Failed for status: {status}"

    def test_invalid_status_rejected(self, auth_client):
        client, token = auth_client
        iid = self._create_incident(client, token)
        resp = client.patch(
            f"/api/incidents/{iid}",
            json={"status": "completed"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 400

    def test_update_affected_hosts(self, auth_client):
        client, token = auth_client
        iid = self._create_incident(client, token)
        resp = client.patch(
            f"/api/incidents/{iid}",
            json={"affected_hosts": ["dc-01.corp", "wkstn-42.corp"]},
            headers=_auth(client, token),
        )
        assert resp.status_code == 200
        detail = client.get(f"/api/incidents/{iid}", headers=_auth(client, token)).get_json()
        assert "dc-01.corp" in detail["affected_hosts"]

    def test_not_found(self, auth_client):
        client, token = auth_client
        resp = client.patch(
            "/api/incidents/does-not-exist",
            json={"notes": "test"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 404

    def test_readonly_forbidden(self, readonly_client):
        client, token = readonly_client
        resp = client.patch(
            "/api/incidents/any-id",
            json={"notes": "test"},
            headers=_auth(client, token),
        )
        assert resp.status_code == 403
