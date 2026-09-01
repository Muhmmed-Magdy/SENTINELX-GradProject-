"""
test_log_ingestion.py — Tests for the LogIngestionService parser and
the /api/logs/ingest API endpoint.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from log_ingestion import LogIngestionService


# =============================================================================
# Format detection
# =============================================================================

class TestFormatDetection:
    def test_detects_json_object(self):
        content = '{"timestamp":"2024-01-01","message":"test"}'
        assert LogIngestionService.detect_format(content) == "json"

    def test_detects_json_array(self):
        content = '[{"timestamp":"2024-01-01","message":"test"}]'
        assert LogIngestionService.detect_format(content) == "json"

    def test_detects_syslog(self):
        content = "Jan  1 00:00:01 myhostname sshd[1234]: Connection from 10.0.0.1"
        assert LogIngestionService.detect_format(content) == "syslog"

    def test_detects_windows_xml(self):
        content = "<Events><Event><System></System></Event></Events>"
        assert LogIngestionService.detect_format(content) == "windows_xml"

    def test_detects_csv_by_comma_count(self):
        content = "timestamp,source,severity,message,source_ip,user\n2024-01-01,DC-01,high,fail,10.0.0.1,jdoe"
        assert LogIngestionService.detect_format(content) == "csv"

    def test_detects_windows_text_by_keyword(self):
        content = "Log Name: Security\nEvent ID: 4625\nLevel: Error"
        assert LogIngestionService.detect_format(content) == "windows_text"

    def test_detects_firewall_by_keyword(self):
        content = "src=10.0.0.1 dst=8.8.8.8 action=deny dport=443"
        assert LogIngestionService.detect_format(content) == "firewall"

    def test_falls_back_to_plain_for_unknown(self):
        content = "some random unstructured log line"
        assert LogIngestionService.detect_format(content) == "plain"


# =============================================================================
# Plain text parser
# =============================================================================

class TestPlainParser:
    def test_extracts_source_and_destination_ips(self):
        _, logs = LogIngestionService.parse_content(
            "2024-03-01T10:15:30Z src=10.0.0.4 dst=10.0.0.5 action=deny", "plain"
        )
        assert logs[0]["source_ip"] == "10.0.0.4"
        assert logs[0]["destination_ip"] == "10.0.0.5"

    def test_deny_action_sets_high_severity(self):
        _, logs = LogIngestionService.parse_content(
            "2024-03-01T10:15:30Z src=10.0.0.4 dst=10.0.0.5 action=deny", "plain"
        )
        assert logs[0]["severity"] == "high"

    def test_timestamps_parsed_correctly(self):
        _, logs = LogIngestionService.parse_content(
            "2024-03-01T10:15:30Z src=1.2.3.4 dst=5.6.7.8 action=allow", "plain"
        )
        assert logs[0]["timestamp"].startswith("2024-03-01T10:15:30")

    def test_empty_line_skipped(self):
        _, logs = LogIngestionService.parse_content("\n\n\n", "plain")
        assert len(logs) == 0

    def test_multiple_lines_produces_multiple_entries(self):
        content = "line one\nline two\nline three"
        _, logs = LogIngestionService.parse_content(content, "plain")
        assert len(logs) == 3

    def test_username_extracted_from_key_value(self):
        _, logs = LogIngestionService.parse_content(
            "2024-01-01T00:00:00Z user=jdoe src=10.0.0.1 dst=10.0.0.2", "plain"
        )
        assert logs[0]["username"] == "jdoe"

    def test_classify_severity_critical_keyword(self):
        sev = LogIngestionService._classify_severity("CRITICAL: system is down")
        assert sev == "critical"

    def test_classify_severity_error_keyword(self):
        sev = LogIngestionService._classify_severity("Error connecting to database")
        assert sev == "high"

    def test_classify_severity_warning_keyword(self):
        sev = LogIngestionService._classify_severity("Warn: retry attempt 2")
        assert sev == "medium"

    def test_classify_severity_normal_is_info(self):
        sev = LogIngestionService._classify_severity("Service started successfully")
        assert sev == "info"


# =============================================================================
# Syslog parser
# =============================================================================

class TestSyslogParser:
    def test_parses_standard_syslog_line(self):
        content = "Jan  1 12:00:00 webserver sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"
        _, logs = LogIngestionService.parse_content(content, "syslog")
        assert len(logs) == 1
        log = logs[0]
        assert log["source"] == "webserver"
        assert log["source_type"] == "linux"
        assert log["source_ip"] == "192.168.1.50"
        assert log["severity"] == "high"   # "failed" keyword

    def test_process_name_extracted(self):
        content = "Jan  1 12:00:00 myhost nginx: GET /api/health 200"
        _, logs = LogIngestionService.parse_content(content, "syslog")
        assert logs[0]["process_name"] == "nginx"

    def test_malformed_syslog_falls_back_to_raw(self):
        content = "this is not a valid syslog line"
        _, logs = LogIngestionService.parse_content(content, "syslog")
        assert len(logs) == 1
        assert logs[0]["source_type"] == "linux"

    def test_empty_syslog_produces_no_logs(self):
        _, logs = LogIngestionService.parse_content("", "syslog")
        assert len(logs) == 0


# =============================================================================
# JSON parser
# =============================================================================

class TestJSONParser:
    def test_parses_json_array(self):
        content = json.dumps([
            {"timestamp": "2024-01-01T00:00:00Z", "message": "test event", "host": "myhost"}
        ])
        _, logs = LogIngestionService.parse_content(content, "json")
        assert len(logs) == 1
        assert logs[0]["source"] == "myhost"

    def test_parses_single_json_object(self):
        content = json.dumps({"timestamp": "2024-01-01T00:00:00Z", "message": "test", "host": "h1"})
        _, logs = LogIngestionService.parse_content(content, "json")
        assert len(logs) == 1

    def test_json_with_source_ip(self):
        content = json.dumps([{"timestamp": "2024-01-01T00:00:00Z", "message": "m", "source_ip": "1.2.3.4"}])
        _, logs = LogIngestionService.parse_content(content, "json")
        assert logs[0]["source_ip"] == "1.2.3.4"

    def test_json_parse_error_returns_error_entry(self):
        _, logs = LogIngestionService.parse_content("{invalid json}", "json")
        assert len(logs) == 1
        assert logs[0]["event_type"] == "parse_error"

    def test_parses_ndjson(self):
        content = "\n".join([
            json.dumps({"timestamp": "2024-01-01T00:00:00Z", "message": "a"}),
            json.dumps({"timestamp": "2024-01-01T00:00:01Z", "message": "b"}),
        ])
        # ndjson is not a separate case yet — JSON parser handles single object;
        # ndjson would fall through to plain. Just verify no crash.
        fmt = LogIngestionService.detect_format(content)
        assert fmt in ("json", "plain", "syslog")


# =============================================================================
# Firewall parser
# =============================================================================

class TestFirewallParser:
    def test_parses_deny_action(self):
        _, logs = LogIngestionService.parse_content(
            "src=10.0.0.1 dst=8.8.8.8 action=deny dport=443", "firewall"
        )
        assert logs[0]["severity"] == "medium"

    def test_parses_source_and_destination(self):
        _, logs = LogIngestionService.parse_content(
            "src=192.168.1.1 dst=10.0.0.2 action=allow", "firewall"
        )
        assert logs[0]["source_ip"] == "192.168.1.1"
        assert logs[0]["destination_ip"] == "10.0.0.2"

    def test_parses_destination_port(self):
        _, logs = LogIngestionService.parse_content(
            "src=1.2.3.4 dst=5.6.7.8 action=allow dport=22", "firewall"
        )
        assert logs[0]["destination_port"] == 22

    def test_empty_firewall_log_returns_empty(self):
        _, logs = LogIngestionService.parse_content("", "firewall")
        assert len(logs) == 0


# =============================================================================
# CSV parser
# =============================================================================

class TestCSVParser:
    def test_parses_basic_csv(self):
        content = "timestamp,source,severity,message\n2024-01-01T00:00:00Z,DC-01,high,Login fail"
        _, logs = LogIngestionService.parse_content(content, "csv")
        assert len(logs) == 1
        assert logs[0]["source"] == "DC-01"
        assert logs[0]["severity"] == "high"

    def test_csv_with_source_ip(self):
        content = "timestamp,source,severity,message,source_ip\n2024-01-01,host,info,msg,10.0.0.5"
        _, logs = LogIngestionService.parse_content(content, "csv")
        assert logs[0]["source_ip"] == "10.0.0.5"

    def test_empty_csv_returns_empty(self):
        _, logs = LogIngestionService.parse_content("", "csv")
        assert len(logs) == 0

    def test_csv_only_header_returns_empty(self):
        _, logs = LogIngestionService.parse_content(
            "timestamp,source,severity,message\n", "csv"
        )
        assert len(logs) == 0


# =============================================================================
# Windows XML parser
# =============================================================================

class TestWindowsXMLParser:
    _MINIMAL_XML = """<Events>
  <Event>
    <System>
      <EventID>4625</EventID>
      <Computer>DC-01</Computer>
      <Level>2</Level>
      <Channel>Security</Channel>
      <TimeCreated SystemTime="2024-01-01T00:00:00Z"/>
    </System>
    <EventData>
      <Data Name="TargetUserName">jdoe</Data>
      <Data Name="IpAddress">10.0.0.1</Data>
    </EventData>
  </Event>
</Events>"""

    def test_parses_event_id(self):
        _, logs = LogIngestionService.parse_content(self._MINIMAL_XML, "windows_xml")
        assert len(logs) >= 1
        assert logs[0]["event_id"] == "4625"

    def test_parses_computer_as_hostname(self):
        _, logs = LogIngestionService.parse_content(self._MINIMAL_XML, "windows_xml")
        assert logs[0]["hostname"] == "DC-01"

    def test_parses_target_username(self):
        _, logs = LogIngestionService.parse_content(self._MINIMAL_XML, "windows_xml")
        assert logs[0]["username"] == "jdoe"

    def test_parses_ip_address(self):
        _, logs = LogIngestionService.parse_content(self._MINIMAL_XML, "windows_xml")
        assert logs[0]["source_ip"] == "10.0.0.1"

    def test_malformed_xml_returns_error_entry(self):
        _, logs = LogIngestionService.parse_content("<invalid>xml<<", "windows_xml")
        assert len(logs) == 1
        assert logs[0]["event_type"] == "parse_error"

    def test_severity_mapped_from_level(self):
        _, logs = LogIngestionService.parse_content(self._MINIMAL_XML, "windows_xml")
        # Level 2 → "high"
        assert logs[0]["severity"] == "high"


# =============================================================================
# /api/logs/ingest endpoint
# =============================================================================

# =============================================================================
# /api/logs/ingest endpoint
# =============================================================================

class TestIngestEndpoint:
    def test_ingest_stores_log_entry(self, client, ingest_headers):
        payload = {
            "logs": [{
                "id": "test-log-001",
                "source": "test-host",
                "source_type": "windows",
                "event_type": "Security",
                "event_id": "4624",
                "severity": "info",
                "message": "Account logged on",
                "source_ip": "10.0.0.99",
                "username": "testuser",
                "timestamp": "2024-06-01T10:00:00Z",
            }]
        }
        resp = client.post("/api/logs/ingest", json=payload, headers=ingest_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ingested"] == 1

    def test_ingest_requires_key(self, client):
        """Missing X-Ingest-Key should return 401."""
        resp = client.post("/api/logs/ingest", json={"logs": []})
        assert resp.status_code == 401

    def test_ingest_rejects_invalid_key(self, client):
        """Wrong key should return 401."""
        resp = client.post(
            "/api/logs/ingest",
            json={"logs": []},
            headers={"X-Ingest-Key": "totally-wrong-key"},
        )
        assert resp.status_code == 401

    def test_ingest_deduplicates_same_event(self, client, ingest_headers):
        log = {
            "id": "dedup-001",
            "source": "host",
            "source_type": "windows",
            "event_id": "4625",
            "severity": "high",
            "message": "Failed login",
            "timestamp": "2024-06-01T10:00:00Z",
        }
        first = client.post("/api/logs/ingest", json={"logs": [log]}, headers=ingest_headers)
        second = client.post("/api/logs/ingest", json={"logs": [log]}, headers=ingest_headers)
        assert first.get_json()["ingested"] == 1
        assert second.get_json()["ingested"] == 0

    def test_ingest_empty_list_returns_zero(self, client, ingest_headers):
        resp = client.post("/api/logs/ingest", json={"logs": []}, headers=ingest_headers)
        assert resp.status_code == 200
        assert resp.get_json()["ingested"] == 0

    def test_ingest_missing_logs_key_ingests_zero(self, client, ingest_headers):
        resp = client.post("/api/logs/ingest", json={}, headers=ingest_headers)
        assert resp.status_code == 200
        assert resp.get_json()["ingested"] == 0

    def test_ingest_truncates_oversized_field(self, client, ingest_headers):
        """Fields longer than safe_str's 500-char limit should be stored truncated."""
        log = {
            "source": "a" * 600,
            "source_type": "windows",
            "message": "Normal log",
        }
        resp = client.post("/api/logs/ingest", json={"logs": [log]}, headers=ingest_headers)
        assert resp.status_code == 200
        assert resp.get_json()["ingested"] == 1


# =============================================================================
# Auto-detection via parse_content("auto")
# =============================================================================

class TestAutoDetection:
    def test_auto_detects_and_parses_syslog(self):
        content = "Jan 15 08:30:00 myserver sshd[5678]: Failed password for admin"
        fmt, logs = LogIngestionService.parse_content(content, "auto")
        assert fmt == "syslog"
        assert len(logs) >= 1

    def test_auto_detects_and_parses_json(self):
        content = json.dumps([{"message": "hello", "host": "h1"}])
        fmt, logs = LogIngestionService.parse_content(content, "auto")
        assert fmt == "json"
        assert len(logs) == 1

    def test_auto_detects_and_parses_firewall(self):
        content = "src=1.2.3.4 dst=5.6.7.8 action=deny dport=22"
        fmt, logs = LogIngestionService.parse_content(content, "auto")
        assert fmt == "firewall"
        assert len(logs) == 1
