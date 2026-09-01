"""
Quick smoke-test for rule_engine.py
Verifies each rule fires correctly and no false positives on benign logs.
"""
from rule_engine import evaluate_log, reset_counters

PASS = 0
FAIL = 0

def check(name, log, expect_rule=None, expect_none=False):
    global PASS, FAIL
    reset_counters()
    results = evaluate_log(log)
    rule_names = [r['rule_name'] for r in results]

    if expect_none:
        if rule_names:
            print(f"  FAIL  {name}: expected NO alert, got {rule_names}")
            FAIL += 1
        else:
            print(f"  PASS  {name}: correctly silent")
            PASS += 1
    elif expect_rule:
        if expect_rule in rule_names:
            print(f"  PASS  {name}: {expect_rule} fired")
            PASS += 1
        else:
            print(f"  FAIL  {name}: expected {expect_rule}, got {rule_names}")
            FAIL += 1

print("=" * 55)
print("  Rule Engine Tests")
print("=" * 55)

# ── BRUTE FORCE: needs threshold (3 hits) ──
# Single failed login should NOT fire
check("brute_force_no_alert_single",
      {'event_id': '4625', 'source_ip': '1.2.3.4', 'source': 'HOST',
       'message': 'account failed to log on', 'timestamp': '2026-01-01T00:00:00Z'},
      expect_none=True)

# After 3 hits from same IP it SHOULD fire — call evaluate 3 times without resetting
from rule_engine import _FAILED_LOGINS
import time
reset_counters()
log_fail = {'event_id': '4625', 'source_ip': '10.0.0.1', 'source': 'VICTIM',
            'message': 'account failed to log on', 'timestamp': '2026-01-01T00:00:00Z'}
evaluate_log(log_fail)  # hit 1 - silent
evaluate_log(log_fail)  # hit 2 - silent
results3 = evaluate_log(log_fail)  # hit 3 - should fire
rule_names3 = [r['rule_name'] for r in results3]
if 'BRUTE_FORCE_LOGIN' in rule_names3:
    print(f"  PASS  brute_force_threshold_fires: BRUTE_FORCE_LOGIN fired on 3rd attempt")
    PASS += 1
else:
    print(f"  FAIL  brute_force_threshold_fires: expected BRUTE_FORCE_LOGIN on 3rd attempt, got {rule_names3}")
    FAIL += 1

# ── PRIVILEGE ESCALATION ──
check("priv_esc_4728",
      {'event_id': '4728', 'source': 'DC01', 'username': 'attacker',
       'message': 'member added to security group', 'timestamp': '2026-01-01T00:00:00Z'},
      expect_rule='PRIVILEGE_ESCALATION')

check("priv_esc_4720",
      {'event_id': '4720', 'source': 'DC01', 'username': 'newadmin',
       'message': 'user account created', 'timestamp': '2026-01-01T00:00:00Z'},
      expect_rule='PRIVILEGE_ESCALATION')

# ── SUSPICIOUS POWERSHELL ──
check("ps_encoded_fires",
      {'event_id': '4104', 'process_name': 'powershell.exe',
       'message': 'Creating Scriptblock text: invoke-mimikatz -dumpcreds',
       'source': 'WS01', 'timestamp': '2026-01-01T00:00:00Z'},
      expect_rule='SUSPICIOUS_POWERSHELL')

# Our own forwarder should NOT fire
check("ps_own_forwarder_silent",
      {'event_id': '4104', 'process_name': 'powershell.exe',
       'message': 'windows-log-forwarder.ps1 -EncodedCommand ...',
       'source': 'WS01', 'timestamp': '2026-01-01T00:00:00Z'},
      expect_none=True)

# Normal PowerShell (no malicious pattern) should NOT fire
check("ps_normal_silent",
      {'event_id': '4104', 'process_name': 'powershell.exe',
       'message': 'Get-Service | Where-Object Status -eq Running',
       'source': 'WS01', 'timestamp': '2026-01-01T00:00:00Z'},
      expect_none=True)

# ── ACCOUNT LOCKOUT ──
check("account_lockout",
      {'event_id': '4740', 'source': 'DC01', 'username': 'jdoe',
       'message': 'user account locked out', 'timestamp': '2026-01-01T00:00:00Z'},
      expect_rule='ACCOUNT_LOCKOUT')

# ── SERVICE INSTALLATION: suspicious (no known-safe provider) ──
check("service_install_suspicious",
      {'event_id': '7045', 'source': 'WS01',
       'message': 'a new service was installed: ServiceName = evilsvc',
       'event_type': 'Service Control Manager',
       'timestamp': '2026-01-01T00:00:00Z'},
      expect_rule='SERVICE_INSTALLATION')

# Known-safe MsiInstaller should NOT fire
check("service_install_msi_silent",
      {'event_id': '7045', 'source': 'WS01',
       'message': 'a new service was installed: MsiInstaller update service',
       'event_type': 'MsiInstaller',
       'timestamp': '2026-01-01T00:00:00Z'},
      expect_none=True)

# ── MALWARE ──
check("malware_detected",
      {'event_id': '1116', 'source': 'WS01',
       'message': 'Windows Defender: threat detected Win32/Mimikatz',
       'event_type': 'Microsoft-Windows-Windows Defender',
       'timestamp': '2026-01-01T00:00:00Z'},
      expect_rule='MALWARE_DETECTED')

# Defender config change should NOT fire
check("malware_config_change_silent",
      {'event_id': '5007', 'source': 'WS01',
       'message': 'Microsoft Defender Antivirus Configuration has changed',
       'event_type': 'Microsoft-Windows-Windows Defender',
       'timestamp': '2026-01-01T00:00:00Z'},
      expect_none=True)

# ── SCHEDULED TASK ──
check("scheduled_task_created",
      {'event_id': '4698', 'source': 'DC01', 'username': 'svc_deploy',
       'message': 'a scheduled task was created: TaskName=\\persistence\\evil',
       'timestamp': '2026-01-01T00:00:00Z'},
      expect_rule='SCHEDULED_TASK_CREATED')

# Windows own tasks should NOT fire
check("scheduled_task_microsoft_silent",
      {'event_id': '4698', 'source': 'DC01',
       'message': 'a scheduled task was created: \\microsoft\\windows\\update',
       'timestamp': '2026-01-01T00:00:00Z'},
      expect_none=True)

# ── BENIGN LOG: should produce no alerts ──
check("benign_info_log",
      {'event_id': '19', 'source': 'WS01',
       'message': 'Windows Update successfully installed KB5034441',
       'source_type': 'windows', 'severity': 'info',
       'timestamp': '2026-01-01T00:00:00Z'},
      expect_none=True)

print()
print("=" * 55)
print(f"  Results: {PASS} passed, {FAIL} failed")
print("=" * 55)
if FAIL > 0:
    exit(1)
