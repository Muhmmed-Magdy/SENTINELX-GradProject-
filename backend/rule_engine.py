"""
Detection Rule Engine
=====================
Design principles:
  - Every rule documents its logic, severity, confidence, and MITRE ATT&CK mapping.
  - Rules return structured evidence, not just a title/description.
  - Brute-force and threshold rules use in-memory sliding windows so a single
    failed login does NOT produce an alert.
  - All pattern matches are case-insensitive.
  - The engine never raises exceptions — malformed logs are skipped gracefully.

Rule index:
  0  BRUTE_FORCE_LOGIN         T1110
  1  PRIVILEGE_ESCALATION      T1078 / T1068
  2  SUSPICIOUS_POWERSHELL     T1059.001 / T1027
  3  DATA_EXFILTRATION         T1048
  4  LATERAL_MOVEMENT          T1021 / T1570
  5  MALWARE_DETECTED          T1204 / T1059
  6  UNUSUAL_LOGIN_TIME        T1078
  7  SERVICE_INSTALLATION      T1543.003
  8  FIREWALL_ANOMALY          T1562.004
  9  DNS_TUNNELING             T1071.004
  10 ACCOUNT_LOCKOUT           T1110.003
  11 SCHEDULED_TASK_CREATED    T1053.005
"""

import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Rule definition
# ─────────────────────────────────────────────────────────────────────────────

class Rule:
    __slots__ = ('name', 'description', 'severity', 'mitre_techniques',
                 'kill_chain_phase', 'confidence')

    def __init__(self, name: str, description: str, severity: str,
                 mitre_techniques: list = None, kill_chain_phase: str = '',
                 confidence: int = 70):
        self.name             = name
        self.description      = description
        self.severity         = severity
        self.mitre_techniques = mitre_techniques or []
        self.kill_chain_phase = kill_chain_phase
        self.confidence       = confidence   # 0-100 base confidence before adjustments


RULES: list[Rule] = [
    Rule("BRUTE_FORCE_LOGIN",
         "Multiple failed authentication attempts detected from the same source",
         "high", ["T1110 - Brute Force"], "Credential Access", confidence=85),

    Rule("PRIVILEGE_ESCALATION",
         "User account added to a privileged group or new privileged account created",
         "critical", ["T1078 - Valid Accounts", "T1068 - Exploitation for Privilege Escalation"],
         "Privilege Escalation", confidence=80),

    Rule("SUSPICIOUS_POWERSHELL",
         "PowerShell execution with characteristics of obfuscation or remote code retrieval",
         "critical", ["T1059.001 - Command and Scripting Interpreter: PowerShell",
                       "T1027 - Obfuscated Files or Information"],
         "Execution", confidence=75),

    Rule("DATA_EXFILTRATION",
         "Potential data exfiltration pattern detected",
         "critical", ["T1048 - Exfiltration Over Alternative Protocol"],
         "Exfiltration", confidence=65),

    Rule("LATERAL_MOVEMENT",
         "Remote interactive logon or lateral movement tool usage detected",
         "high", ["T1021 - Remote Services", "T1570 - Lateral Tool Transfer"],
         "Lateral Movement", confidence=70),

    Rule("MALWARE_DETECTED",
         "Malware, ransomware, or malicious file activity detected by endpoint protection",
         "critical", ["T1204 - User Execution", "T1059 - Command and Scripting Interpreter"],
         "Installation", confidence=90),

    Rule("UNUSUAL_LOGIN_TIME",
         "Successful interactive logon outside normal business hours (23:00-06:00)",
         "medium", ["T1078 - Valid Accounts"], "Initial Access", confidence=60),

    Rule("SERVICE_INSTALLATION",
         "A new Windows service was installed — possible persistence mechanism",
         "high", ["T1543.003 - Create or Modify System Process: Windows Service"],
         "Persistence", confidence=70),

    Rule("FIREWALL_ANOMALY",
         "Firewall rule modification or policy change detected",
         "medium", ["T1562.004 - Impair Defenses: Disable or Modify System Firewall"],
         "Defense Evasion", confidence=65),

    Rule("DNS_TUNNELING",
         "Abnormally large DNS payload detected — possible DNS tunnelling",
         "high", ["T1071.004 - Application Layer Protocol: DNS"],
         "Command and Control", confidence=60),

    Rule("ACCOUNT_LOCKOUT",
         "User account locked out after repeated failed authentication attempts",
         "high", ["T1110.003 - Brute Force: Password Spraying"],
         "Credential Access", confidence=85),

    Rule("PASSWORD_SPRAYING",
         "Password spraying activity detected across multiple accounts from the same source",
         "high", ["T1110.003 - Brute Force: Password Spraying"],
         "Credential Access", confidence=88),

    Rule("SCHEDULED_TASK_CREATED",
         "A new scheduled task was created — possible persistence or execution mechanism",
         "high", ["T1053.005 - Scheduled Task/Job: Scheduled Task"],
         "Persistence", confidence=70),
]

# Fast lookup by name
_RULE_MAP: dict[str, Rule] = {r.name: r for r in RULES}
_RULE_ENABLED: dict[str, bool] = {r.name: True for r in RULES}

_RULE_CATEGORIES = {
    'BRUTE_FORCE_LOGIN': 'Credential Access',
    'PASSWORD_SPRAYING': 'Credential Access',
    'PRIVILEGE_ESCALATION': 'Privilege Escalation',
    'SUSPICIOUS_POWERSHELL': 'Execution',
    'DATA_EXFILTRATION': 'Exfiltration',
    'LATERAL_MOVEMENT': 'Lateral Movement',
    'MALWARE_DETECTED': 'Malware',
    'UNUSUAL_LOGIN_TIME': 'Authentication',
    'SERVICE_INSTALLATION': 'Persistence',
    'FIREWALL_ANOMALY': 'Defense Evasion',
    'DNS_TUNNELING': 'Command and Control',
    'ACCOUNT_LOCKOUT': 'Credential Access',
    'SCHEDULED_TASK_CREATED': 'Persistence',
}

# ─────────────────────────────────────────────────────────────────────────────
# Sliding-window counters for threshold-based rules
# Structure: { key: [(timestamp_float, ...), ...] }
# ─────────────────────────────────────────────────────────────────────────────

_FAILED_LOGINS: dict[str, list[float]] = defaultdict(list)
_PASSWORD_SPRAYING_ATTEMPTS: dict[str, list[tuple[float, str]]] = defaultdict(list)

# Thresholds
_BRUTE_FORCE_THRESHOLD = 3      # failures within window → alert (tune this higher to reduce FP)
_BRUTE_FORCE_WINDOW    = 300    # 5 minutes in seconds

# Additional tuning and allowlists
_INTERNAL_IP_PREFIXES = ('10.', '192.168.', '127.', '::1')


# Known-legitimate services that should NOT trigger SERVICE_INSTALLATION alerts
_KNOWN_SAFE_SERVICE_PROVIDERS = frozenset({
    'microsoft-windows-windowsupdateclient',
    'trustedinstaller',
    'windows modules installer',
    'windows update',
    'msiinstaller',
})

# Our own forwarder identifiers — never alert on these
_OWN_FORWARDER_SIGNATURES = (
    'windows-log-forwarder',
    'soc-log-forwarder',
    'ai soc dashboard',
    'soc dashboard',
    'ai-soc-dashboard',
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _norm(s: Optional[str]) -> str:
    """Return lowercase string, never None."""
    return (s or '').lower()


def _is_own_tool(msg: str, process: str) -> bool:
    """Return True if the log originates from our own forwarder/dashboard."""
    combined = msg + process
    return any(sig in combined for sig in _OWN_FORWARDER_SIGNATURES)


def _is_private_ip(ip: str) -> bool:
    """Basic check for common private IP prefixes."""
    if not ip:
        return False
    return ip.startswith(('10.', '192.168.')) or ip.startswith('127.') or ip.startswith('::1') or ip.startswith('172.')


def _shannon_entropy(s: str) -> float:
    """Compute a simple Shannon entropy for a string (used for DNS name entropy)."""
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for v in freq.values():
        p = v / length
        entropy -= p * log2(p)
    return entropy


def _log_timestamp_as_float(log: dict) -> float:
    """Parse log timestamp to a Unix float; fallback to wall-clock now."""
    ts_str = log.get('timestamp', '')
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return dt.timestamp()
    except Exception:
        return time.time()


def _purge_window(bucket: list[float], window: int) -> list[float]:
    """Remove entries older than window seconds from a timestamp list."""
    cutoff = time.time() - window
    return [t for t in bucket if t > cutoff]


def _make_alert(rule: Rule, log: dict, evidence: dict = None,
                confidence_override: int = None) -> dict:
    """
    Build a structured alert dict from a rule and a log entry.
    Evidence dict allows callers to attach rule-specific supporting data.
    """
    ip = log.get('source_ip', '')
    if not ip:
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', log.get('message', ''))
        ip = m.group(1) if m else ''

    source_label = log.get('source') or log.get('hostname') or 'Unknown'
    confidence    = confidence_override if confidence_override is not None else rule.confidence

    return {
        'title':           f"{rule.name.replace('_', ' ').title()} — {source_label}",
        'description':     (
            f"{rule.description}. "
            f"Source: {source_label} | "
            f"Event ID: {log.get('event_id', 'N/A')} | "
            f"User: {log.get('username', 'N/A')}"
        ),
        'severity':        rule.severity,
        'rule_name':       rule.name,
        'confidence':      confidence,
        'mitre_techniques': rule.mitre_techniques,
        'kill_chain_phase': rule.kill_chain_phase,
        'source':          log.get('source', ''),
        'source_ip':       ip,
        'destination_ip':  log.get('destination_ip', ''),
        'username':        log.get('username', ''),
        'hostname':        log.get('hostname', log.get('source', '')),
        'related_log_ids': [log.get('id', '')] if log.get('id') else [],
        'evidence':        evidence or {
            'event_id':   log.get('event_id', ''),
            'message':    (log.get('message', '') or '')[:400],
            'timestamp':  log.get('timestamp', ''),
            'source_type': log.get('source_type', ''),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main evaluation entry point
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_log(log: dict) -> list[dict]:
    """
    Evaluate all rules against a single log entry.
    Returns a (possibly empty) list of alert dicts.
    Designed to be called for every ingested log.
    """
    if not isinstance(log, dict):
        return []

    try:
        return _evaluate(log)
    except Exception:
        # Never crash the ingestion pipeline
        return []


def _evaluate(log: dict) -> list[dict]:
    triggered = []

    msg        = _norm(log.get('message'))
    event_id   = str(log.get('event_id', ''))
    process    = _norm(log.get('process_name'))
    source_type = _norm(log.get('source_type', ''))
    source     = _norm(log.get('source', ''))
    username   = _norm(log.get('username', ''))
    source_ip  = log.get('source_ip', '')
    event_type = _norm(log.get('event_type', ''))
    ts_float   = _log_timestamp_as_float(log)

    # ── 0. BRUTE FORCE LOGIN ────────────────────────────────────────────────
    # Threshold: 3 failures within 5 minutes from the same (source_ip or source)
    is_failed_login = (
        event_id == '4625' or
        event_id == '4771' or
        'failed password' in msg or
        'authentication failure' in msg or
        'account failed to log on' in msg or
        'invalid password' in msg or
        'login failed' in msg or
        'failed login' in msg
    )
    if is_failed_login:
        # Use a bucket per (source_ip, username) when available to reduce NAT false-positives
        bucket_key = (source_ip or source or 'unknown') + '|' + (username or '')
        now = time.time()
        # Use wall-clock time for the window, not the event's own timestamp
        _FAILED_LOGINS[bucket_key] = [t for t in _FAILED_LOGINS[bucket_key]
                                       if now - t < _BRUTE_FORCE_WINDOW]
        _FAILED_LOGINS[bucket_key].append(now)
        count = len(_FAILED_LOGINS[bucket_key])
        if count >= _BRUTE_FORCE_THRESHOLD:
            # Scale confidence with count: 3=85, 5=90, 10+=95
            conf = min(95, 85 + (count - _BRUTE_FORCE_THRESHOLD) * 2)
            triggered.append(_make_alert(
                _RULE_MAP['BRUTE_FORCE_LOGIN'], log,
                evidence={
                    'failure_count': count,
                    'window_seconds': _BRUTE_FORCE_WINDOW,
                    'bucket_key':    bucket_key,
                    'event_id':      event_id,
                    'message':       (log.get('message', '') or '')[:400],
                    'timestamp':     log.get('timestamp', ''),
                },
                confidence_override=conf,
            ))

    # ── 1. PRIVILEGE ESCALATION ─────────────────────────────────────────────
    # Event IDs: 4728 (global group), 4732 (local group), 4756 (universal group),
    #            4720 (account created), 4672 (special privileges at logon)
    # For Linux: only fire on actual group/privilege changes, NOT routine sudo sessions.
    PRIV_ESC_IDS = {'4728', '4732', '4756', '4720'}
    is_priv_esc = (
        event_id in PRIV_ESC_IDS or
        ('added to' in msg and 'group' in msg and 'administrators' in msg) or
        # Linux: only fire on real escalation — group membership changes or su to root
        # NOT on pam sudo session open/close (those are normal operations)
        ('sudo' in msg and 'root' in msg and 'session' not in msg) or
        ('usermod' in msg or 'groupadd' in msg or 'useradd' in msg) or
        ('added' in msg and ('sudo' in msg or 'wheel' in msg or 'admin' in msg))
    )
    if is_priv_esc:
        triggered.append(_make_alert(
            _RULE_MAP['PRIVILEGE_ESCALATION'], log,
            evidence={
                'event_id':   event_id,
                'username':   log.get('username', ''),
                'message':    (log.get('message', '') or '')[:400],
                'timestamp':  log.get('timestamp', ''),
            }
        ))

    # ── 2. SUSPICIOUS POWERSHELL ────────────────────────────────────────────
    # Only flag genuinely malicious PowerShell patterns.
    # Excludes our own forwarder/dashboard scripts and 4100 scripting warnings.
    PS_MALICIOUS = (
        '-encodedcommand', 'invoke-expression', 'iex(',
        'downloadstring', 'downloadfile',
        'invoke-mimikatz', 'invoke-bloodhound', 'invoke-shellcode',
        'amsibypass', 'amsi.utils', 'reflection.assembly',
        'frombase64string', 'system.net.webclient',
        'net.webclient', 'hidden -windowstyle', 'bypass -noprofile',
    )
    is_ps = 'powershell' in process or 'powershell' in event_type or 'powershell' in msg
    if is_ps and not _is_own_tool(msg, process) and event_id != '4100':
        matched = [p for p in PS_MALICIOUS if p in msg]
        PS_HIGH_CONFIDENCE = ('invoke-mimikatz', 'invoke-bloodhound', 'invoke-shellcode', 'amsibypass', 'iex(')
        # Reduce false positives: require either a critical pattern (download/encoded) or multiple matches
        critical_indicators = any(k in msg for k in ('-encodedcommand', 'downloadstring', 'downloadfile', 'frombase64string'))
        high_conf = any(h in msg for h in PS_HIGH_CONFIDENCE)
        if matched and (critical_indicators or len(matched) > 1 or len(msg) > 120 or high_conf):
            triggered.append(_make_alert(
                _RULE_MAP['SUSPICIOUS_POWERSHELL'], log,
                evidence={
                    'matched_patterns': matched,
                    'event_id':   event_id,
                    'message':    (log.get('message', '') or '')[:400],
                    'timestamp':  log.get('timestamp', ''),
                }
            ))

    # ── 3. DATA EXFILTRATION ────────────────────────────────────────────────
    EXFIL_KEYWORDS = (
        'large transfer', 'exfiltration', 'data leak',
        'sensitive data', 'unauthorized upload',
    )
    if any(k in msg for k in EXFIL_KEYWORDS):
        triggered.append(_make_alert(_RULE_MAP['DATA_EXFILTRATION'], log))

    # ── 4. LATERAL MOVEMENT ─────────────────────────────────────────────────
    # Type 10 = RemoteInteractive (RDP), Type 3 from external IP = network logon
    is_rdp = event_id == '4624' and 'logon type:\t\t10' in msg.replace(' ', '\t')
    is_type3_external = (
        event_id == '4624' and
        'logon type' in msg and ('3' in msg) and
        source_ip and not source_ip.startswith(('10.', '192.168.', '172.', '127.', '::1'))
    )
    LATERAL_TOOLS = ('psexec', 'wmiexec', 'wmic /node', 'invoke-wmimethod',
                     'invoke-pssession', 'enter-pssession', 'smbexec', 'atexec')
    has_lateral_tool = any(t in msg for t in LATERAL_TOOLS)

    if is_rdp or is_type3_external or has_lateral_tool:
        triggered.append(_make_alert(
            _RULE_MAP['LATERAL_MOVEMENT'], log,
            evidence={
                'indicator': 'rdp' if is_rdp else ('external_network_logon' if is_type3_external else 'lateral_tool'),
                'source_ip': source_ip,
                'event_id':  event_id,
                'message':   (log.get('message', '') or '')[:400],
                'timestamp': log.get('timestamp', ''),
            }
        ))

    # ── 5. MALWARE DETECTED ─────────────────────────────────────────────────
    # Only fires on actual AV/EDR detection events, not config changes
    MALWARE_POSITIVE = (
        'threat detected', 'threat found', 'virus detected',
        'malware detected', 'ransomware detected', 'trojan detected',
        'infected file', 'quarantined', 'severe threat', 'malicious file',
        'win32/', 'trojan:', 'ransom:', 'backdoor:', 'exploit:',
    )
    if any(k in msg for k in MALWARE_POSITIVE):
        triggered.append(_make_alert(_RULE_MAP['MALWARE_DETECTED'], log))

    # ── 6. UNUSUAL LOGIN TIME ───────────────────────────────────────────────
    # Successful interactive logon (type 2 = interactive, type 10 = RDP)
    # outside 06:00–23:00 local time — only for non-service/non-SYSTEM accounts
    SYSTEM_ACCOUNTS = frozenset({'system', 'local service', 'network service',
                                  'desktop window manager', 'window manager'})
    is_successful_logon = event_id in ('4624',) and username not in SYSTEM_ACCOUNTS
    if is_successful_logon and username and len(username) > 1:
        try:
            dt = datetime.fromisoformat(
                (log.get('timestamp') or '').replace('Z', '+00:00')
            ).astimezone()
            hour = dt.hour
            if hour >= 23 or hour < 6:   # after 11 PM or before 6 AM
                triggered.append(_make_alert(
                    _RULE_MAP['UNUSUAL_LOGIN_TIME'], log,
                    evidence={
                        'hour':     hour,
                        'username': username,
                        'event_id': event_id,
                        'timestamp': log.get('timestamp', ''),
                    },
                    confidence_override=55,
                ))
        except Exception:
            pass

    # ── 7. SERVICE INSTALLATION ─────────────────────────────────────────────
    # Event ID 7045 — exclude known-legitimate installation sources
    # and well-known Windows security/system driver paths.
    SAFE_SERVICE_PATHS = (
        r'system32\drivers\wd\\',   # Windows Defender kernel drivers (KslD, WdFilter, etc.)
        r'system32\drivers\wd/',
        r'\windows\system32\drivers\wd',
        'windows defender',
        'microsoft defender',
    )
    if event_id == '7045':
        safe = any(s in msg or s in event_type for s in _KNOWN_SAFE_SERVICE_PROVIDERS)
        safe = safe or any(p in msg.lower() for p in SAFE_SERVICE_PATHS)
        if not safe:
            triggered.append(_make_alert(
                _RULE_MAP['SERVICE_INSTALLATION'], log,
                evidence={
                    'event_id':   '7045',
                    'message':    (log.get('message', '') or '')[:400],
                    'source':     log.get('source', ''),
                    'timestamp':  log.get('timestamp', ''),
                }
            ))

    # ── 8. FIREWALL ANOMALY ─────────────────────────────────────────────────
    FIREWALL_CHANGE = ('rule change', 'policy modified', 'firewall disabled',
                       'firewall rule added', 'firewall rule deleted',
                       'netsh advfirewall')
    if (source_type == 'firewall' or 'firewall' in event_type) and \
       any(k in msg for k in FIREWALL_CHANGE):
        triggered.append(_make_alert(_RULE_MAP['FIREWALL_ANOMALY'], log))

    # ── 9. DNS TUNNELLING ───────────────────────────────────────────────────
    # Large DNS query name length + high entropy or explicit tunnelling keywords
    dest_port = log.get('destination_port')
    DNS_TUNNEL_WORDS = ('dns tunnel', 'dns tunneling', 'iodine', 'dnscat',
                        'high entropy dns', 'long dns query')
    try:
        qname = msg.split()[-1] if msg else ''
    except Exception:
        qname = ''
    large_name = dest_port == 53 and len(qname) > 100
    high_entropy = _shannon_entropy(qname) > 3.8
    keyword_dns = any(k in msg for k in DNS_TUNNEL_WORDS)
    if (large_name and high_entropy) or keyword_dns:
        triggered.append(_make_alert(_RULE_MAP['DNS_TUNNELING'], log))

    # ── 10. ACCOUNT LOCKOUT ─────────────────────────────────────────────────
    # Event ID 4740 — account locked out
    if event_id == '4740':
        triggered.append(_make_alert(
            _RULE_MAP['ACCOUNT_LOCKOUT'], log,
            evidence={
                'locked_account': username,
                'event_id':       '4740',
                'message':        (log.get('message', '') or '')[:400],
                'timestamp':      log.get('timestamp', ''),
            }
        ))

    # ── 10b. PASSWORD SPRAYING ──────────────────────────────────────────────
    # Detect repeated password failures across multiple accounts from the same source.
    if is_failed_login and source_ip and username:
        spray_bucket_key = source_ip or source or 'unknown'
        now = time.time()
        _PASSWORD_SPRAYING_ATTEMPTS[spray_bucket_key] = [
            entry for entry in _PASSWORD_SPRAYING_ATTEMPTS[spray_bucket_key]
            if now - entry[0] < _BRUTE_FORCE_WINDOW
        ]
        _PASSWORD_SPRAYING_ATTEMPTS[spray_bucket_key].append((now, username))

        account_names = {entry[1] for entry in _PASSWORD_SPRAYING_ATTEMPTS[spray_bucket_key] if entry[1]}
        if len(_PASSWORD_SPRAYING_ATTEMPTS[spray_bucket_key]) >= _BRUTE_FORCE_THRESHOLD and len(account_names) >= 2:
            triggered.append(_make_alert(
                _RULE_MAP['PASSWORD_SPRAYING'], log,
                evidence={
                    'account_count': len(account_names),
                    'source_ip': source_ip,
                    'event_id': event_id,
                    'message': (log.get('message', '') or '')[:400],
                    'timestamp': log.get('timestamp', ''),
                },
                confidence_override=92,
            ))

    # ── 11. SCHEDULED TASK CREATED ──────────────────────────────────────────
    # Event IDs 4698 (created), 4702 (updated) — exclude known system tasks
    SYSTEM_TASK_PATHS = ('\\microsoft\\windows\\', 'windows defender',
                          'microsoft update', 'windows update')
    if event_id in ('4698', '4702'):
        is_system_task = any(p in msg for p in SYSTEM_TASK_PATHS)
        if not is_system_task:
            triggered.append(_make_alert(
                _RULE_MAP['SCHEDULED_TASK_CREATED'], log,
                evidence={
                    'event_id': event_id,
                    'message':  (log.get('message', '') or '')[:400],
                    'username': username,
                    'timestamp': log.get('timestamp', ''),
                }
            ))

    return [alert for alert in triggered if _RULE_ENABLED.get(alert['rule_name'], True)]


def get_rules_info() -> list[dict]:
    """Return all rule definitions for the API and Settings page."""
    return [
        {
            'name':             r.name,
            'description':      r.description,
            'severity':         r.severity,
            'confidence':       r.confidence,
            'mitre_techniques': r.mitre_techniques,
            'kill_chain_phase': r.kill_chain_phase,
            'category':          _RULE_CATEGORIES.get(r.name, 'Detection'),
            'threshold':         3 if r.name in ('BRUTE_FORCE_LOGIN', 'PASSWORD_SPRAYING') else None,
            'time_window_seconds': 300 if r.name in ('BRUTE_FORCE_LOGIN', 'PASSWORD_SPRAYING') else None,
            'supported_configuration': r.name in ('BRUTE_FORCE_LOGIN', 'PASSWORD_SPRAYING'),
        }
        for r in RULES
    ]


def load_rule_overrides(rows) -> None:
    """Load persisted rule controls before an ingestion batch is evaluated."""
    global _BRUTE_FORCE_THRESHOLD, _BRUTE_FORCE_WINDOW
    _BRUTE_FORCE_THRESHOLD = 3
    _BRUTE_FORCE_WINDOW = 300
    _RULE_ENABLED.update({rule.name: True for rule in RULES})
    for row in rows:
        name = row['name']
        if name not in _RULE_MAP:
            continue
        _RULE_ENABLED[name] = bool(row['enabled'])
        if name in ('BRUTE_FORCE_LOGIN', 'PASSWORD_SPRAYING'):
            if row['threshold'] is not None:
                _BRUTE_FORCE_THRESHOLD = int(row['threshold'])
            if row['time_window_seconds'] is not None:
                _BRUTE_FORCE_WINDOW = int(row['time_window_seconds'])


def reset_counters() -> None:
    """Clear sliding-window counters (useful for testing)."""
    _FAILED_LOGINS.clear()
    _PASSWORD_SPRAYING_ATTEMPTS.clear()
