"""Replaces _mock_chat and _mock_assessment with the improved versions."""
import os

target = os.path.join(os.path.dirname(__file__), '..', 'ai_engine.py')

with open(target, 'r', encoding='utf-8') as f:
    content = f.read()

# Keep everything up to (not including) _mock_chat
cut = content.find('\ndef _mock_chat(')
if cut == -1:
    cut = content.find('def _mock_chat(')
keep = content[:cut]

new_code = r'''

def _mock_chat(message: str, context: dict = None) -> str:
    m = message.lower()

    # Log translation
    if any(k in m for k in ['translate', 'explain log', 'what does this log', 'readable',
                             'what does it mean', 'decode', 'what is this log',
                             'what does event', 'what is event']):
        return (
            "Here is how to read common log entries in plain language:\n\n"
            "Event ID 4624 - A user successfully logged in. "
            "Logon Type 2 = keyboard (sitting at the machine), "
            "Type 3 = network (shared drive/SMB), Type 10 = Remote Desktop.\n\n"
            "Event ID 4625 - A login attempt failed.\n\n"
            "Event ID 4672 - An account logged in and was assigned admin privileges. "
            "Normal for SYSTEM; unusual for regular user accounts.\n\n"
            "Event ID 7045 - A new Windows service was installed. Malware uses this for persistence.\n\n"
            "pam_unix(sudo:session): session opened - Someone on Linux ran a command as root.\n\n"
            "pam_unix(sudo:session): session closed - The sudo command finished. This is normal.\n\n"
            "FW-DROP: SRC=X DST=Y DPT=Z - The firewall blocked a connection: "
            "IP X tried to reach IP Y on port Z and was denied.\n\n"
            "Paste a specific log line and I will explain exactly what it means."
        )

    # Top threats / status
    if any(k in m for k in ['top threat', 'current threat', 'status', 'what is happening',
                             "what's happening", 'security posture', 'overview']):
        return (
            "Current observable patterns in your SOC data:\n\n"
            "- Windows: Logon events (4624/4672) and PowerShell activity from DESKTOP-G89B4BO.\n"
            "- Linux (Kali VM): sudo sessions, cron jobs, and auth events from 'siddu'.\n"
            "- Firewall: iptables DROP events captured with source/destination IP and port.\n\n"
            "Priority checks:\n"
            "1. Open the Alerts page for any active BRUTE_FORCE or PRIVILEGE_ESCALATION alerts.\n"
            "2. Review the Top Attacking IPs widget on the Dashboard.\n"
            "3. Check if any 4624 logons occurred outside business hours."
        )

    # Brute force / password spray
    if any(k in m for k in ['brute', 'spray', 'password attack', 'failed login', 'failed password']):
        return (
            "Brute Force vs Password Spraying:\n\n"
            "Brute Force: one attacker targeting one account with many passwords. "
            "Alert fires after 3 failures from the same IP+account within 5 minutes.\n\n"
            "Password Spraying: one attacker targeting many accounts with one password. "
            "Alert fires when 3+ failures from the same IP hit 2+ different accounts.\n\n"
            "Investigation steps:\n"
            "1. Note the source IP - is it internal or external?\n"
            "2. Check if a 4624 (success) followed the 4625 failures from that IP.\n"
            "3. Look for 4672 (special privileges) on the affected account.\n"
            "4. Block the source IP at the firewall if external."
        )

    # Lateral movement
    if 'lateral' in m:
        return (
            "Lateral Movement Detection:\n\n"
            "The LATERAL_MOVEMENT rule fires on:\n"
            "- Event ID 4624 Logon Type 10 (Remote Desktop from external IP)\n"
            "- Network logon (Type 3) from IPs outside private ranges\n"
            "- Known lateral tools: PsExec, WMIExec, SMBExec\n\n"
            "Signs to investigate:\n"
            "- Same username on multiple different hostnames in a short timeframe\n"
            "- Use Log Explorer, filter source_type=windows, search for the username."
        )

    # MITRE ATT&CK
    if any(k in m for k in ['mitre', 'att&ck', 'attack technique', 'ttp']):
        return (
            "MITRE ATT&CK Techniques monitored:\n\n"
            "T1110   Brute Force              -> BRUTE_FORCE_LOGIN\n"
            "T1110.003 Password Spraying      -> PASSWORD_SPRAYING\n"
            "T1078   Valid Accounts           -> PRIVILEGE_ESCALATION, UNUSUAL_LOGIN_TIME\n"
            "T1059.001 PowerShell             -> SUSPICIOUS_POWERSHELL\n"
            "T1053.005 Scheduled Task         -> SCHEDULED_TASK_CREATED\n"
            "T1543.003 Windows Service        -> SERVICE_INSTALLATION\n"
            "T1021   Remote Services          -> LATERAL_MOVEMENT\n"
            "T1071.004 DNS Tunneling          -> DNS_TUNNELING\n"
            "T1048   Data Exfiltration        -> DATA_EXFILTRATION"
        )

    # Summarize / report
    if any(k in m for k in ['summarize', 'summary', 'report', 'incident report', 'executive']):
        return (
            "Security Summary:\n\n"
            "Sources monitored: Windows (DESKTOP-G89B4BO), Linux Kali VM (siddu), Firewall (iptables).\n\n"
            "Authentication: Windows logon and privilege events appear normal.\n\n"
            "Linux: Routine sudo and cron activity observed. debian-sa1 is the system activity reporter.\n\n"
            "Firewall: iptables DROP entries recorded. Review source IPs for repeated attempts.\n\n"
            "Recommended actions:\n"
            "1. Review any open alerts in the Alerts page\n"
            "2. Correlate firewall deny events with authentication failures on the same IP\n"
            "3. Confirm no logins occurred outside business hours"
        )

    # PowerShell
    if any(k in m for k in ['powershell', 'ps1', 'encoded command', 'script block']):
        return (
            "PowerShell Security Monitoring:\n\n"
            "Event ID 4104 (Script Block Logging) is collected from Windows. "
            "The SUSPICIOUS_POWERSHELL rule fires on:\n"
            "- -EncodedCommand: obfuscated/hidden commands\n"
            "- DownloadString / DownloadFile: downloading payloads from internet\n"
            "- Invoke-Mimikatz / Invoke-BloodHound: credential theft tools\n"
            "- IEX(...): executes downloaded code in memory\n\n"
            "Event 4100 is filtered out to reduce noise. "
            "The SOC forwarder script is allowlisted and never triggers alerts."
        )

    # Firewall logs
    if any(k in m for k in ['firewall', 'fw-drop', 'iptables', 'block', 'deny', 'port']):
        return (
            "Reading Firewall Logs:\n\n"
            "Your firewall events come from iptables on the Kali VM:\n"
            "- FW-DROP: packet was blocked\n"
            "- SRC= attacker IP address\n"
            "- DST= target IP address\n"
            "- DPT= destination port number\n"
            "- PROTO= TCP / UDP / ICMP\n\n"
            "Severity levels:\n"
            "- Port 22/3389/445/23/4444 = HIGH severity\n"
            "- Other deny = MEDIUM\n"
            "- Allow = INFO\n\n"
            "A FIREWALL_ANOMALY alert fires only when a firewall rule is changed, not on deny events."
        )

    # Linux / Kali logs
    if any(k in m for k in ['linux', 'kali', 'syslog', 'auth.log', 'journald',
                             'journal', 'sudo', 'cron', 'pam']):
        return (
            "Linux Log Sources (Kali VM - hostname: siddu):\n\n"
            "- sshd: SSH login attempts. 3 failures = BRUTE_FORCE_LOGIN alert.\n"
            "- sudo: Privileged commands. Session open/close is normal - NOT an alert.\n"
            "- cron: Scheduled jobs. debian-sa1 = system activity reporter (benign).\n"
            "- auth: PAM authentication events.\n"
            "- kernel: Kernel messages (mostly VirtualBox-related on your setup).\n"
            "- firewall: iptables DROP/ACCEPT events.\n\n"
            "Filter Log Explorer by Source Type = linux to see only Kali events."
        )

    # Windows Event IDs
    if any(k in m for k in ['event id', 'event log', 'windows log',
                             '4624', '4625', '4672', '4688', '7045', '4728', '4740']):
        return (
            "Key Windows Event IDs monitored:\n\n"
            "4624  Successful login           -> UNUSUAL_LOGIN_TIME, LATERAL_MOVEMENT\n"
            "4625  Failed login               -> BRUTE_FORCE_LOGIN, PASSWORD_SPRAYING\n"
            "4672  Admin privileges assigned  -> (informational)\n"
            "4688  New process started        -> (informational)\n"
            "4698  Scheduled task created     -> SCHEDULED_TASK_CREATED\n"
            "4720  New user account created   -> PRIVILEGE_ESCALATION\n"
            "4728  Added to global group      -> PRIVILEGE_ESCALATION\n"
            "4732  Added to local group       -> PRIVILEGE_ESCALATION\n"
            "4740  Account locked out         -> ACCOUNT_LOCKOUT\n"
            "4771  Kerberos login failed      -> BRUTE_FORCE_LOGIN\n"
            "7045  New service installed      -> SERVICE_INSTALLATION\n"
            "4104  PowerShell script executed -> SUSPICIOUS_POWERSHELL"
        )

    # Help
    if any(k in m for k in ['help', 'what can you', 'capabilities', 'what do you']):
        return (
            "I am your built-in SOC analyst. I can help with:\n\n"
            "- Translate logs: explain any log entry in plain language\n"
            "- Explain attacks: brute force, lateral movement, privilege escalation\n"
            "- MITRE ATT&CK: which techniques are monitored\n"
            "- Windows Event IDs: what each event ID means\n"
            "- Linux/firewall logs: how to read sudo, cron, iptables entries\n"
            "- Incident summaries: current activity overview\n"
            "- Investigation guidance: where to start\n\n"
            "Try asking:\n"
            "  'What does event 4625 mean?'\n"
            "  'Translate the logs into readable language'\n"
            "  'Is there any brute force activity?'\n"
            "  'What MITRE techniques are active?'"
        )

    # Default
    return (
        "Your SOC is collecting logs from Windows (DESKTOP-G89B4BO), "
        "Linux Kali VM (siddu), and Firewall (iptables).\n\n"
        "Try asking something specific:\n"
        "- 'Translate the logs into readable language'\n"
        "- 'What does event ID 4625 mean?'\n"
        "- 'Explain the brute force detection'\n"
        "- 'What MITRE techniques are monitored?'\n"
        "- 'Summarize current security status'\n\n"
        "For fully context-aware AI responses using your actual live data, "
        "add your OPENAI_API_KEY to backend/.env."
    )


def _mock_assessment(stats: dict) -> dict:
    total    = stats.get('total_alerts', 0)
    critical = stats.get('critical', 0)
    high     = stats.get('high', 0)

    if total == 0:
        return {
            'overall_score': 0,
            'risk_level': 'low',
            'summary': 'No active alerts. Environment appears normal.',
            'top_concerns': ['Continue monitoring for new threats.'],
        }

    score = min(100, (critical * 25) + (high * 10) + max(0, total - critical - high) * 2)
    level = 'critical' if score >= 80 else 'high' if score >= 60 else 'medium' if score >= 40 else 'low'
    return {
        'overall_score': score,
        'risk_level': level,
        'summary': f"Current threat level is {level}. {critical} critical and {high} high severity alerts require attention.",
        'top_concerns': [
            'Active brute force attempts detected' if critical > 0 else 'Elevated failed login rate',
            'Suspicious process execution detected' if high > 0 else 'Monitor for anomalies',
        ],
    }
'''

with open(target, 'w', encoding='utf-8') as f:
    f.write(keep + new_code)

print("ai_engine.py patched successfully")
