"""
Log Ingestion Service - Parses and normalizes logs from various sources
Uses only built-in Python modules (re, json, xml.etree)
"""
import re
import json
import uuid
import csv
import io
from datetime import datetime, timezone
from defusedxml import ElementTree

class LogIngestionService:
    
    @staticmethod
    def detect_format(content: str) -> str:
        content = content.strip()
        if content.startswith('{') or content.startswith('['):
            try:
                json.loads(content)
                return "json"
            except json.JSONDecodeError:
                pass
        if content.startswith('<?xml') or content.startswith('<Event') or content.startswith('<Events'):
            return "windows_xml"
        if re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+', content):
            return "syslog"
        first_line = content.split('\n')[0]
        if ',' in first_line and (first_line.count(',') > 3):
            return "csv"
        if 'Log Name:' in content or 'Event ID:' in content:
            return "windows_text"
        if any(kw in content.lower() for kw in ['src=', 'dst=', 'action=', 'deny', 'allow', 'drop']):
            return "firewall"
        return "plain"
    
    @staticmethod
    def parse_windows_xml(xml_content: str) -> list:
        logs = []
        try:
            root = ElementTree.fromstring(xml_content if not xml_content.startswith('<?xml') else xml_content)
            # Handle both single Event and Events>Event
            events = []
            if root.tag == 'Events':
                events = list(root)
            elif root.tag == 'Event':
                events = [root]
            else:
                events = root.findall('.//Event')
                if not events:
                    events = [root]
            
            for event in events:
                _sys = event.find('System')
                system = _sys if _sys is not None else event.find('{http://schemas.microsoft.com/win/2004/08/events/event}System')
                _ed = event.find('EventData')
                event_data = _ed if _ed is not None else event.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
                
                ns = ''
                if system is not None and '{' in system.tag:
                    ns = system.tag.split('}')[0] + '}'
                
                def get_text(parent, tag):
                    if parent is None:
                        return ''
                    el = parent.find(f'{ns}{tag}') if ns else parent.find(tag)
                    if el is None:
                        el = parent.find(tag)
                    return el.text if el is not None and el.text else ''
                
                def get_attr(parent, tag, attr):
                    if parent is None:
                        return ''
                    el = parent.find(f'{ns}{tag}') if ns else parent.find(tag)
                    if el is None:
                        el = parent.find(tag)
                    return el.get(attr, '') if el is not None else ''
                
                event_id = get_text(system, 'EventID') if system is not None else ''
                computer = get_text(system, 'Computer') if system is not None else ''
                level = get_text(system, 'Level') if system is not None else '4'
                channel = get_text(system, 'Channel') if system is not None else 'System'
                time_created = get_attr(system, 'TimeCreated', 'SystemTime') if system is not None else ''
                
                severity_map = {'0': 'info', '1': 'critical', '2': 'high', '3': 'medium', '4': 'info', '5': 'low'}
                
                # Extract message from EventData
                message_parts = []
                if event_data is not None:
                    for data in event_data:
                        name = data.get('Name', '')
                        text = data.text or ''
                        if name and text:
                            message_parts.append(f"{name}: {text}")
                        elif text:
                            message_parts.append(text)
                message = ' | '.join(message_parts) if message_parts else f"Event {event_id} from {computer}"
                
                # Extract username
                username = ''
                if event_data is not None:
                    for data in event_data:
                        if data.get('Name', '').lower() in ['targetusername', 'subjectusername']:
                            username = data.text or ''
                            break
                
                # Extract IP
                source_ip = ''
                if event_data is not None:
                    for data in event_data:
                        if data.get('Name', '').lower() in ['ipaddress', 'sourceip', 'ip address']:
                            source_ip = data.text or ''
                            break
                if not source_ip:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
                    if ip_match:
                        source_ip = ip_match.group(1)
                
                log = {
                    'id': str(uuid.uuid4()),
                    'timestamp': LogIngestionService._parse_timestamp(time_created),
                    'source': computer or 'unknown',
                    'source_type': 'windows',
                    'event_type': channel or 'System',
                    'event_id': event_id,
                    'severity': severity_map.get(str(level), 'info'),
                    'message': message,
                    'raw_log': xml_content[:2000],
                    'source_ip': source_ip,
                    'hostname': computer,
                    'username': username,
                    'tags': json.dumps(['windows', channel.lower() if channel else 'system']),
                }
                logs.append(log)
        except Exception as e:
            logs.append({
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'parser',
                'source_type': 'windows',
                'event_type': 'parse_error',
                'severity': 'info',
                'message': f'XML parse error: {str(e)}',
                'raw_log': xml_content[:1000],
                'tags': json.dumps(['error']),
            })
        return logs
    
    @staticmethod
    def parse_syslog(content: str) -> list:
        logs = []
        pattern = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)$')
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            match = pattern.match(line)
            if match:
                ts_str, hostname, process, message = match.groups()
                severity = LogIngestionService._classify_severity(message)
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
                user_match = re.search(r'(?:user|username)[=: ]+(\S+)', message, re.I)
                logs.append({
                    'id': str(uuid.uuid4()),
                    'timestamp': LogIngestionService._parse_syslog_ts(ts_str),
                    'source': hostname,
                    'source_type': 'linux',
                    'event_type': process,
                    'severity': severity,
                    'message': message,
                    'raw_log': line,
                    'hostname': hostname,
                    'process_name': process,
                    'source_ip': ip_match.group(1) if ip_match else '',
                    'username': user_match.group(1) if user_match else '',
                    'tags': json.dumps(['linux', process.lower()]),
                })
            else:
                logs.append({
                    'id': str(uuid.uuid4()),
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'source': 'unknown',
                    'source_type': 'linux',
                    'event_type': 'raw',
                    'severity': 'info',
                    'message': line,
                    'raw_log': line,
                    'tags': json.dumps(['raw']),
                })
        return logs
    
    @staticmethod
    def parse_json(content: str) -> list:
        logs = []
        try:
            data = json.loads(content)
            items = data if isinstance(data, list) else data.get('hits', data.get('events', [data]))
            if isinstance(items, dict):
                items = [items]
            for item in items:
                if not isinstance(item, dict):
                    continue
                ts = item.get('@timestamp', item.get('timestamp', item.get('time', '')))
                msg = item.get('message', item.get('msg', ''))
                if isinstance(msg, dict):
                    msg = json.dumps(msg)
                st = 'unknown'
                if 'winlog' in item:
                    st = 'windows'
                elif 'syslog' in str(item).lower():
                    st = 'linux'
                logs.append({
                    'id': str(uuid.uuid4()),
                    'timestamp': ts or datetime.now(timezone.utc).isoformat(),
                    'source': item.get('host', item.get('source', item.get('agent', {}).get('name', 'unknown'))),
                    'source_type': item.get('source_type', st),
                    'event_type': item.get('event_type', item.get('category', 'general')),
                    'event_id': str(item.get('event_id', '')),
                    'severity': str(item.get('severity', item.get('level', 'info'))).lower(),
                    'message': str(msg) if msg else json.dumps(item)[:500],
                    'raw_log': json.dumps(item),
                    'source_ip': item.get('source_ip', item.get('src_ip', '')),
                    'destination_ip': item.get('destination_ip', item.get('dst_ip', '')),
                    'username': item.get('username', item.get('user', '')),
                    'hostname': item.get('hostname', item.get('host', '')),
                    'tags': json.dumps(item.get('tags', ['json'])),
                })
        except Exception as e:
            logs.append({
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'parser', 'source_type': 'unknown', 'event_type': 'parse_error',
                'severity': 'info', 'message': f'JSON parse error: {str(e)}',
                'raw_log': content[:1000], 'tags': json.dumps(['error']),
            })
        return logs
    
    @staticmethod
    def parse_firewall(content: str) -> list:
        logs = []
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            log = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'firewall', 'source_type': 'firewall', 'event_type': 'network',
                'severity': 'info', 'message': line, 'raw_log': line, 'tags': json.dumps(['firewall']),
            }
            src = re.search(r'(?:src|source|SrcIP)[=:]\s*(\d+\.\d+\.\d+\.\d+)', line, re.I)
            dst = re.search(r'(?:dst|dest|DstIP)[=:]\s*(\d+\.\d+\.\d+\.\d+)', line, re.I)
            action = re.search(r'(?:action|act)[=:]\s*(\w+)', line, re.I)
            dport = re.search(r'(?:dport|dst_port|DPT)[=:]\s*(\d+)', line, re.I)
            if src: log['source_ip'] = src.group(1)
            if dst: log['destination_ip'] = dst.group(1)
            if dport: log['destination_port'] = int(dport.group(1))
            if action:
                a = action.group(1).lower()
                if a in ['deny', 'drop', 'block']:
                    log['severity'] = 'medium'
                log['message'] = f"Firewall {a}: {log.get('source_ip','?')} -> {log.get('destination_ip','?')}:{log.get('destination_port','?')}"
            logs.append(log)
        return logs
    
    @staticmethod
    def parse_csv(content: str) -> list:
        logs = []
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                logs.append({
                    'id': str(uuid.uuid4()),
                    'timestamp': row.get('timestamp', row.get('date', datetime.now(timezone.utc).isoformat())),
                    'source': row.get('source', row.get('host', 'unknown')),
                    'source_type': row.get('source_type', row.get('type', 'unknown')),
                    'event_type': row.get('event_type', row.get('category', 'general')),
                    'severity': row.get('severity', row.get('level', 'info')).lower(),
                    'message': row.get('message', row.get('msg', str(row))),
                    'raw_log': json.dumps(row),
                    'source_ip': row.get('source_ip', row.get('src_ip', '')),
                    'username': row.get('username', row.get('user', '')),
                    'hostname': row.get('hostname', ''),
                    'tags': json.dumps(['csv']),
                })
        except Exception:
            pass
        return logs
    
    @staticmethod
    def parse_windows_text(content: str) -> list:
        logs = []
        events = re.split(r'\n(?=Log Name:)', content)
        for text in events:
            text = text.strip()
            if not text:
                continue
            log = {
                'id': str(uuid.uuid4()), 'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'windows', 'source_type': 'windows', 'event_type': 'general',
                'severity': 'info', 'message': text[:500], 'raw_log': text, 'tags': json.dumps(['windows']),
            }
            m = re.search(r'Event ID:\s*(\d+)', text)
            if m: log['event_id'] = m.group(1)
            m = re.search(r'Level:\s*(\w+)', text)
            if m:
                log['severity'] = {'Error': 'high', 'Warning': 'medium', 'Critical': 'critical'}.get(m.group(1), 'info')
            m = re.search(r'Computer:\s*(.+)', text)
            if m: log['hostname'] = log['source'] = m.group(1).strip()
            logs.append(log)
        return logs
    
    @staticmethod
    def parse_plain(content: str) -> list:
        logs = []
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            timestamp = LogIngestionService._extract_timestamp(line)
            fields = LogIngestionService._extract_key_value_fields(line)
            source_ip = fields.get('src') or fields.get('source_ip') or fields.get('src_ip') or ''
            destination_ip = fields.get('dst') or fields.get('destination_ip') or fields.get('dst_ip') or ''
            severity = LogIngestionService._classify_severity(line)
            if fields.get('action') in {'deny', 'drop', 'block', 'reject'}:
                severity = 'high'

            log = {
                'id': str(uuid.uuid4()),
                'timestamp': timestamp,
                'source': fields.get('host') or fields.get('source') or 'unknown',
                'source_type': 'unknown',
                'event_type': 'raw',
                'severity': severity,
                'message': line,
                'raw_log': line,
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'tags': json.dumps(['plain']),
            }

            if fields.get('user'):
                log['username'] = fields['user']
            if fields.get('host'):
                log['hostname'] = fields['host']
            if fields.get('proto'):
                log['event_type'] = f"{log['event_type']}:{fields['proto']}"

            logs.append(log)
        return logs
    
    @staticmethod
    def parse_content(content: str, format_hint: str = "auto") -> tuple:
        fmt = format_hint if format_hint != "auto" else LogIngestionService.detect_format(content)
        parsers = {
            'windows_xml': LogIngestionService.parse_windows_xml,
            'syslog': LogIngestionService.parse_syslog,
            'json': LogIngestionService.parse_json,
            'firewall': LogIngestionService.parse_firewall,
            'csv': LogIngestionService.parse_csv,
            'windows_text': LogIngestionService.parse_windows_text,
            'plain': LogIngestionService.parse_plain,
        }
        parser = parsers.get(fmt, LogIngestionService.parse_plain)
        return fmt, parser(content)
    
    @staticmethod
    def _parse_timestamp(ts: str) -> str:
        if not ts:
            return datetime.now(timezone.utc).isoformat()
        for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S', '%m/%d/%Y %I:%M:%S %p']:
            try:
                return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
        return ts

    @staticmethod
    def _extract_timestamp(text: str) -> str:
        if not text:
            return datetime.now(timezone.utc).isoformat()

        ts_match = re.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)', text)
        if ts_match:
            return LogIngestionService._parse_timestamp(ts_match.group(1))

        for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S', '%m/%d/%Y %I:%M:%S %p']:
            try:
                dt = datetime.strptime(text.split()[0], fmt)
                return dt.replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue

        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _extract_key_value_fields(text: str) -> dict:
        fields = {}
        for match in re.finditer(r'([A-Za-z0-9_\.\-]+)=("[^"]*"|\S+)', text):
            key = match.group(1).lower()
            value = match.group(2).strip('"')
            if key in {'src', 'source_ip', 'src_ip'}:
                fields['src'] = value
            elif key in {'dst', 'destination_ip', 'dst_ip'}:
                fields['dst'] = value
            elif key in {'action', 'act'}:
                fields['action'] = value.lower()
            elif key in {'protocol', 'proto'}:
                fields['proto'] = value.lower()
            elif key in {'user', 'username'}:
                fields['user'] = value
            elif key in {'host', 'hostname', 'server'}:
                fields['host'] = value
            else:
                fields[key] = value
        return fields
    
    @staticmethod
    def _parse_syslog_ts(ts: str) -> str:
        try:
            # Supply an explicit year to avoid the Python 3.15 ambiguity deprecation
            year = datetime.now().year
            dt = datetime.strptime(f"{year} {ts}", '%Y %b %d %H:%M:%S').replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
    
    @staticmethod
    def _classify_severity(text: str) -> str:
        t = text.lower()
        if any(k in t for k in ['critical', 'emergency', 'panic']): return 'critical'
        if any(k in t for k in ['error', 'fail', 'denied', 'attack', 'blocked', 'malicious', 'invalid']): return 'high'
        if any(k in t for k in ['warn', 'timeout', 'retry', 'suspicious']): return 'medium'
        return 'info'
