"""
AI SOC Dashboard - Flask Backend
Works with Python 3.14+ — no compilation dependencies
"""
import os
import json
import uuid
import hashlib
import secrets
import chardet
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from config import settings
from database import init_db, get_db, row_to_dict
from log_ingestion import LogIngestionService
from rule_engine import evaluate_log, get_rules_info, load_rule_overrides
import ai_engine
import anomaly_scorer
import ai_triage_worker
from auth import (
    require_auth, require_min_role, get_current_user,
    create_session, get_session_user, revoke_session, purge_expired_sessions,
    validate_ingest_key, create_ingest_key, bootstrap_admin, hash_password, verify_password,
)
import soc_context as soc_ctx
from seed_data import seed_database

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = settings.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = settings.MAX_UPLOAD_SIZE


@app.errorhandler(500)
def internal_server_error(error):
    """Return a generic API error without exposing server internals."""
    app.logger.exception("Unhandled server error", exc_info=error)
    return jsonify({'error': 'Internal server error'}), 500


@app.errorhandler(400)
def bad_request(error):
    response = {'error': 'Bad request'}
    if settings.DEBUG and not settings.IS_PRODUCTION:
        response['details'] = getattr(error, 'description', 'Invalid request')
    return jsonify(response), 400


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(413)
def request_too_large(error):
    return jsonify({'error': 'Payload too large'}), 413

CORS(app, origins=settings.CORS_ORIGINS)
socketio = SocketIO(app, cors_allowed_origins=settings.CORS_ORIGINS, async_mode='threading')

# Ensure upload directory exists
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)

_LOGIN_ATTEMPTS = defaultdict(list)
_MAX_LOGIN_ATTEMPTS = 10
_LOGIN_WINDOW_SECONDS = 300
_ENDPOINT_ATTEMPTS = defaultdict(list)
_ENDPOINT_LIMITS = {
    'upload': (20, 300),
    'ai': (30, 60),
    'ingest': (120, 60),
}

# Timestamp (UTC float) set when live logs are cleared.
# The ingest endpoint rejects any log older than this so the forwarder
# cannot re-fill the DB with logs that were just deleted.
_LIVE_CLEARED_AT: float = 0.0


@app.before_request
def enforce_payload_limits():
    if request.path.startswith('/api/logs/ingest') and request.content_length and request.content_length > settings.MAX_INGEST_PAYLOAD_SIZE:
        return jsonify({'error': 'Payload too large'}), 413

    if request.method == 'OPTIONS' or request.path == '/api/auth/login':
        return None
    category = None
    if request.path == '/api/upload/file' and request.method == 'POST':
        category = 'upload'
    elif request.path.startswith('/api/ai/') or request.path.endswith('/ai-analysis') or request.path.endswith('/escalate'):
        category = 'ai'
    elif request.path == '/api/logs/ingest' and request.method == 'POST':
        category = 'ingest'
    if category:
        limit, window = _ENDPOINT_LIMITS[category]
        key = f"{category}:{request.remote_addr or 'unknown'}"
        now = datetime.now(timezone.utc).timestamp()
        attempts = _ENDPOINT_ATTEMPTS[key]
        attempts[:] = [ts for ts in attempts if now - ts < window]
        if len(attempts) >= limit:
            return jsonify({'error': 'Too many requests'}), 429
        attempts.append(now)
    return None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self'",
    )
    if settings.IS_PRODUCTION:
        response.headers.setdefault(
            'Strict-Transport-Security', 'max-age=31536000; includeSubDomains'
        )
    return response


def _is_rate_limited(ip: str) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    attempts = _LOGIN_ATTEMPTS[ip]
    attempts[:] = [ts for ts in attempts if now - ts < _LOGIN_WINDOW_SECONDS]
    if len(attempts) >= _MAX_LOGIN_ATTEMPTS:
        return True
    attempts.append(now)
    return False


# ============================================================
# HEALTH & ROOT
# ============================================================

@app.route('/')
def root():
    return jsonify({"name": "AI SOC Dashboard API", "version": "1.0.0", "status": "running", "docs": "/api/health"})

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy"})

# ============================================================
# ============================================================
# DASHBOARD STATS
# ============================================================

@app.route('/api/dashboard/stats')
@require_auth
def dashboard_stats():
    """
    Aggregated statistics for the dashboard.
    data_source param: 'all' | 'live' | 'uploaded'
    Uses GROUP BY aggregations instead of per-value loops.
    """
    db = get_db()
    data_source = request.args.get('data_source', 'all')

    # Log filter clause
    if data_source == 'uploaded':
        log_where = "upload_session_id != '' AND upload_session_id IS NOT NULL"
    elif data_source == 'live':
        # live = ingested via API (no upload_session_id)
        log_where = "(upload_session_id = '' OR upload_session_id IS NULL)"
    else:
        log_where = "1=1"

    # ── Severity counts from log_entries (source-filtered) ──
    # Counting log entry severities gives consistent numbers with the
    # Live Ingestion page and correctly reflects the chosen data source.
    ACTIVE_STATUSES = "('new','acknowledged','investigating','escalated')"
    sev_rows = db.execute(
        f"SELECT severity, COUNT(*) FROM log_entries WHERE {log_where} GROUP BY severity"
    ).fetchall()
    severity_counts = {s: 0 for s in ('critical', 'high', 'medium', 'low', 'info')}
    for row in sev_rows:
        if row[0] in severity_counts:
            severity_counts[row[0]] = row[1]

    # ── Alert status counts (across all alerts, unfiltered by source) ──
    status_rows = db.execute(
        "SELECT status, COUNT(*) FROM alerts GROUP BY status"
    ).fetchall()
    status_counts = {s: 0 for s in ('new', 'acknowledged', 'investigating', 'resolved', 'false_positive', 'escalated')}
    for row in status_rows:
        if row[0] in status_counts:
            status_counts[row[0]] = row[1]

    # Total alerts = active only (excludes resolved and false positives)
    total_alerts = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved', 'false_positive')"
    ).fetchone()[0]

    # ── Log counts ──
    total_logs     = db.execute(f"SELECT COUNT(*) FROM log_entries WHERE {log_where}").fetchone()[0]
    live_logs      = db.execute("SELECT COUNT(*) FROM log_entries WHERE (upload_session_id = '' OR upload_session_id IS NULL)").fetchone()[0]
    uploaded_logs  = db.execute("SELECT COUNT(*) FROM log_entries WHERE upload_session_id != '' AND upload_session_id IS NOT NULL").fetchone()[0]

    # ── Log source type breakdown ──
    src_rows = db.execute(
        f"SELECT source_type, COUNT(*) FROM log_entries WHERE {log_where} GROUP BY source_type"
    ).fetchall()
    source_counts = {r[0]: r[1] for r in src_rows if r[1] > 0}

    # ── Recent alerts — active only, so widget matches the Alerts page ──
    recent_alerts = [row_to_dict(r) for r in db.execute(
        f"SELECT * FROM alerts WHERE status IN {ACTIVE_STATUSES} ORDER BY created_at DESC LIMIT 10"
    ).fetchall()]

    recent_logs = [row_to_dict(r) for r in db.execute(
        f"SELECT * FROM log_entries WHERE {log_where} ORDER BY created_at DESC LIMIT 20"
    ).fetchall()]

    # ── Top attacking IPs ──
    top_ips = [
        {"ip": r[0], "count": r[1]}
        for r in db.execute(
            "SELECT source_ip, COUNT(*) as cnt FROM alerts "
            "WHERE source_ip != '' GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
    ]

    # ── Top active hosts ──
    top_hosts = [
        {"host": r[0], "count": r[1]}
        for r in db.execute(
            f"SELECT source, COUNT(*) as cnt FROM log_entries WHERE {log_where} "
            "GROUP BY source ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
    ]

    db.close()
    return jsonify({
        "alerts": {
            "total":       total_alerts,
            "by_severity": severity_counts,
            "by_status":   status_counts,
        },
        "logs": {
            "total":          total_logs,
            "by_source":      source_counts,
            "live_count":     live_logs,
            "uploaded_count": uploaded_logs,
        },
        "recent_alerts": recent_alerts,
        "recent_logs":   recent_logs,
        "top_ips":       top_ips,
        "top_hosts":     top_hosts,
    })

# ============================================================
# ALERTS
# ============================================================

def _safe_int(value, default: int, minimum: int = 0, maximum: int = None) -> int:
    """Parse *value* as int with bounds. Returns *default* on failure."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None:
        v = max(minimum, v)
    if maximum is not None:
        v = min(maximum, v)
    return v


@app.route('/api/alerts')
@require_auth
def get_alerts():
    db = get_db()
    severity = request.args.get('severity')
    status = request.args.get('status')
    limit = _safe_int(request.args.get('limit', 50), default=50, minimum=1, maximum=500)
    offset = _safe_int(request.args.get('offset', 0), default=0, minimum=0)
    hide_closed = request.args.get('hide_closed', 'true').lower() != 'false'

    # Validate enum filters to prevent SQL value injection
    _VALID_SEVERITIES = frozenset({'critical', 'high', 'medium', 'low', 'info'})
    if severity and severity not in _VALID_SEVERITIES:
        return jsonify({'error': f"Invalid severity filter '{severity}'"}), 400
    if status and status not in _VALID_ALERT_STATUSES:
        return jsonify({'error': f"Invalid status filter '{status}'"}), 400

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        query += " AND severity=?"
        params.append(severity)
    if status:
        query += " AND status=?"
        params.append(status)
    if hide_closed:
        query += " AND status NOT IN ('resolved','false_positive')"
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    alerts = [row_to_dict(r) for r in db.execute(query, params).fetchall()]
    db.close()
    return jsonify(alerts)

@app.route('/api/alerts/stats')
@require_auth
def alert_stats():
    """
    Returns alert counts.
    by_severity counts ONLY active alerts (new/investigating/escalated)
    so the number matches what the Alerts page displays.
    by_status always covers all statuses for the status breakdown view.
    """
    db = get_db()
    active = "('new','acknowledged','investigating','escalated')"
    total = db.execute(f"SELECT COUNT(*) FROM alerts WHERE status IN {active}").fetchone()[0]
    by_severity = {}
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        by_severity[sev] = db.execute(
            f"SELECT COUNT(*) FROM alerts WHERE severity=? AND status IN {active}", (sev,)
        ).fetchone()[0]
    by_status = {}
    for st in ['new', 'acknowledged', 'investigating', 'resolved', 'false_positive', 'escalated']:
        by_status[st] = db.execute("SELECT COUNT(*) FROM alerts WHERE status=?", (st,)).fetchone()[0]
    db.close()
    return jsonify({"total": total, "by_severity": by_severity, "by_status": by_status})

@app.route('/api/alerts/<alert_id>')
@require_auth
def get_alert(alert_id):
    db = get_db()
    alert = row_to_dict(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
    if not alert:
        db.close()
        return jsonify({"error": "Alert not found"}), 404
    
    # Get related logs
    related_ids = alert.get('related_log_ids', [])
    related_logs = []
    if related_ids:
        placeholders = ','.join(['?' for _ in related_ids])
        related_logs = [row_to_dict(r) for r in db.execute(
            f"SELECT * FROM log_entries WHERE id IN ({placeholders})", related_ids).fetchall()]
    
    rule = next((item for item in get_rules_info() if item['name'] == alert.get('rule_name')), None)
    evidence_events = [
        {
            'id': log.get('id'),
            'event_id': log.get('event_id'),
            'timestamp': log.get('timestamp'),
            'source': log.get('source'),
            'source_type': log.get('source_type'),
            'severity': log.get('severity'),
            'message': log.get('message'),
            'source_ip': log.get('source_ip'),
            'destination_ip': log.get('destination_ip'),
            'username': log.get('username'),
            'hostname': log.get('hostname'),
        }
        for log in related_logs
    ]
    ai_assessment = alert.get('ai_analysis') if isinstance(alert.get('ai_analysis'), dict) else {}
    history = [dict(row) for row in db.execute(
        "SELECT previous_status, new_status, changed_by, changed_by_email, reason, created_at "
        "FROM alert_status_history WHERE alert_id=? ORDER BY created_at ASC, id ASC", (alert_id,)
    ).fetchall()]
    alert['status_history'] = history
    alert['related_logs'] = related_logs
    alert['detection'] = {
        'rule': alert.get('rule_name'),
        'category': rule.get('category') if rule else None,
        'threshold': rule.get('threshold') if rule else None,
        'time_window_seconds': rule.get('time_window_seconds') if rule else None,
        'detection_timestamp': alert.get('timestamp') or alert.get('created_at'),
        'confidence': alert.get('confidence'),
        'mitre_techniques': alert.get('mitre_techniques') or [],
    }
    alert['evidence_trace'] = {
        'rule': alert.get('rule_name'),
        'events': evidence_events,
        'detection_evidence': alert.get('evidence') or {},
    }
    alert['ai_assessment'] = ai_assessment
    # FP classification
    alert['fp_classification'] = alert.get('fp_classification') or ''
    alert['fp_classified_by'] = alert.get('fp_classified_by') or ''
    alert['fp_classified_at'] = alert.get('fp_classified_at') or ''
    alert['fp_reason'] = alert.get('fp_reason') or ''
    db.close()
    return jsonify(alert)

@app.route('/api/alerts/<alert_id>/ai-analysis')
@require_auth
def get_ai_analysis(alert_id):
    db = get_db()
    alert = row_to_dict(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
    if not alert:
        db.close()
        return jsonify({"error": "Not found"}), 404
    
    analysis = alert.get('ai_analysis', {})
    if not analysis or not analysis.get('summary'):
        analysis = ai_engine.analyze_alert(alert)
        db.execute("UPDATE alerts SET ai_analysis=?, threat_score=? WHERE id=?",
                   (json.dumps(analysis), analysis.get('threat_score', 50), alert_id))
        db.commit()
    
    db.close()
    return jsonify(analysis)

@app.route('/api/alerts/<alert_id>/investigation-context')
@require_auth
def get_investigation_context(alert_id):
    db = get_db()
    alert = row_to_dict(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
    if not alert:
        db.close()
        return jsonify({"error": "Not found"}), 404

    related_log_ids = alert.get('related_log_ids', []) or []
    related_logs = []
    if related_log_ids:
        placeholders = ','.join(['?' for _ in related_log_ids])
        related_logs = [row_to_dict(r) for r in db.execute(
            f"SELECT * FROM log_entries WHERE id IN ({placeholders}) ORDER BY created_at DESC",
            related_log_ids
        ).fetchall()]

    related_alert_filters = []
    related_alert_params: list = [alert_id]
    if alert.get('source_ip'):
        related_alert_filters.append("source_ip=?")
        related_alert_params.append(alert['source_ip'])
    if alert.get('username'):
        related_alert_filters.append("username=?")
        related_alert_params.append(alert['username'])
    if alert.get('hostname'):
        related_alert_filters.append("hostname=?")
        related_alert_params.append(alert['hostname'])

    related_alerts = []
    if related_alert_filters:
        query = (
            "SELECT id, title, severity, status, source_ip, username, hostname, created_at "
            "FROM alerts WHERE id != ? AND (" + " OR ".join(related_alert_filters) + ") "
            "ORDER BY created_at DESC LIMIT 5"
        )
        related_alerts = [row_to_dict(r) for r in db.execute(query, related_alert_params).fetchall()]

    ai_analysis = alert.get('ai_analysis', {}) or {}
    recommended_steps = []
    if alert.get('severity') in {'critical', 'high'}:
        recommended_steps.append('Contain the affected asset and preserve evidence before further changes.')
    if alert.get('source_ip'):
        recommended_steps.append('Review network telemetry and firewall logs for the source IP.')
    if alert.get('username'):
        recommended_steps.append('Inspect recent authentication activity for the implicated account.')
    if 'BRUTE_FORCE' in (alert.get('rule_name', '') or '').upper():
        recommended_steps.append('Check for successful logons after the failed attempts to confirm compromise.')
    elif 'POWERSHELL' in (alert.get('rule_name', '') or '').upper():
        recommended_steps.append('Collect process execution evidence and investigate the command lineage.')
    elif 'PRIVILEGE' in (alert.get('rule_name', '') or '').upper():
        recommended_steps.append('Audit account privilege changes and related administrative actions.')
    else:
        recommended_steps.append('Correlate this alert with neighboring events and confirm the observed activity.')

    if isinstance(ai_analysis, dict):
        for action in ai_analysis.get('recommended_actions', []) or []:
            if action not in recommended_steps:
                recommended_steps.append(action)

    db.close()
    return jsonify({
        "alert": alert,
        "related_logs": related_logs,
        "related_alerts": related_alerts,
        "recommended_next_steps": recommended_steps[:6],
        "evidence": alert.get('evidence', {}) or {},
    })

_VALID_ALERT_STATUSES = frozenset({'new', 'acknowledged', 'investigating', 'resolved', 'false_positive', 'escalated'})
_ALLOWED_ALERT_TRANSITIONS = {
    'new': {'acknowledged', 'investigating', 'false_positive', 'escalated'},
    'acknowledged': {'investigating'},
    'investigating': {'resolved', 'false_positive', 'escalated'},
    'resolved': set(),
    'false_positive': set(),
    'escalated': set(),
}
# Statuses that should disappear from the default view immediately
_CLOSED_STATUSES = frozenset({'resolved', 'false_positive'})


def _transition_alert(db, alert_id: str, new_status: str, user: dict, reason: str):
    """Apply one audited alert transition inside the caller's transaction."""
    row = db.execute("SELECT status FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row:
        return None, {'error': 'Alert not found'}, 404
    previous_status = row['status']
    if new_status == 'acknowledged' and not reason:
        return None, {'error': 'reason is required for acknowledgment'}, 400
    legacy_request = not reason
    if new_status not in _ALLOWED_ALERT_TRANSITIONS.get(previous_status, set()) and not legacy_request:
        return None, {'error': 'Invalid alert status transition'}, 409
    if previous_status == new_status:
        return {'id': alert_id, 'status': new_status, 'previous_status': previous_status,
                'changed_by': user.get('email', ''), 'reason': '', 'changed_at': None}, None, None
    reason = reason or 'Legacy status update'

    updated_at_expr = "datetime('now', '-31 minutes')" if new_status in _CLOSED_STATUSES else "datetime('now')"
    db.execute(
        f"UPDATE alerts SET status=?, updated_at={updated_at_expr} WHERE id=?",
        (new_status, alert_id),
    )
    changed_at = datetime.now(timezone.utc).isoformat()
    db.execute(
        """INSERT INTO alert_status_history
           (alert_id, previous_status, new_status, changed_by, changed_by_email, reason, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (alert_id, previous_status, new_status, user.get('user_id', ''), user.get('email', ''), reason, changed_at),
    )
    return {
        "id": alert_id, "status": new_status, "previous_status": previous_status,
        "changed_by": user.get('email', ''), "reason": reason, "changed_at": changed_at,
    }, None, None

@app.route('/api/alerts/<alert_id>/status', methods=['PATCH'])
@require_min_role('analyst')
def update_alert_status(alert_id):
    data = request.get_json() or {}
    status = (data.get('status') or '').strip()
    reason = (data.get('reason') or '').strip()[:1000]
    if status not in _VALID_ALERT_STATUSES:
        return jsonify({
            'error': f"Invalid status '{status}'. Must be one of: {sorted(_VALID_ALERT_STATUSES)}"
        }), 400

    db = get_db()
    user = get_current_user()
    event, error, error_code = _transition_alert(db, alert_id, status, user, reason)
    if error:
        db.close()
        return jsonify(error), error_code

    db.commit()
    db.close()
    socketio.emit('alert_update', event)
    return jsonify(event)

@app.route('/api/alerts/<alert_id>/respond', methods=['POST'])
@require_min_role('analyst')
def respond_alert(alert_id):
    db = get_db()
    action = request.args.get('action', 'dismiss')
    if action not in {'dismiss', 'escalate', 'resolve'}:
        db.close()
        return jsonify({'error': 'Invalid response action'}), 400
    alert = row_to_dict(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
    if not alert:
        db.close()
        return jsonify({"error": "Not found"}), 404

    actions = alert.get('response_actions', [])
    actions.append({"action": action, "timestamp": datetime.now(timezone.utc).isoformat()})

    new_status = 'false_positive' if action == 'dismiss' else 'escalated' if action == 'escalate' else 'resolved'
    user = get_current_user()
    reason = f"Legacy response action: {action}"
    event, error, error_code = _transition_alert(db, alert_id, new_status, user, reason)
    if error:
        db.close()
        return jsonify(error), error_code
    db.execute("UPDATE alerts SET response_actions=? WHERE id=?", (json.dumps(actions), alert_id))
    db.commit()
    db.close()
    socketio.emit('alert_update', event)
    return jsonify({**event, "action": action})

# ============================================================
# LOGS
# ============================================================

@app.route('/api/logs', methods=['GET'])
@require_auth
def get_logs():
    db = get_db()
    source = request.args.get('source')
    source_type = request.args.get('source_type')
    severity = request.args.get('severity')
    search = request.args.get('search')
    upload_only = request.args.get('upload_only', '').lower() == 'true'
    limit = _safe_int(request.args.get('limit', 100), default=100, minimum=1, maximum=1000)
    offset = _safe_int(request.args.get('offset', 0), default=0, minimum=0)
    
    query = "SELECT * FROM log_entries WHERE 1=1"
    params = []
    if upload_only:
        query += " AND upload_session_id != '' AND upload_session_id IS NOT NULL"
    if source:
        query += " AND source=?"
        params.append(source)
    if source_type:
        query += " AND source_type=?"
        params.append(source_type)
    if severity:
        query += " AND severity=?"
        params.append(severity)
    if search:
        query += " AND (message LIKE ? OR source LIKE ? OR source_ip LIKE ? OR username LIKE ?)"
        s = f'%{search}%'
        params.extend([s, s, s, s])
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    logs = [row_to_dict(r) for r in db.execute(query, params).fetchall()]
    db.close()
    return jsonify(logs)

@app.route('/api/logs/ingest', methods=['POST'])
def ingest_logs():
    """Ingest logs from external sources. Requires X-Ingest-Key header."""
    global _LIVE_CLEARED_AT

    # ── Ingest key authentication ─────────────────────────────────────────
    raw_key = request.headers.get('X-Ingest-Key', '').strip()
    if not raw_key:
        return jsonify({'error': 'Authentication required'}), 401
    db = get_db()
    if not validate_ingest_key(db, raw_key):
        db.close()
        return jsonify({'error': 'Authentication required'}), 401
    db.commit()  # persist last_used_at update
    load_rule_overrides(db.execute("SELECT name, enabled, threshold, time_window_seconds FROM detection_rules").fetchall())
    data = request.get_json() or {}
    log_list = data.get('logs', [])

    ingested = 0
    alerts_generated = 0

    for log_data in log_list:
        log_id = log_data.get('id', str(uuid.uuid4()))

        # Coerce tags to JSON string regardless of what arrives
        tags = log_data.get('tags', [])
        if isinstance(tags, (list, dict)):
            tags = json.dumps(tags)
        elif not isinstance(tags, str):
            tags = '[]'

        # Coerce all text fields to plain strings (guard against nested dicts/lists)
        def safe_str(v, default=''):
            if v is None: return default
            if isinstance(v, (dict, list)): return json.dumps(v)[:500]
            return str(v)[:500]

        ts       = safe_str(log_data.get('timestamp', ''))
        source   = safe_str(log_data.get('source', 'unknown'))
        event_id = safe_str(log_data.get('event_id', ''))

        # ── Reject logs older than the last clear operation ──
        # This prevents the forwarder from re-filling the DB with events
        # that were just deleted.
        if _LIVE_CLEARED_AT > 0 and ts:
            try:
                log_ts = datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp()
                if log_ts < _LIVE_CLEARED_AT:
                    continue
            except Exception:
                pass  # unparseable timestamp — let it through

        # ── Deduplication: skip if same event_id + timestamp + source already stored ──
        if ts and event_id:
            exists = db.execute(
                "SELECT 1 FROM log_entries WHERE event_id=? AND timestamp=? AND source=? LIMIT 1",
                (event_id, ts, source)
            ).fetchone()
            if exists:
                continue

        # ── Anomaly scoring (local, non-blocking, zero OpenAI calls) ─────
        a_score, a_level, a_reasons = 0, "normal", []
        if settings.ANOMALY_SCORING_ENABLED:
            try:
                a_score, a_level, a_reasons = anomaly_scorer.score_log(log_data)
            except Exception:
                pass  # scoring failure must never block ingestion

        db.execute("""INSERT OR IGNORE INTO log_entries
            (id, timestamp, source, source_type, event_type, event_id, severity, message,
             raw_log, source_ip, destination_ip, source_port, destination_port,
             username, hostname, process_name, tags,
             anomaly_score, anomaly_level, anomaly_reasons)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (log_id,
             ts or datetime.now(timezone.utc).isoformat(),
             source,
             safe_str(log_data.get('source_type', 'unknown')),
             safe_str(log_data.get('event_type', 'general')),
             event_id,
             safe_str(log_data.get('severity', 'info')),
             safe_str(log_data.get('message', '')),
             safe_str(log_data.get('raw_log', '')),
             safe_str(log_data.get('source_ip', '')),
             safe_str(log_data.get('destination_ip', '')),
             log_data.get('source_port'),
             log_data.get('destination_port'),
             safe_str(log_data.get('username', '')),
             safe_str(log_data.get('hostname', '')),
             safe_str(log_data.get('process_name', '')),
             tags,
             a_score, a_level, json.dumps(a_reasons)))
        ingested += 1
        
        # Run detection rules
        triggered = evaluate_log(log_data)
        for alert_data in triggered:
            alert_id = str(uuid.uuid4())
            db.execute("""INSERT INTO alerts (id, title, description, severity, status, rule_name,
                confidence, source, source_ip, destination_ip, username, hostname, mitre_techniques,
                kill_chain_phase, related_log_ids, evidence, ai_analysis, threat_score, ai_triage_status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (alert_id, alert_data['title'], alert_data['description'],
                 alert_data['severity'], 'new', alert_data['rule_name'],
                 alert_data.get('confidence', 70),
                 alert_data.get('source', ''), alert_data.get('source_ip', ''),
                 alert_data.get('destination_ip', ''), alert_data.get('username', ''),
                 alert_data.get('hostname', ''), json.dumps(alert_data.get('mitre_techniques', [])),
                 alert_data.get('kill_chain_phase', ''), json.dumps([log_id]),
                 json.dumps(alert_data.get('evidence', {})),
                 '{}', 0, 'pending'))
            alerts_generated += 1

            # Enqueue async AI triage (non-blocking)
            if settings.AUTO_TRIAGE_ENABLED:
                ai_triage_worker.enqueue_triage_job(db, alert_id)

            socketio.emit('new_alert', {
                "id": alert_id, "title": alert_data['title'],
                "severity": alert_data['severity'], "rule_name": alert_data['rule_name'],
            })
        
        socketio.emit('new_log', {
            "id": log_id, "source": log_data.get('source', ''),
            "severity": log_data.get('severity', 'info'),
            "message": log_data.get('message', '')[:200],
        })
    
    db.commit()
    db.close()
    return jsonify({"ingested": ingested, "alerts_generated": alerts_generated})

@app.route('/api/logs/stats')
@require_auth
def log_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
    by_source = {}
    for st in ['windows', 'linux', 'firewall', 'ids', 'network', 'uploaded']:
        c = db.execute("SELECT COUNT(*) FROM log_entries WHERE source_type=?", (st,)).fetchone()[0]
        if c > 0:
            by_source[st] = c
    by_severity = {}
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        by_severity[sev] = db.execute("SELECT COUNT(*) FROM log_entries WHERE severity=?", (sev,)).fetchone()[0]
    top_sources = [{"name": r[0], "count": r[1]} for r in db.execute(
        "SELECT source, COUNT(*) as cnt FROM log_entries GROUP BY source ORDER BY cnt DESC LIMIT 20").fetchall()]
    db.close()
    return jsonify({"total": total, "by_source_type": by_source, "by_severity": by_severity, "top_sources": top_sources})

@app.route('/api/logs/sources')
@require_auth
def log_sources():
    db = get_db()
    sources = [{"source": r[0], "source_type": r[1], "count": r[2]} for r in db.execute(
        "SELECT source, source_type, COUNT(*) FROM log_entries GROUP BY source, source_type ORDER BY COUNT(*) DESC").fetchall()]
    db.close()
    return jsonify(sources)

@app.route('/api/logs/rules')
@require_auth
def log_rules():
    return jsonify(get_rules_info())


def _ensure_detection_rules(db):
    for rule in get_rules_info():
        db.execute(
            """INSERT OR IGNORE INTO detection_rules
               (name, enabled, threshold, time_window_seconds)
               VALUES (?, 1, ?, ?)""",
            (rule['name'], rule['threshold'], rule['time_window_seconds']),
        )
    db.commit()


@app.route('/api/detection-rules')
@require_auth
def detection_rules():
    db = get_db()
    _ensure_detection_rules(db)
    definitions = {rule['name']: rule for rule in get_rules_info()}
    counts = {
        row['rule_name']: {'trigger_count': row['trigger_count'], 'last_triggered': row['last_triggered']}
        for row in db.execute(
            """SELECT rule_name, COUNT(*) AS trigger_count, MAX(created_at) AS last_triggered
               FROM alerts GROUP BY rule_name"""
        ).fetchall()
    }
    rows = db.execute(
        "SELECT name, enabled, threshold, time_window_seconds, created_at, updated_at "
        "FROM detection_rules ORDER BY name"
    ).fetchall()
    db.close()
    result = []
    for row in rows:
        definition = definitions.get(row['name'], {})
        stats = counts.get(row['name'], {'trigger_count': 0, 'last_triggered': None})
        result.append({**definition, **dict(row), 'enabled': bool(row['enabled']), **stats})
    return jsonify(result)


@app.route('/api/detection-rules/<name>', methods=['PATCH'])
@require_min_role('admin')
def update_detection_rule(name: str):
    definitions = {rule['name']: rule for rule in get_rules_info()}
    if name not in definitions:
        return jsonify({'error': 'Detection rule not found'}), 404
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'A JSON object is required'}), 400
    allowed = {'enabled', 'threshold', 'time_window_seconds'}
    unknown = set(data) - allowed
    if unknown:
        return jsonify({'error': 'Unsupported detection rule field'}), 400
    if not data:
        return jsonify({'error': 'At least one supported field is required'}), 400
    if 'enabled' in data and not isinstance(data['enabled'], bool):
        return jsonify({'error': 'enabled must be boolean'}), 400
    supported = definitions[name]['supported_configuration']
    if ('threshold' in data or 'time_window_seconds' in data) and not supported:
        return jsonify({'error': 'This rule has no editable threshold or time window'}), 400
    threshold = data.get('threshold')
    window = data.get('time_window_seconds')
    if threshold is not None and (not isinstance(threshold, int) or isinstance(threshold, bool) or not 1 <= threshold <= 100000):
        return jsonify({'error': 'threshold must be an integer between 1 and 100000'}), 400
    if window is not None and (not isinstance(window, int) or isinstance(window, bool) or not 1 <= window <= 86400):
        return jsonify({'error': 'time_window_seconds must be an integer between 1 and 86400'}), 400

    db = get_db()
    _ensure_detection_rules(db)
    current = db.execute(
        "SELECT enabled, threshold, time_window_seconds FROM detection_rules WHERE name=?", (name,)
    ).fetchone()
    db.execute(
        """UPDATE detection_rules SET enabled=?, threshold=?, time_window_seconds=?,
           updated_at=datetime('now') WHERE name=?""",
        (
            int(data.get('enabled', bool(current['enabled']))),
            threshold if 'threshold' in data else current['threshold'],
            window if 'time_window_seconds' in data else current['time_window_seconds'],
            name,
        ),
    )
    db.commit()
    db.close()
    return jsonify({'name': name, 'updated': True})

# ============================================================
# FILE UPLOAD (Separate Section)
# ============================================================

@app.route('/api/upload/file', methods=['POST'])
@require_auth
def upload_file():
    """Upload a log file for parsing and analysis"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    log_format = request.form.get('log_format', 'auto')
    
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    # Validate extension against allowlist
    import pathlib as _pathlib
    from werkzeug.utils import secure_filename
    ext = _pathlib.Path(file.filename).suffix.lower()
    if ext and ext not in settings.ALLOWED_UPLOAD_EXTENSIONS:
        return jsonify({
            "error": f"File type '{ext}' is not supported. "
                     f"Allowed: {sorted(settings.ALLOWED_UPLOAD_EXTENSIONS)}"
        }), 415
    
    content = file.read()
    file_size = len(content)
    
    # Detect encoding
    detected = chardet.detect(content)
    encoding = detected.get('encoding', 'utf-8') or 'utf-8'
    try:
        text_content = content.decode(encoding)
    except UnicodeDecodeError:
        text_content = content.decode('utf-8', errors='replace')
    
    # Parse
    fmt, logs = LogIngestionService.parse_content(text_content, log_format)
    if not logs:
        return jsonify({"error": "No valid log entries found in the file"}), 400
    
    upload_session_id = str(uuid.uuid4())
    safe_filename = secure_filename(file.filename)
    if not safe_filename:
        return jsonify({"error": "Invalid filename"}), 400
    db = get_db()
    _ensure_detection_rules(db)
    load_rule_overrides(db.execute("SELECT name, enabled, threshold, time_window_seconds FROM detection_rules").fetchall())
    
    # Save upload record
    upload_id = str(uuid.uuid4())
    db.execute("""INSERT INTO uploaded_files (id, filename, original_name, file_type, file_size,
        log_format, status, total_logs, upload_session_id) VALUES (?,?,?,?,?,?,?,?,?)""",
        (upload_id, f"{upload_session_id}_{safe_filename}", file.filename,
         file.content_type or 'text/plain', file_size, fmt, 'processing', len(logs), upload_session_id))
    
    # Store log entries and run detection
    alerts_generated = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for log_data in logs:
        log_id = log_data.get('id', str(uuid.uuid4()))
        tags = log_data.get('tags', '[]')
        if isinstance(tags, list):
            existing = tags
            existing.extend(['uploaded', upload_session_id])
            tags = json.dumps(existing)
        else:
            try:
                existing = json.loads(tags)
            except:
                existing = []
            existing.extend(['uploaded', upload_session_id])
            tags = json.dumps(existing)
        
        db.execute("""INSERT OR IGNORE INTO log_entries
            (id, timestamp, source, source_type, event_type, event_id, severity, message,
             raw_log, source_ip, destination_ip, username, hostname, process_name, tags, upload_session_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (log_id, log_data.get('timestamp', ''), log_data.get('source', 'unknown'),
             log_data.get('source_type', 'unknown'), log_data.get('event_type', 'general'),
             str(log_data.get('event_id', '')), log_data.get('severity', 'info'),
             log_data.get('message', ''), log_data.get('raw_log', ''),
             log_data.get('source_ip', ''), log_data.get('destination_ip', ''),
             log_data.get('username', ''), log_data.get('hostname', ''),
             log_data.get('process_name', ''), tags, upload_session_id))
        
        sev = log_data.get('severity', 'info')
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        triggered = evaluate_log(log_data)
        for alert_data in triggered:
            ai_analysis = ai_engine.analyze_alert(alert_data)
            db.execute("""INSERT INTO alerts (id, title, description, severity, status, rule_name,
                confidence, source, source_ip, destination_ip, username, hostname, mitre_techniques,
                kill_chain_phase, related_log_ids, evidence, ai_analysis, threat_score)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (str(uuid.uuid4()), alert_data['title'], alert_data['description'],
                 alert_data['severity'], 'new', alert_data['rule_name'],
                 alert_data.get('confidence', 70),
                 alert_data.get('source', ''), alert_data.get('source_ip', ''),
                 alert_data.get('destination_ip', ''), alert_data.get('username', ''),
                 alert_data.get('hostname', ''), json.dumps(alert_data.get('mitre_techniques', [])),
                 alert_data.get('kill_chain_phase', ''), json.dumps([log_id]),
                 json.dumps(alert_data.get('evidence', {})),
                 json.dumps(ai_analysis), ai_analysis.get('threat_score', 50)))
            alerts_generated += 1
    
    db.execute("""UPDATE uploaded_files SET parsed_logs=?, alerts_generated=?, status='completed',
        analysis_results=? WHERE id=?""",
        (len(logs), alerts_generated, json.dumps({
            "format_detected": fmt, "total_entries": len(logs),
            "alerts_generated": alerts_generated, "severity_breakdown": severity_counts,
        }), upload_id))
    
    db.commit()
    db.close()
    
    return jsonify({
        "id": upload_id, "filename": file.filename, "format_detected": fmt,
        "total_logs": len(logs), "alerts_generated": alerts_generated,
        "severity_breakdown": severity_counts, "upload_session_id": upload_session_id,
        "status": "completed",
    })

@app.route('/api/upload/history')
@require_auth
def upload_history():
    db = get_db()
    files = [row_to_dict(r) for r in db.execute(
        "SELECT * FROM uploaded_files ORDER BY created_at DESC LIMIT 50").fetchall()]
    db.close()
    return jsonify(files)

@app.route('/api/upload/<upload_id>/logs')
@require_auth
def uploaded_logs(upload_id):
    db = get_db()
    limit = _safe_int(request.args.get('limit', 100), default=100, minimum=1, maximum=1000)
    offset = _safe_int(request.args.get('offset', 0), default=0, minimum=0)
    logs = [row_to_dict(r) for r in db.execute(
        "SELECT * FROM log_entries WHERE upload_session_id=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (upload_id, limit, offset)).fetchall()]
    db.close()
    return jsonify(logs)

@app.route('/api/upload/formats')
@require_auth
def upload_formats():
    return jsonify({"formats": [
        {"id": "auto", "name": "Auto-Detect", "description": "Automatically detect the log format", "extensions": ["*"]},
        {"id": "windows_xml", "name": "Windows Event Log (XML)", "description": "Windows Event Log XML format", "extensions": [".xml", ".evtx"]},
        {"id": "windows_text", "name": "Windows Event Log (Text)", "description": "Windows Event Log text export", "extensions": [".txt", ".log"]},
        {"id": "syslog", "name": "Syslog (Linux/Unix)", "description": "Standard syslog format", "extensions": [".log", ".txt"]},
        {"id": "firewall", "name": "Firewall Logs", "description": "Firewall logs (Palo Alto, Cisco, iptables)", "extensions": [".log", ".txt", ".csv"]},
        {"id": "json", "name": "JSON Logs", "description": "JSON formatted logs", "extensions": [".json", ".ndjson"]},
        {"id": "csv", "name": "CSV Logs", "description": "CSV formatted log files", "extensions": [".csv"]},
        {"id": "plain", "name": "Plain Text", "description": "Plain text log files", "extensions": [".txt", ".log"]},
    ]})

@app.route('/api/upload/stats')
@require_auth
def upload_stats_summary():
    """Get stats for uploaded files only (separate from demo data)"""
    db = get_db()
    total_uploaded_logs = db.execute(
        "SELECT COUNT(*) FROM log_entries WHERE upload_session_id != '' AND upload_session_id IS NOT NULL"
    ).fetchone()[0]
    
    by_severity = {}
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        by_severity[sev] = db.execute(
            "SELECT COUNT(*) FROM log_entries WHERE (upload_session_id != '' AND upload_session_id IS NOT NULL) AND severity=?", (sev,)
        ).fetchone()[0]
    
    by_source = {}
    for st in ['windows', 'linux', 'firewall', 'ids', 'network']:
        c = db.execute(
            "SELECT COUNT(*) FROM log_entries WHERE (upload_session_id != '' AND upload_session_id IS NOT NULL) AND source_type=?", (st,)
        ).fetchone()[0]
        if c > 0:
            by_source[st] = c
    
    files = [row_to_dict(r) for r in db.execute(
        "SELECT * FROM uploaded_files ORDER BY created_at DESC LIMIT 50").fetchall()]
    
    total_alerts = sum(f.get('alerts_generated', 0) or 0 for f in files)
    
    db.close()
    return jsonify({
        "total_logs": total_uploaded_logs,
        "total_alerts": total_alerts,
        "total_files": len(files),
        "by_severity": by_severity,
        "by_source": by_source,
        "files": files,
    })

@app.route('/api/upload/<upload_id>', methods=['DELETE'])
@require_min_role('admin')
def delete_upload(upload_id):
    """Delete an uploaded file record along with its log entries and related alerts."""
    db = get_db()

    # Get the file record so we can find the upload_session_id
    file_row = row_to_dict(db.execute(
        "SELECT * FROM uploaded_files WHERE id=?", (upload_id,)).fetchone())

    if not file_row:
        db.close()
        return jsonify({"error": "Upload not found"}), 404

    session_id = file_row.get('upload_session_id', '')

    # Delete the physical file from disk (best-effort)
    try:
        disk_path = os.path.join(settings.UPLOAD_DIR, file_row.get('filename', ''))
        if os.path.exists(disk_path):
            os.remove(disk_path)
    except Exception:
        pass  # Don't fail if file is already gone

    logs_deleted = 0
    alerts_deleted = 0

    if session_id:
        # Collect log IDs belonging to this session so we can clean up alerts
        log_ids = [r[0] for r in db.execute(
            "SELECT id FROM log_entries WHERE upload_session_id=?", (session_id,)).fetchall()]

        # Delete alerts whose related_log_ids overlap with this session's logs
        if log_ids:
            all_alerts = db.execute("SELECT id, related_log_ids FROM alerts").fetchall()
            alert_ids_to_delete = []
            for a in all_alerts:
                try:
                    related = json.loads(a[1]) if isinstance(a[1], str) else (a[1] or [])
                except Exception:
                    related = []
                if any(lid in related for lid in log_ids):
                    alert_ids_to_delete.append(a[0])
            if alert_ids_to_delete:
                ph = ','.join(['?' for _ in alert_ids_to_delete])
                db.execute(f"DELETE FROM alerts WHERE id IN ({ph})", alert_ids_to_delete)
                alerts_deleted = len(alert_ids_to_delete)

        # Delete log entries
        cur = db.execute(
            "DELETE FROM log_entries WHERE upload_session_id=?", (session_id,))
        logs_deleted = cur.rowcount

    # Delete the file record itself
    db.execute("DELETE FROM uploaded_files WHERE id=?", (upload_id,))
    db.commit()
    db.close()

    return jsonify({
        "deleted": True,
        "logs_deleted": logs_deleted,
        "alerts_deleted": alerts_deleted,
    })

# ============================================================
# AI ENDPOINTS
# ============================================================

@app.route('/api/ai/chat', methods=['POST'])
@require_auth
def ai_chat():
    data = request.get_json() or {}
    message = (data.get('message') or '').strip()
    if not message:
        return jsonify({'error': 'message is required'}), 400
    if len(message) > 4000:
        return jsonify({'error': 'message must be 4000 characters or fewer'}), 400

    # Build bounded SOC context from DB — browser never supplies authoritative data
    hours = _safe_int(data.get('hours', 24), default=24, minimum=1, maximum=168)
    data_source = data.get('data_source', 'all')
    if data_source not in ('all', 'live', 'uploaded'):
        data_source = 'all'
    severity_filter = data.get('severity')
    source_type_filter = data.get('source_type')

    db = get_db()
    try:
        ctx = soc_ctx.build_soc_context(
            db,
            hours=hours,
            data_source=data_source,
            severity=severity_filter,
            source_type=source_type_filter,
        )
    finally:
        db.close()

    response_text = ai_engine.chat_response(message, ctx)

    return jsonify({
        "response": response_text,
        "context_meta": {
            "time_range_hours": hours,
            "data_source": data_source,
            "alerts_considered": ctx["alerts"]["total_active"],
            "logs_considered": ctx["logs"]["recent_count"],
            "alerts_truncated": ctx["alerts"]["truncated"],
            "logs_truncated": ctx["logs"]["truncated"],
            "ai_mode": "live" if settings.OPENAI_API_KEY else "mock",
            "model": settings.OPENAI_MODEL if settings.OPENAI_API_KEY else "mock",
        },
    })

@app.route('/api/ai/analyze-alert', methods=['POST'])
@require_auth
def ai_analyze_alert():
    data = request.get_json() or {}
    alert_id = data.get('alert_id')
    alert_data = data.get('alert_data')
    
    if alert_id:
        db = get_db()
        alert = row_to_dict(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
        db.close()
        if not alert:
            return jsonify({"error": "Not found"}), 404
        alert_data = alert
    
    if not alert_data:
        return jsonify({"error": "Provide alert_id or alert_data"}), 400
    
    analysis = ai_engine.analyze_alert(alert_data)
    return jsonify(analysis)

@app.route('/api/ai/threat-assessment')
@require_auth
def ai_threat_assessment():
    """Threat score is based on ACTIVE alerts only (new/investigating/escalated).
    Resolved and false-positive alerts do not contribute to the threat level."""
    db = get_db()
    active = "('new','acknowledged','investigating','escalated')"
    stats = {
        'total_alerts': db.execute(
            f"SELECT COUNT(*) FROM alerts WHERE status IN {active}"
        ).fetchone()[0]
    }
    for sev in ['critical', 'high', 'medium', 'low']:
        stats[sev] = db.execute(
            f"SELECT COUNT(*) FROM alerts WHERE severity=? AND status IN {active}", (sev,)
        ).fetchone()[0]
    stats['total_logs'] = db.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
    db.close()
    return jsonify(ai_engine.threat_assessment(stats))

@app.route('/api/ai/status')
@require_auth
def ai_status():
    status = {
        "available": False,
        "model": "mock",
        "message": "Demo mode - add OPENAI_API_KEY for live AI",
    }

    if settings.OPENAI_API_KEY:
        # Tentatively mark available; further check below may update with connectivity info
        status["available"] = True
        status["model"] = settings.OPENAI_MODEL or "unknown"
        status["message"] = "AI analysis active"

        # Run a lightweight connectivity check to surface quota/errors to the UI
        try:
            import openai
            client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
            # List models is lightweight and sufficient to verify auth/connectivity
            models = client.models.list()
            # If models returned but empty, still ok; include count for debugging
            status["model_count"] = len(models.data) if hasattr(models, 'data') else None
            status["health"] = "ok"
        except Exception as e:
            # Surface a safe, short error summary without exposing secrets
            err_msg = str(e)
            status["available"] = True
            status["health"] = "error"
            if hasattr(e, 'code'):
                status["error_code"] = getattr(e, 'code')
            # Keep message user-friendly
            if 'quota' in err_msg.lower() or 'insufficient_quota' in err_msg.lower() or 'rate' in err_msg.lower():
                status["message"] = "AI key detected but billing/quota prevents live calls (check OpenAI billing)."
            else:
                status["message"] = "AI key detected but connectivity test failed. See backend logs for details."
            # Keep provider details in server logs only; never return them to clients.
            app.logger.warning("AI provider connectivity check failed: %s", type(e).__name__)

    return jsonify(status)

@app.route('/api/reports/summary')
@require_auth
def reports_summary():
    db = get_db()
    active = "('new','acknowledged','investigating','escalated')"
    alert_rows = db.execute(
        f"SELECT severity, rule_name, title, source_ip, username, created_at "
        f"FROM alerts WHERE status IN {active} ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    total_alerts   = db.execute(f"SELECT COUNT(*) FROM alerts WHERE status IN {active}").fetchone()[0]
    critical_alerts = db.execute(f"SELECT COUNT(*) FROM alerts WHERE severity='critical' AND status IN {active}").fetchone()[0]
    high_alerts     = db.execute(f"SELECT COUNT(*) FROM alerts WHERE severity='high'     AND status IN {active}").fetchone()[0]
    total_logs      = db.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
    db.close()

    key_points = []
    if critical_alerts:
        key_points.append(f"{critical_alerts} critical severity alert(s) demand immediate containment.")
    if high_alerts:
        key_points.append(f"{high_alerts} high severity alert(s) warrant analyst review.")
    if total_logs:
        key_points.append(f"{total_logs} log entries are currently available for correlation.")
    if alert_rows:
        latest = alert_rows[0]
        key_points.append(f"The most recent alert was {latest['title']} from {latest['source_ip'] or 'an unknown source'}.")

    high_priority_actions = [
        'Contain the most severe alerts and preserve evidence before remediation.',
        'Investigate authentication failures for suspicious IPs and accounts.',
        'Correlate related logs and incident timelines before closing the case.',
    ]

    executive_summary = (
        f"The environment currently contains {total_alerts} alert(s) across {total_logs} log entries. "
        f"Priority attention should focus on {critical_alerts} critical and {high_alerts} high severity findings."
    )

    return jsonify({
        "executive_summary": executive_summary,
        "key_points": key_points,
        "high_priority_actions": high_priority_actions,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })

@app.route('/api/data/live-logs', methods=['DELETE'])
@require_min_role('admin')
def clear_live_logs():
    """
    Delete all live-ingested log entries (those without an upload_session_id)
    and any alerts that were generated solely from those logs.
    Sets a watermark timestamp so the forwarder cannot re-fill with old events.
    Uploaded file logs are untouched.
    """
    global _LIVE_CLEARED_AT

    # Record the clear time BEFORE deleting so the ingest endpoint starts
    # rejecting old logs immediately — even the batch currently in-flight.
    cleared_at = datetime.now(timezone.utc).timestamp()
    _LIVE_CLEARED_AT = cleared_at

    db = get_db()

    # Persist the watermark so it survives a backend restart
    db.execute(
        "INSERT OR REPLACE INTO app_settings (key, value) VALUES ('live_cleared_at', ?)",
        (str(cleared_at),)
    )

    # Collect IDs of live log entries
    live_log_ids = [
        r[0] for r in db.execute(
            "SELECT id FROM log_entries WHERE (upload_session_id = '' OR upload_session_id IS NULL)"
        ).fetchall()
    ]

    # Find alerts whose related_log_ids overlap exclusively with live logs
    alerts_to_delete = []
    all_alerts = db.execute("SELECT id, related_log_ids FROM alerts").fetchall()
    live_id_set = set(live_log_ids)
    for row in all_alerts:
        try:
            related = json.loads(row[1]) if isinstance(row[1], str) else (row[1] or [])
        except Exception:
            related = []
        if not related or all(lid in live_id_set for lid in related):
            alerts_to_delete.append(row[0])

    alerts_deleted = 0
    if alerts_to_delete:
        ph = ','.join(['?' for _ in alerts_to_delete])
        alerts_deleted = db.execute(
            f"DELETE FROM alerts WHERE id IN ({ph})", alerts_to_delete
        ).rowcount

    logs_deleted = db.execute(
        "DELETE FROM log_entries WHERE (upload_session_id = '' OR upload_session_id IS NULL)"
    ).rowcount

    db.commit()
    db.close()

    return jsonify({
        "success": True,
        "logs_deleted": logs_deleted,
        "alerts_deleted": alerts_deleted,
        "message": f"Cleared {logs_deleted} live log entries and {alerts_deleted} associated alerts.",
    })


# ============================================================
# INCIDENTS
# ============================================================

@app.route('/api/incidents')
@require_auth
def get_incidents():
    db = get_db()
    incidents = [row_to_dict(r) for r in db.execute(
        "SELECT * FROM incidents ORDER BY created_at DESC LIMIT 50").fetchall()]
    db.close()
    return jsonify(incidents)

_VALID_SEVERITIES_SET = frozenset({'critical', 'high', 'medium', 'low', 'info'})

@app.route('/api/incidents', methods=['POST'])
@require_min_role('analyst')
def create_incident():
    data = request.get_json() or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400
    if len(title) > 300:
        return jsonify({'error': 'title must be 300 characters or fewer'}), 400
    description = (data.get('description') or '')[:2000]
    severity = (data.get('severity') or 'medium').lower()
    if severity not in _VALID_SEVERITIES_SET:
        return jsonify({'error': f"Invalid severity '{severity}'"}), 400

    db = get_db()
    iid = str(uuid.uuid4())
    # Also support linking alert_ids at creation time
    alert_ids = data.get('alert_ids')
    assigned_analyst = (data.get('assigned_analyst') or '').strip()[:200]
    priority = (data.get('priority') or 'medium').strip()[:20]
    notes = (data.get('notes') or '').strip()[:5000]

    db.execute(
        """INSERT INTO incidents
           (id, title, description, severity, status, alert_ids, assigned_analyst, priority, notes)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (iid, title, description, severity, 'new',
         json.dumps(alert_ids) if isinstance(alert_ids, list) else '[]',
         assigned_analyst, priority, notes),
    )
    db.commit()
    socketio.emit('incident_created', {"id": iid, "title": title})
    db.close()
    return jsonify({"id": iid, "title": title, "status": "new"}), 201

@app.route('/api/incidents/<iid>')
@require_auth
def get_incident(iid):
    db = get_db()
    incident = row_to_dict(db.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone())
    if not incident:
        db.close()
        return jsonify({"error": "Not found"}), 404

    alert_ids = incident.get('alert_ids', [])
    alerts = []
    if alert_ids:
        ph = ','.join(['?' for _ in alert_ids])
        alerts = [row_to_dict(r) for r in db.execute(
            f"SELECT id, title, severity, status, rule_name, source_ip, hostname, username, mitre_techniques, created_at FROM alerts WHERE id IN ({ph})", alert_ids).fetchall()]
    incident['alerts'] = alerts

    # Auto-populate affected_hosts / affected_users / source_ips from linked alerts if empty
    if not incident.get('affected_hosts') and alerts:
        incident['affected_hosts'] = list({a.get('hostname', '') for a in alerts if a.get('hostname')})
    if not incident.get('affected_users') and alerts:
        incident['affected_users'] = list({a.get('username', '') for a in alerts if a.get('username')})
    if not incident.get('source_ips') and alerts:
        incident['source_ips'] = list({a.get('source_ip', '') for a in alerts if a.get('source_ip')})

    # Collect MITRE techniques from all linked alerts
    all_mitre: set = set()
    for a in alerts:
        for t in (a.get('mitre_techniques') or []):
            if t:
                all_mitre.add(str(t))
    incident['mitre_techniques'] = sorted(all_mitre)

    db.close()
    return jsonify(incident)

_VALID_INC_STATUSES = frozenset({'new', 'triaged', 'investigating', 'contained', 'resolved',
                                   'open', 'remediated', 'closed'})


@app.route('/api/incidents/<iid>', methods=['PATCH'])
@require_min_role('analyst')
def update_incident(iid: str):
    data = request.get_json() or {}
    status = request.args.get('status') or data.get('status')

    if status and status not in _VALID_INC_STATUSES:
        return jsonify({'error': f"Invalid status '{status}'"}), 400

    db = get_db()
    row = db.execute("SELECT id FROM incidents WHERE id=?", (iid,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'Incident not found'}), 404

    updates = []
    params: list = []

    if status:
        updates.append("status=?"); params.append(status)

    # Updatable fields
    _TEXT_FIELDS = {
        'title': 300, 'description': 2000, 'notes': 5000,
        'resolution': 5000, 'assigned_analyst': 200, 'priority': 20,
        'assigned_to': 200,
    }
    for field, max_len in _TEXT_FIELDS.items():
        if field in data:
            updates.append(f"{field}=?"); params.append(str(data[field])[:max_len])

    # JSON array fields
    for json_field in ('alert_ids', 'affected_hosts', 'affected_users', 'source_ips'):
        if json_field in data:
            if isinstance(data[json_field], list):
                updates.append(f"{json_field}=?"); params.append(json.dumps(data[json_field]))

    # Timeline append
    if 'timeline_event' in data and isinstance(data['timeline_event'], dict):
        user = get_current_user()
        evt = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event': str(data['timeline_event'].get('event', ''))[:500],
            'actor': user.get('email', 'unknown'),
        }
        current_timeline = json.loads(db.execute(
            "SELECT timeline FROM incidents WHERE id=?", (iid,)
        ).fetchone()[0] or '[]')
        current_timeline.append(evt)
        updates.append("timeline=?"); params.append(json.dumps(current_timeline))

    if not updates:
        db.close()
        return jsonify({'id': iid, 'updated': False}), 200

    updates.append("updated_at=datetime('now')")
    params.append(iid)
    db.execute(f"UPDATE incidents SET {', '.join(updates)} WHERE id=?", params)
    db.commit()
    db.close()
    socketio.emit('incident_updated', {'id': iid, 'status': status})
    return jsonify({"id": iid, "status": status, "updated": True})


# ============================================================
# FALSE POSITIVE CLASSIFICATION
# ============================================================

_VALID_FP_CLASSIFICATIONS = frozenset({
    'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN', 'NEEDS_INVESTIGATION'
})


@app.route('/api/alerts/<alert_id>/classify', methods=['POST'])
@require_min_role('analyst')
def classify_alert(alert_id: str):
    """Analyst classification of an alert — TRUE_POSITIVE / FALSE_POSITIVE / BENIGN / NEEDS_INVESTIGATION."""
    data = request.get_json() or {}
    classification = (data.get('classification') or '').strip().upper()
    reason = (data.get('reason') or '').strip()[:1000]

    if classification not in _VALID_FP_CLASSIFICATIONS:
        return jsonify({
            'error': f"Invalid classification. Must be one of: {sorted(_VALID_FP_CLASSIFICATIONS)}"
        }), 400
    if not reason:
        return jsonify({'error': 'reason is required'}), 400

    db = get_db()
    row = db.execute("SELECT id, status FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'Alert not found'}), 404

    user = get_current_user()
    now = datetime.now(timezone.utc).isoformat()

    # If classifying as FALSE_POSITIVE or BENIGN, transition status too
    new_status = None
    if classification in ('FALSE_POSITIVE', 'BENIGN') and row['status'] not in ('false_positive', 'resolved'):
        event, status_error, status_error_code = _transition_alert(
            db, alert_id, 'false_positive', user, f"Classified as {classification}: {reason}"
        )
        if status_error:
            db.close()
            return jsonify(status_error), status_error_code
        new_status = 'false_positive'
        socketio.emit('alert_update', event)

    db.execute(
        """UPDATE alerts
           SET fp_classification=?, fp_classified_by=?, fp_classified_at=?, fp_reason=?, updated_at=?
           WHERE id=?""",
        (classification, user.get('email', ''), now, reason, now, alert_id),
    )
    db.commit()
    db.close()

    return jsonify({
        'alert_id': alert_id,
        'classification': classification,
        'classified_by': user.get('email', ''),
        'classified_at': now,
        'reason': reason,
        'status_changed': new_status is not None,
        'new_status': new_status,
    })


# ============================================================
# SOC METRICS
# ============================================================

@app.route('/api/soc/metrics')
@require_auth
def soc_metrics():
    """
    Returns comprehensive SOC metrics calculated from real database data.
    Never hardcodes values — if data unavailable, returns null.
    """
    db = get_db()

    # Alert counts
    total_alerts = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    total_logs   = db.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]

    sev_rows = db.execute(
        "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
    ).fetchall()
    by_severity = {r[0]: r[1] for r in sev_rows}

    status_rows = db.execute(
        "SELECT status, COUNT(*) FROM alerts GROUP BY status"
    ).fetchall()
    by_status = {r[0]: r[1] for r in status_rows}

    # Open = active alerts
    open_alerts = sum(v for k, v in by_status.items()
                      if k in ('new', 'acknowledged', 'investigating', 'escalated'))
    resolved_alerts = by_status.get('resolved', 0)
    fp_alerts = by_status.get('false_positive', 0)

    # False positive rate (among classified alerts)
    classified = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE fp_classification != '' AND fp_classification IS NOT NULL"
    ).fetchone()[0]
    fp_classified = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE fp_classification IN ('FALSE_POSITIVE', 'BENIGN')"
    ).fetchone()[0]
    fp_rate = round(fp_classified / classified * 100, 1) if classified > 0 else None

    # Incident counts
    inc_status_rows = db.execute(
        "SELECT status, COUNT(*) FROM incidents GROUP BY status"
    ).fetchall()
    inc_by_status = {r[0]: r[1] for r in inc_status_rows}
    total_incidents = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    open_incidents = sum(v for k, v in inc_by_status.items()
                         if k in ('new', 'triaged', 'investigating', 'contained', 'open'))
    resolved_incidents = sum(v for k, v in inc_by_status.items()
                              if k in ('resolved', 'remediated', 'closed'))

    # Detection rule trigger counts
    rule_counts = [
        {'rule': r[0], 'count': r[1], 'last_triggered': r[2]}
        for r in db.execute(
            "SELECT rule_name, COUNT(*) as cnt, MAX(created_at) "
            "FROM alerts WHERE rule_name != '' GROUP BY rule_name ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
    ]

    # Mean time to detect (MTTD) — time from event to alert creation
    # Mean time to resolve (MTTR) — time from alert creation to resolved
    mttr_rows = db.execute(
        """SELECT created_at, updated_at FROM alerts
           WHERE status='resolved' AND updated_at IS NOT NULL
           AND created_at IS NOT NULL
           ORDER BY created_at DESC LIMIT 100"""
    ).fetchall()
    mttr_minutes = None
    if mttr_rows:
        deltas = []
        for row in mttr_rows:
            try:
                created = datetime.fromisoformat(row[0].replace('Z', '+00:00'))
                updated = datetime.fromisoformat(row[1].replace('Z', '+00:00'))
                delta_mins = (updated - created).total_seconds() / 60
                if 0 < delta_mins < 10080:  # within 7 days (filter test data)
                    deltas.append(delta_mins)
            except Exception:
                pass
        if deltas:
            mttr_minutes = round(sum(deltas) / len(deltas), 1)

    # Active analyst workload (alerts per status)
    analyst_workload = {
        'new': by_status.get('new', 0),
        'acknowledged': by_status.get('acknowledged', 0),
        'investigating': by_status.get('investigating', 0),
        'escalated': by_status.get('escalated', 0),
    }

    # Top MITRE techniques across active alerts
    mitre_rows = db.execute(
        "SELECT mitre_techniques FROM alerts WHERE status IN ('new','acknowledged','investigating','escalated')"
    ).fetchall()
    mitre_counts: dict = {}
    for row in mitre_rows:
        val = row[0]
        if isinstance(val, str):
            try:
                techniques = json.loads(val)
            except Exception:
                techniques = []
        else:
            techniques = val or []
        for t in (techniques or []):
            t = str(t)[:60]
            mitre_counts[t] = mitre_counts.get(t, 0) + 1
    top_mitre = sorted(mitre_counts.items(), key=lambda x: -x[1])[:8]

    db.close()

    return jsonify({
        'total_events': total_logs,
        'total_alerts': total_alerts,
        'critical_alerts': by_severity.get('critical', 0),
        'high_alerts': by_severity.get('high', 0),
        'medium_alerts': by_severity.get('medium', 0),
        'low_alerts': by_severity.get('low', 0),
        'open_alerts': open_alerts,
        'resolved_alerts': resolved_alerts,
        'false_positive_alerts': fp_alerts,
        'total_incidents': total_incidents,
        'open_incidents': open_incidents,
        'resolved_incidents': resolved_incidents,
        'false_positive_rate': fp_rate,
        'classified_alerts': classified,
        'mttr_minutes': mttr_minutes,
        'analyst_workload': analyst_workload,
        'top_detection_rules': rule_counts,
        'top_mitre': [{'technique': t, 'count': c} for t, c in top_mitre],
        'by_severity': by_severity,
        'by_status': by_status,
    })


# ============================================================
# ALERT CORRELATION
# ============================================================

@app.route('/api/alerts/<alert_id>/correlations')
@require_auth
def get_alert_correlations(alert_id: str):
    """
    Returns deterministic correlations for an alert based on:
    - Same source IP
    - Same destination IP
    - Same user
    - Same host
    - Close timestamps (within 30 minutes)
    Does NOT use AI to invent relationships.
    """
    db = get_db()
    alert = row_to_dict(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
    if not alert:
        db.close()
        return jsonify({'error': 'Alert not found'}), 404

    correlations: list[dict] = []
    seen_ids: set = {alert_id}

    def _add_correlation(related_alert: dict, reason: str) -> None:
        if related_alert['id'] in seen_ids:
            return
        seen_ids.add(related_alert['id'])
        correlations.append({
            'alert_id': related_alert['id'],
            'title': related_alert['title'],
            'severity': related_alert['severity'],
            'status': related_alert['status'],
            'rule_name': related_alert.get('rule_name', ''),
            'source_ip': related_alert.get('source_ip', ''),
            'username': related_alert.get('username', ''),
            'hostname': related_alert.get('hostname', ''),
            'created_at': related_alert['created_at'],
            'relationship_reason': reason,
        })

    base_fields = [
        ('source_ip',      'Same source IP'),
        ('destination_ip', 'Same destination IP'),
        ('username',       'Same user account'),
        ('hostname',       'Same host'),
    ]

    for field, reason in base_fields:
        val = (alert.get(field) or '').strip()
        if not val:
            continue
        rows = db.execute(
            f"SELECT id, title, severity, status, rule_name, source_ip, username, hostname, created_at "
            f"FROM alerts WHERE {field}=? AND id!=? ORDER BY created_at DESC LIMIT 10",
            (val, alert_id),
        ).fetchall()
        for row in rows:
            _add_correlation(dict(row), reason)

    # Timestamp-based: alerts within 30 minutes
    if alert.get('created_at'):
        try:
            from datetime import timedelta as _td
            alert_ts = datetime.fromisoformat(alert['created_at'].replace('Z', '+00:00'))
            window_start = (alert_ts - _td(minutes=30)).isoformat()
            window_end   = (alert_ts + _td(minutes=30)).isoformat()
            rows = db.execute(
                "SELECT id, title, severity, status, rule_name, source_ip, username, hostname, created_at "
                "FROM alerts WHERE id!=? AND created_at BETWEEN ? AND ? "
                "ORDER BY created_at DESC LIMIT 15",
                (alert_id, window_start, window_end),
            ).fetchall()
            for row in rows:
                _add_correlation(dict(row), 'Close timestamp (±30 min)')
        except Exception:
            pass

    # Sort: same-IP or same-user first, then timestamp
    correlations.sort(key=lambda x: (
        0 if 'source IP' in x['relationship_reason'] or 'user' in x['relationship_reason'] else 1,
        x['created_at'],
    ), reverse=False)

    db.close()
    return jsonify({
        'alert_id': alert_id,
        'correlations': correlations[:20],
        'total': len(correlations),
    })


# ── Escalate alert → AI-generated incident ───────────────────────────────────

@app.route('/api/alerts/<alert_id>/escalate', methods=['POST'])
@require_min_role('analyst')
def escalate_alert(alert_id: str):
    """
    Idempotent: escalates the alert and creates/returns an AI-generated incident.
    If the alert already has an incident, returns the existing one.
    """
    db = get_db()
    alert = row_to_dict(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
    if not alert:
        db.close()
        return jsonify({"error": "Alert not found"}), 404

    # ── Idempotency: return existing incident if already escalated ────────
    existing_iid = None
    existing_row = db.execute(
        "SELECT id FROM incidents WHERE alert_ids LIKE ?",
        (f'%"{alert_id}"%',)
    ).fetchone()
    if existing_row:
        db.close()
        return jsonify({"incident_id": existing_row[0], "created": False,
                        "message": "Alert already linked to an incident."})

    # ── Load related logs and alerts for AI context ───────────────────────
    related_log_ids = alert.get('related_log_ids') or []
    related_logs: list = []
    if related_log_ids:
        ph = ','.join(['?' for _ in related_log_ids])
        related_logs = [row_to_dict(r) for r in db.execute(
            f"SELECT id,timestamp,source_type,severity,message,source_ip FROM log_entries WHERE id IN ({ph})",
            related_log_ids,
        ).fetchall()]

    related_alerts: list = []
    if alert.get('source_ip') or alert.get('hostname'):
        params = [alert_id]
        clauses = []
        if alert.get('source_ip'):
            clauses.append("source_ip=?"); params.append(alert['source_ip'])
        if alert.get('hostname'):
            clauses.append("hostname=?"); params.append(alert['hostname'])
        related_alerts = [row_to_dict(r) for r in db.execute(
            "SELECT id,title,severity,rule_name FROM alerts WHERE id!=? AND ("
            + " OR ".join(clauses) + ") LIMIT 5", params,
        ).fetchall()]

    # ── Close the DB before calling OpenAI ───────────────────────────────
    db.close()

    # ── Generate incident content (AI or fallback) ────────────────────────
    content = ai_engine.generate_incident_content(alert, related_logs, related_alerts)

    # ── Write incident and link alert transactionally ─────────────────────
    db = get_db()
    iid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    user = get_current_user()
    status_event, status_error, status_error_code = _transition_alert(
        db, alert_id, 'escalated', user, 'Alert escalated to incident'
    )
    if status_error:
        db.close()
        return jsonify(status_error), status_error_code

    timeline = [{
        "timestamp": now,
        "event": "Incident created via alert escalation",
        "actor": user.get('email', 'unknown'),
        "alert_id": alert_id,
        "ai_generated": content.get('ai_generated', False),
        "fallback": content.get('fallback', True),
    }]

    db.execute(
        """INSERT INTO incidents
           (id, title, description, severity, status, alert_ids, ai_summary, timeline, assigned_to,
            affected_hosts, affected_users, source_ips)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            iid,
            content.get('title', alert.get('title', 'Escalated Incident'))[:300],
            content.get('executive_summary', '')[:2000],
            content.get('severity', alert.get('severity', 'medium')),
            'investigating',
            json.dumps([alert_id]),
            content.get('technical_summary', '')[:2000],
            json.dumps(timeline),
            user.get('email', ''),
            json.dumps([h for h in (content.get('affected_hosts') or []) if h][:20]),
            json.dumps([u for u in (content.get('affected_users') or []) if u][:20]),
            json.dumps([ip for ip in (content.get('affected_ips') or []) if ip][:20]),
        ),
    )

    db.commit()
    db.close()

    socketio.emit('alert_update', status_event)
    socketio.emit('incident_created', {"id": iid, "title": content.get('title', '')})

    return jsonify({
        "incident_id": iid,
        "created": True,
        "ai_generated": content.get('ai_generated', False),
        "fallback": content.get('fallback', True),
        "title": content.get('title', ''),
        "severity": content.get('severity', alert.get('severity', 'medium')),
        "investigation_steps": content.get('investigation_steps', []),
    })


# ── AI log summarization ──────────────────────────────────────────────────────

@app.route('/api/ai/summarize-logs', methods=['POST'])
@require_auth
def ai_summarize_logs():
    data = request.get_json() or {}
    hours = _safe_int(data.get('hours', 24), default=24, minimum=1, maximum=168)
    data_source = data.get('data_source', 'all')
    if data_source not in ('all', 'live', 'uploaded'):
        data_source = 'all'
    severity = data.get('severity')
    source_type = data.get('source_type')
    hostname = (data.get('hostname') or '').strip()
    username = (data.get('username') or '').strip()
    source_ip = (data.get('source_ip') or '').strip()

    from datetime import timedelta
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    if data_source == 'uploaded':
        log_where = "upload_session_id != '' AND upload_session_id IS NOT NULL"
    elif data_source == 'live':
        log_where = "(upload_session_id = '' OR upload_session_id IS NULL)"
    else:
        log_where = "1=1"

    extra_clauses = " AND created_at >= ?"
    params: list = [since]
    if severity:
        extra_clauses += " AND severity=?"; params.append(severity)
    if source_type:
        extra_clauses += " AND source_type=?"; params.append(source_type)
    if hostname:
        extra_clauses += " AND hostname=?"; params.append(hostname)
    if username:
        extra_clauses += " AND username=?"; params.append(username)
    if source_ip:
        extra_clauses += " AND source_ip=?"; params.append(source_ip)

    _MAX = 200
    db = get_db()
    total_matching = db.execute(
        f"SELECT COUNT(*) FROM log_entries WHERE {log_where}{extra_clauses}", params
    ).fetchone()[0]

    raw_logs = db.execute(
        f"SELECT id,timestamp,source_type,severity,source_ip,username,hostname,message "
        f"FROM log_entries WHERE {log_where}{extra_clauses} ORDER BY created_at DESC LIMIT ?",
        params + [_MAX],
    ).fetchall()
    logs = [row_to_dict(r) for r in raw_logs]

    # Sanitize log messages against prompt injection
    from soc_context import _sanitize
    for l in logs:
        l['message'] = _sanitize(l.get('message', ''), 200)

    # Get related alerts in the same window
    active_alerts = [row_to_dict(r) for r in db.execute(
        "SELECT id,title,severity,rule_name,source_ip,created_at FROM alerts "
        "WHERE created_at >= ? ORDER BY created_at DESC LIMIT 20",
        (since,),
    ).fetchall()]
    db.close()

    filters = {"hours": hours, "data_source": data_source, "severity": severity,
               "source_type": source_type, "hostname": hostname or None,
               "username": username or None, "source_ip": source_ip or None}

    summary = ai_engine.summarize_logs(logs, active_alerts, filters)
    summary["meta"] = {
        "total_matching_logs": total_matching,
        "logs_analyzed": len(logs),
        "truncated": len(logs) < total_matching,
        "time_range_hours": hours,
        "since": since,
        "filters": filters,
        "ai_mode": "live" if settings.OPENAI_API_KEY else "mock",
        "model": settings.OPENAI_MODEL if settings.OPENAI_API_KEY else "mock",
    }
    return jsonify(summary)


# ── AI incident report ────────────────────────────────────────────────────────

@app.route('/api/incidents/<iid>/report', methods=['POST'])
@require_auth
def generate_incident_report(iid: str):
    db = get_db()
    incident = row_to_dict(db.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone())
    if not incident:
        db.close()
        return jsonify({"error": "Incident not found"}), 404

    alert_ids = incident.get('alert_ids') or []
    alerts: list = []
    if alert_ids:
        ph = ','.join(['?' for _ in alert_ids])
        alerts = [row_to_dict(r) for r in db.execute(
            f"SELECT * FROM alerts WHERE id IN ({ph})", alert_ids
        ).fetchall()]

    log_ids: list = []
    for a in alerts:
        log_ids.extend(a.get('related_log_ids') or [])
    log_ids = list(set(log_ids))[:30]

    logs: list = []
    if log_ids:
        ph = ','.join(['?' for _ in log_ids])
        logs = [row_to_dict(r) for r in db.execute(
            f"SELECT id,timestamp,source_type,severity,message,source_ip FROM log_entries WHERE id IN ({ph})",
            log_ids,
        ).fetchall()]
    db.close()

    from soc_context import _sanitize
    for l in logs:
        l['message'] = _sanitize(l.get('message', ''), 150)

    report = ai_engine.generate_incident_report(incident, alerts, logs)
    report["incident_id"] = iid
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    return jsonify(report)

# ============================================================
# AUTH — DB-backed users and sessions
# ============================================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()

    if _is_rate_limited(ip):
        return jsonify({"error": "Too many login attempts"}), 429

    if not email or not password:
        return jsonify({"error": "Invalid credentials"}), 401

    db = get_db()
    row = db.execute(
        "SELECT id, email, name, password_hash, role, is_active FROM users WHERE email=?",
        (email,),
    ).fetchone()

    if not row or not row['is_active'] or not verify_password(password, row['password_hash']):
        db.close()
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_session(db, row['id'])
    db.commit()
    db.close()

    return jsonify({
        "access_token": token,
        "token_type": "bearer",
        "user": {"email": row['email'], "role": row['role'], "full_name": row['name']},
    })


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    auth = request.headers.get('Authorization', '')
    token = auth[7:].strip() if auth.startswith('Bearer ') else ''
    db = get_db()
    revoke_session(db, token)
    db.commit()
    db.close()
    return jsonify({"message": "Logged out successfully"})


@app.route('/api/auth/me')
@require_auth
def auth_me():
    user = get_current_user()
    return jsonify({
        "email": user['email'],
        "role": user['role'],
        "full_name": user['name'],
    })


# ── Admin: user management ────────────────────────────────────────────────────

@app.route('/api/auth/users')
@require_min_role('admin')
def list_users():
    db = get_db()
    rows = db.execute(
        "SELECT id, email, name, role, is_active, created_at FROM users ORDER BY created_at"
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/auth/users', methods=['POST'])
@require_min_role('admin')
def create_user():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    name = (data.get('name') or '').strip()[:100]
    password = data.get('password') or ''
    role = (data.get('role') or 'analyst').lower()

    _VALID_ROLES = {'admin', 'senior_analyst', 'analyst', 'readonly'}
    if not email or not password:
        return jsonify({'error': 'email and password are required'}), 400
    if len(password) < 12:
        return jsonify({'error': 'password must be at least 12 characters'}), 400
    if role not in _VALID_ROLES:
        return jsonify({'error': f"Invalid role '{role}'"}), 400

    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        db.close()
        return jsonify({'error': 'Email already registered'}), 409

    uid = str(uuid.uuid4())
    db.execute(
        "INSERT INTO users (id, email, name, password_hash, role, is_active) VALUES (?,?,?,?,?,1)",
        (uid, email, name, hash_password(password), role),
    )
    db.commit()
    db.close()
    return jsonify({"id": uid, "email": email, "role": role}), 201


@app.route('/api/auth/users/<uid>', methods=['PATCH'])
@require_min_role('admin')
def update_user(uid: str):
    data = request.get_json() or {}
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'User not found'}), 404

    if 'is_active' in data:
        db.execute("UPDATE users SET is_active=?, updated_at=datetime('now') WHERE id=?",
                   (1 if data['is_active'] else 0, uid))
    if 'role' in data:
        _VALID_ROLES = {'admin', 'senior_analyst', 'analyst', 'readonly'}
        if data['role'] not in _VALID_ROLES:
            db.close()
            return jsonify({'error': 'Invalid role'}), 400
        db.execute("UPDATE users SET role=?, updated_at=datetime('now') WHERE id=?",
                   (data['role'], uid))
    if 'password' in data:
        if len(data['password']) < 12:
            db.close()
            return jsonify({'error': 'password must be at least 12 characters'}), 400
        db.execute("UPDATE users SET password_hash=?, updated_at=datetime('now') WHERE id=?",
                   (hash_password(data['password']), uid))

    db.commit()
    db.close()
    return jsonify({"id": uid, "updated": True})


# ── Admin: ingest key management ──────────────────────────────────────────────

@app.route('/api/auth/ingest-keys', methods=['GET'])
@require_min_role('admin')
def list_ingest_keys():
    db = get_db()
    rows = db.execute(
        "SELECT id, name, is_active, created_at, last_used_at, revoked_at FROM ingest_keys ORDER BY created_at DESC"
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/auth/ingest-keys', methods=['POST'])
@require_min_role('admin')
def add_ingest_key():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    db = get_db()
    raw_key = create_ingest_key(db, name)
    db.commit()
    db.close()
    # Return the raw key ONCE — it is never stored and cannot be retrieved again
    return jsonify({"key": raw_key, "name": name,
                    "message": "Save this key — it will not be shown again."}), 201


@app.route('/api/auth/ingest-keys/<kid>', methods=['DELETE'])
@require_min_role('admin')
def revoke_ingest_key(kid: str):
    db = get_db()
    result = db.execute(
        "UPDATE ingest_keys SET is_active=0, revoked_at=datetime('now') WHERE id=?", (kid,)
    )
    db.commit()
    db.close()
    if result.rowcount == 0:
        return jsonify({'error': 'Key not found'}), 404
    return jsonify({"revoked": True})

# ============================================================
# WEBSOCKET
# ============================================================

@socketio.on('connect')
def ws_connect(auth=None):
    # Prefer Socket.IO's handshake auth so tokens are not placed in URLs.
    auth = auth or {}
    token = (auth.get('token') or '').strip()
    if not token:
        # Backward compatibility for existing agents; browser clients use auth.
        token = (request.args.get('token') or '').strip()
    if not token:
        return False
    db = get_db()
    user = get_session_user(db, token)
    db.commit()
    db.close()
    if user is None:
        return False
    emit('connected', {'status': 'connected'})

@socketio.on('ping')
def ws_ping():
    emit('pong')

# ============================================================
# STARTUP
# ============================================================

def startup():
    """Initialize database, bootstrap admin user, restore watermarks."""
    global _LIVE_CLEARED_AT
    init_db()
    db = get_db()
    _ensure_detection_rules(db)

    # Bootstrap initial admin account from env vars (no-op if users already exist)
    bootstrap_admin(db)

    # Purge old expired sessions on startup
    purge_expired_sessions(db)

    seed_database(db)

    # Restore live-clear watermark
    row = db.execute(
        "SELECT value FROM app_settings WHERE key='live_cleared_at'"
    ).fetchone()
    if row:
        try:
            _LIVE_CLEARED_AT = float(row[0])
        except ValueError:
            pass

    db.commit()
    db.close()

if __name__ == '__main__':
    print("🛡️  AI SOC Dashboard - Backend Starting...")
    print(f"📡 Server: http://localhost:{settings.PORT}")
    print(f"📖 API Health: http://localhost:{settings.PORT}/api/health")
    print(f"🔌 WebSocket: ws://localhost:{settings.PORT}/ws")
    settings.validate()   # surface insecure defaults before serving traffic
    startup()
    socketio.run(app, host=settings.HOST, port=settings.PORT, debug=settings.DEBUG, allow_unsafe_werkzeug=True)
