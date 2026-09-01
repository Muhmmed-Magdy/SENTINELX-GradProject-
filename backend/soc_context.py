"""
soc_context.py — Builds a bounded, sanitised SOC context dict from the DB.

Rules:
- All data comes from the DB; nothing is accepted from the browser as authoritative.
- Record counts are hard-bounded to prevent oversized prompts.
- Log messages and alert titles are treated as untrusted data (no instructions injected).
- Secrets (API keys, passwords, tokens) are never included.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Any


# ── Prompt-injection defence ──────────────────────────────────────────────────
# Strip sequences that look like system-prompt overrides embedded in log data.
_INJECTION_PATTERNS = [
    re.compile(r"(?i)(ignore\s+(previous|above|all)\s+instructions?)"),
    re.compile(r"(?i)(you\s+are\s+now\s+a\s+different)"),
    re.compile(r"(?i)(system\s*:\s*you\s+are)"),
    re.compile(r"(?i)(assistant\s*:\s*sure)"),
    re.compile(r"(?i)(disregard\s+(all\s+)?(prior|previous)\s+instructions?)"),
    re.compile(r"(?i)(<\s*/?system\s*>|<\s*/?prompt\s*>|<\s*/?instruction\s*>)"),
]

def _sanitize(text: str, max_len: int = 300) -> str:
    """Truncate and strip prompt-injection patterns from untrusted text."""
    if not isinstance(text, str):
        text = str(text) if text is not None else ""
    text = text[:max_len]
    for pat in _INJECTION_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


def _safe_alert(row: dict) -> dict:
    """Return a safe, bounded representation of one alert row."""
    return {
        "id": str(row.get("id", ""))[:40],
        "title": _sanitize(row.get("title", ""), 120),
        "severity": str(row.get("severity", ""))[:20],
        "status": str(row.get("status", ""))[:30],
        "rule_name": str(row.get("rule_name", ""))[:60],
        "source_ip": str(row.get("source_ip", ""))[:40],
        "hostname": _sanitize(row.get("hostname", ""), 60),
        "username": _sanitize(row.get("username", ""), 60),
        "mitre_techniques": (row.get("mitre_techniques") or [])[:5],
        "created_at": str(row.get("created_at", ""))[:30],
        "threat_score": int(row.get("threat_score") or 0),
    }


def _safe_log(row: dict) -> dict:
    """Return a safe, bounded representation of one log row."""
    return {
        "id": str(row.get("id", ""))[:40],
        "timestamp": str(row.get("timestamp", ""))[:30],
        "source_type": str(row.get("source_type", ""))[:30],
        "severity": str(row.get("severity", ""))[:20],
        "source_ip": str(row.get("source_ip", ""))[:40],
        "username": _sanitize(row.get("username", ""), 60),
        "hostname": _sanitize(row.get("hostname", ""), 60),
        "message": _sanitize(row.get("message", ""), 200),
    }


# ── Context limits ────────────────────────────────────────────────────────────
_MAX_ALERTS = 20
_MAX_LOGS = 15
_MAX_INCIDENTS = 10
_MAX_IPS = 10
_MAX_HOSTS = 10
_MAX_USERS = 10


def build_soc_context(
    db,
    *,
    hours: int = 24,
    data_source: str = "all",      # "all" | "live" | "uploaded"
    severity: str | None = None,
    source_type: str | None = None,
    include_logs: bool = True,
) -> dict[str, Any]:
    """
    Query the DB and return a bounded SOC context dict.

    Never includes passwords, tokens, or session data.
    All free-text fields are sanitised against prompt injection.
    """
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=max(1, min(hours, 168)))).isoformat()  # 1h–7d

    # ── Source filter ──────────────────────────────────────────────────────
    if data_source == "uploaded":
        log_where = "upload_session_id != '' AND upload_session_id IS NOT NULL"
    elif data_source == "live":
        log_where = "(upload_session_id = '' OR upload_session_id IS NULL)"
    else:
        log_where = "1=1"

    # Optional extra filters
    log_extra = ""
    log_params: list = []
    if severity:
        log_extra += " AND severity=?"
        log_params.append(severity)
    if source_type:
        log_extra += " AND source_type=?"
        log_params.append(source_type)

    # ── Alert severity counts (active) ────────────────────────────────────
    ACTIVE = "('new','acknowledged','investigating','escalated')"
    sev_counts: dict[str, int] = {}
    for s in ("critical", "high", "medium", "low", "info"):
        sev_counts[s] = db.execute(
            f"SELECT COUNT(*) FROM alerts WHERE severity=? AND status IN {ACTIVE}", (s,)
        ).fetchone()[0]

    total_active_alerts = sum(sev_counts.values())

    # ── Recent active alerts ──────────────────────────────────────────────
    alert_since_param = [since]
    alert_sev_clause = ""
    if severity:
        alert_sev_clause = " AND severity=?"
        alert_since_param.append(severity)

    raw_alerts = db.execute(
        f"""SELECT id, title, severity, status, rule_name, source_ip,
                   hostname, username, mitre_techniques, created_at, threat_score
            FROM alerts
            WHERE status IN {ACTIVE} AND created_at >= ?{alert_sev_clause}
            ORDER BY
              CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
              created_at DESC
            LIMIT ?""",
        (*alert_since_param, _MAX_ALERTS),
    ).fetchall()

    from database import row_to_dict
    recent_alerts = [_safe_alert(row_to_dict(r)) for r in raw_alerts]

    truncated_alerts = len(raw_alerts) == _MAX_ALERTS

    # ── Top attacking IPs ─────────────────────────────────────────────────
    top_ips = [
        {"ip": r[0], "count": r[1]}
        for r in db.execute(
            f"SELECT source_ip, COUNT(*) as cnt FROM alerts "
            f"WHERE source_ip != '' AND status IN {ACTIVE} "
            f"GROUP BY source_ip ORDER BY cnt DESC LIMIT ?",
            (_MAX_IPS,),
        ).fetchall()
    ]

    # ── Top hosts ─────────────────────────────────────────────────────────
    top_hosts = [
        {"host": _sanitize(r[0], 60), "count": r[1]}
        for r in db.execute(
            f"SELECT source, COUNT(*) as cnt FROM log_entries "
            f"WHERE {log_where} AND created_at >= ? "
            f"GROUP BY source ORDER BY cnt DESC LIMIT ?",
            (since, _MAX_HOSTS),
        ).fetchall()
    ]

    # ── Top users in alerts ───────────────────────────────────────────────
    top_users = [
        {"username": _sanitize(r[0], 60), "count": r[1]}
        for r in db.execute(
            f"SELECT username, COUNT(*) as cnt FROM alerts "
            f"WHERE username != '' AND status IN {ACTIVE} "
            f"GROUP BY username ORDER BY cnt DESC LIMIT ?",
            (_MAX_USERS,),
        ).fetchall()
    ]

    # ── MITRE technique frequency ─────────────────────────────────────────
    mitre_raw = db.execute(
        f"SELECT mitre_techniques FROM alerts WHERE status IN {ACTIVE} AND created_at >= ?",
        (since,),
    ).fetchall()
    mitre_counts: dict[str, int] = {}
    for row in mitre_raw:
        val = row[0]
        if isinstance(val, str):
            try:
                import json as _json
                techniques = _json.loads(val)
            except Exception:
                techniques = []
        else:
            techniques = val or []
        for t in techniques[:5]:
            t = str(t)[:20]
            mitre_counts[t] = mitre_counts.get(t, 0) + 1
    top_mitre = sorted(mitre_counts.items(), key=lambda x: -x[1])[:8]

    # ── Detection rules fired ─────────────────────────────────────────────
    top_rules = [
        {"rule": r[0], "count": r[1]}
        for r in db.execute(
            f"SELECT rule_name, COUNT(*) as cnt FROM alerts "
            f"WHERE rule_name != '' AND status IN {ACTIVE} AND created_at >= ? "
            f"GROUP BY rule_name ORDER BY cnt DESC LIMIT 10",
            (since,),
        ).fetchall()
    ]

    # ── Log stats ─────────────────────────────────────────────────────────
    total_logs = db.execute(
        f"SELECT COUNT(*) FROM log_entries WHERE {log_where}"
    ).fetchone()[0]

    recent_logs_count = db.execute(
        f"SELECT COUNT(*) FROM log_entries WHERE {log_where} AND created_at >= ?",
        (since,),
    ).fetchone()[0]

    # ── Recent log samples ────────────────────────────────────────────────
    recent_logs: list[dict] = []
    truncated_logs = False
    if include_logs:
        log_sample_params = [since] + log_params
        raw_logs = db.execute(
            f"""SELECT id, timestamp, source_type, severity, source_ip,
                       username, hostname, message
                FROM log_entries
                WHERE {log_where} AND created_at >= ?{log_extra}
                ORDER BY created_at DESC LIMIT ?""",
            (*log_sample_params, _MAX_LOGS),
        ).fetchall()
        recent_logs = [_safe_log(row_to_dict(r)) for r in raw_logs]
        truncated_logs = len(raw_logs) == _MAX_LOGS

    # ── Recent incidents ──────────────────────────────────────────────────
    raw_incidents = db.execute(
        """SELECT id, title, severity, status, created_at
           FROM incidents WHERE created_at >= ?
           ORDER BY created_at DESC LIMIT ?""",
        (since, _MAX_INCIDENTS),
    ).fetchall()
    recent_incidents = [
        {
            "id": str(r[0])[:40],
            "title": _sanitize(r[1] or "", 120),
            "severity": str(r[2] or "")[:20],
            "status": str(r[3] or "")[:30],
            "created_at": str(r[4] or "")[:30],
        }
        for r in raw_incidents
    ]

    return {
        "generated_at": now.isoformat(),
        "time_range_hours": hours,
        "since": since,
        "data_source": data_source,
        "alerts": {
            "total_active": total_active_alerts,
            "by_severity": sev_counts,
            "recent": recent_alerts,
            "truncated": truncated_alerts,
            "top_ips": top_ips,
            "top_users": top_users,
            "top_rules": top_rules,
            "top_mitre": [{"technique": t, "count": c} for t, c in top_mitre],
        },
        "logs": {
            "total": total_logs,
            "recent_count": recent_logs_count,
            "recent_samples": recent_logs,
            "truncated": truncated_logs,
        },
        "hosts": top_hosts,
        "incidents": {
            "recent": recent_incidents,
        },
        "filters_applied": {
            "severity": severity,
            "source_type": source_type,
        },
    }
