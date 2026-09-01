"""
Database Layer — SQLite with WAL mode and comprehensive indexing.
All JSON fields are stored as TEXT and parsed transparently by row_to_dict().
"""
import sqlite3
import json
import os
from datetime import datetime, timezone
from config import settings

DB_PATH = settings.DATABASE_PATH


def get_db() -> sqlite3.Connection:
    """Return a WAL-mode SQLite connection with Row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, faster than FULL
    conn.execute("PRAGMA cache_size=-32000")    # 32 MB page cache
    return conn


def _migrate_phase3(conn: sqlite3.Connection) -> None:
    """
    Safe, additive migrations for Phase 3 (MVP completion).
    Adds: alert FP classification, enhanced incident fields, correlation indexes.
    """
    c = conn.cursor()

    # ── alerts: false-positive classification fields ───────────────────────
    existing_alert_cols = {row[1] for row in c.execute("PRAGMA table_info(alerts)").fetchall()}
    for col, defn in [
        ("fp_classification",  "TEXT DEFAULT ''"),   # TRUE_POSITIVE / FALSE_POSITIVE / BENIGN / NEEDS_INVESTIGATION
        ("fp_classified_by",   "TEXT DEFAULT ''"),
        ("fp_classified_at",   "TEXT DEFAULT ''"),
        ("fp_reason",          "TEXT DEFAULT ''"),
    ]:
        if col not in existing_alert_cols:
            c.execute(f"ALTER TABLE alerts ADD COLUMN {col} {defn}")

    # ── incidents: enhanced fields ────────────────────────────────────────
    existing_inc_cols = {row[1] for row in c.execute("PRAGMA table_info(incidents)").fetchall()}
    for col, defn in [
        ("assigned_analyst",   "TEXT DEFAULT ''"),
        ("affected_hosts",     "TEXT DEFAULT '[]'"),  # JSON array
        ("affected_users",     "TEXT DEFAULT '[]'"),  # JSON array
        ("source_ips",         "TEXT DEFAULT '[]'"),  # JSON array
        ("notes",              "TEXT DEFAULT ''"),
        ("resolution",         "TEXT DEFAULT ''"),
        ("priority",           "TEXT DEFAULT 'medium'"),
    ]:
        if col not in existing_inc_cols:
            c.execute(f"ALTER TABLE incidents ADD COLUMN {col} {defn}")

    # ── incidents: status must support NEW→TRIAGED→INVESTIGATING→CONTAINED→RESOLVED ─
    # SQLite CHECK constraints can't be altered, but the existing set (open/investigating/
    # contained/remediated/closed) maps to the required flow. We add 'triaged' and
    # 'resolved' as aliases by rebuilding the table only if needed.
    row = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='incidents'").fetchone()
    if row and "'triaged'" not in (row[0] or '') and "'resolved'" not in (row[0] or ''):
        # Rebuild incidents table with expanded status CHECK
        c.execute("ALTER TABLE incidents RENAME TO incidents_legacy")
        c.execute("""
            CREATE TABLE incidents (
                id               TEXT PRIMARY KEY,
                title            TEXT NOT NULL,
                description      TEXT DEFAULT '',
                severity         TEXT DEFAULT 'medium',
                status           TEXT DEFAULT 'new'
                                     CHECK(status IN ('new','triaged','investigating','contained',
                                                      'resolved','open','remediated','closed')),
                alert_ids        TEXT DEFAULT '[]',
                ai_summary       TEXT DEFAULT '',
                timeline         TEXT DEFAULT '[]',
                assigned_to      TEXT DEFAULT '',
                assigned_analyst TEXT DEFAULT '',
                affected_hosts   TEXT DEFAULT '[]',
                affected_users   TEXT DEFAULT '[]',
                source_ips       TEXT DEFAULT '[]',
                notes            TEXT DEFAULT '',
                resolution       TEXT DEFAULT '',
                priority         TEXT DEFAULT 'medium',
                created_at       TEXT DEFAULT (datetime('now')),
                updated_at       TEXT DEFAULT (datetime('now'))
            )
        """)
        c.execute("""
            INSERT INTO incidents
            (id, title, description, severity, status, alert_ids, ai_summary,
             timeline, assigned_to, created_at, updated_at)
            SELECT id, title, description, severity, status, alert_ids, ai_summary,
                   timeline, assigned_to, created_at, updated_at
            FROM incidents_legacy
        """)
        c.execute("DROP TABLE incidents_legacy")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_status  ON incidents(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_created ON incidents(created_at DESC)")

    # ── Correlation indexes ───────────────────────────────────────────────
    c.execute("CREATE INDEX IF NOT EXISTS idx_alert_username ON alerts(username) WHERE username != ''")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alert_hostname ON alerts(hostname) WHERE hostname != ''")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alert_updated  ON alerts(updated_at DESC)")

    conn.commit()


def _migrate_phase2(conn: sqlite3.Connection) -> None:
    """
    Safe, additive migrations for Phase 2 (anomaly scoring + AI triage jobs).
    Uses ALTER TABLE ADD COLUMN which is a no-op when the column already exists
    in SQLite ≥ 3.37 — but we guard explicitly to support older SQLite versions.
    """
    c = conn.cursor()

    # ── log_entries: add anomaly columns ─────────────────────────────────
    existing_log_cols = {row[1] for row in c.execute("PRAGMA table_info(log_entries)").fetchall()}
    for col, defn in [
        ("anomaly_score",   "INTEGER DEFAULT 0"),
        ("anomaly_level",   "TEXT    DEFAULT 'normal'"),
        ("anomaly_reasons", "TEXT    DEFAULT '[]'"),
    ]:
        if col not in existing_log_cols:
            c.execute(f"ALTER TABLE log_entries ADD COLUMN {col} {defn}")

    # ── alerts: add ai_triage_status column ───────────────────────────────
    existing_alert_cols = {row[1] for row in c.execute("PRAGMA table_info(alerts)").fetchall()}
    if "ai_triage_status" not in existing_alert_cols:
        c.execute("ALTER TABLE alerts ADD COLUMN ai_triage_status TEXT DEFAULT 'pending'")

    # ── ai_jobs: persistent background job queue ─────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS ai_jobs (
            id           TEXT PRIMARY KEY,
            job_type     TEXT NOT NULL DEFAULT 'alert_triage',
            alert_id     TEXT,
            status       TEXT NOT NULL DEFAULT 'pending'
                             CHECK(status IN ('pending','running','completed','fallback','failed')),
            retry_count  INTEGER NOT NULL DEFAULT 0,
            max_retries  INTEGER NOT NULL DEFAULT 3,
            created_at   TEXT DEFAULT (datetime('now')),
            started_at   TEXT,
            completed_at TEXT,
            error_msg    TEXT DEFAULT '',
            next_retry_at TEXT,
            result       TEXT DEFAULT '{}'
        )
    """)
    existing_job_cols = {row[1] for row in c.execute("PRAGMA table_info(ai_jobs)").fetchall()}
    if "next_retry_at" not in existing_job_cols:
        c.execute("ALTER TABLE ai_jobs ADD COLUMN next_retry_at TEXT")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ai_jobs_status   ON ai_jobs(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ai_jobs_alert_id ON ai_jobs(alert_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ai_jobs_created  ON ai_jobs(created_at DESC)")

    # ── Indexes for new anomaly columns ──────────────────────────────────
    c.execute("CREATE INDEX IF NOT EXISTS idx_log_anomaly_score ON log_entries(anomaly_score DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_log_anomaly_level ON log_entries(anomaly_level)")

    conn.commit()


def _migrate_alert_status_constraint(conn: sqlite3.Connection) -> None:
    """Rebuild the legacy alerts table once to add the acknowledged status."""
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='alerts'"
    ).fetchone()
    if not row or "'acknowledged'" in (row[0] or ''):
        return

    indexes = [item[1] for item in conn.execute(
        "SELECT type, name FROM sqlite_master WHERE type='index' AND tbl_name='alerts'"
    ).fetchall() if not item[1].startswith('sqlite_autoindex_')]
    for index_name in indexes:
        conn.execute(f'DROP INDEX IF EXISTS "{index_name}"')
    conn.execute("ALTER TABLE alerts RENAME TO alerts_legacy")
    conn.commit()


def init_db() -> None:
    """Create all tables and indexes idempotently."""
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
        -- ─────────────────────────────────────────────────────────────────
        -- log_entries: every normalised event from every ingestion source
        -- ─────────────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS log_entries (
            id               TEXT PRIMARY KEY,
            timestamp        TEXT,                       -- ISO-8601 UTC
            source           TEXT NOT NULL DEFAULT 'unknown',
            source_type      TEXT NOT NULL DEFAULT 'unknown',
            event_type       TEXT NOT NULL DEFAULT 'general',
            event_id         TEXT DEFAULT '',
            severity         TEXT DEFAULT 'info'
                                 CHECK(severity IN ('critical','high','medium','low','info')),
            message          TEXT NOT NULL DEFAULT '',
            raw_log          TEXT DEFAULT '',
            source_ip        TEXT DEFAULT '',
            destination_ip   TEXT DEFAULT '',
            source_port      INTEGER,
            destination_port INTEGER,
            username         TEXT DEFAULT '',
            hostname         TEXT DEFAULT '',
            process_name     TEXT DEFAULT '',
            file_path        TEXT DEFAULT '',
            hash_sha256      TEXT DEFAULT '',
            geo_country      TEXT DEFAULT '',
            geo_city         TEXT DEFAULT '',
            geo_lat          REAL,
            geo_lon          REAL,
            tags             TEXT DEFAULT '[]',          -- JSON array
            upload_session_id TEXT DEFAULT '',
            created_at       TEXT DEFAULT (datetime('now'))
        );

        -- ─────────────────────────────────────────────────────────────────
        -- alerts: every triggered detection with evidence and AI analysis
        -- ─────────────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS alerts (
            id               TEXT PRIMARY KEY,
            timestamp        TEXT DEFAULT (datetime('now')),
            title            TEXT NOT NULL,
            description      TEXT DEFAULT '',
            severity         TEXT DEFAULT 'medium'
                                 CHECK(severity IN ('critical','high','medium','low','info')),
            status           TEXT DEFAULT 'new'
                                 CHECK(status IN ('new','acknowledged','investigating','resolved',
                                                  'false_positive','escalated')),
            rule_name        TEXT DEFAULT '',
            confidence       INTEGER DEFAULT 50,         -- 0-100
            threat_score     INTEGER DEFAULT 0,          -- 0-100
            source           TEXT DEFAULT '',
            source_ip        TEXT DEFAULT '',
            destination_ip   TEXT DEFAULT '',
            username         TEXT DEFAULT '',
            hostname         TEXT DEFAULT '',
            mitre_techniques TEXT DEFAULT '[]',          -- JSON array
            kill_chain_phase TEXT DEFAULT '',
            related_log_ids  TEXT DEFAULT '[]',          -- JSON array of log_entry IDs
            evidence         TEXT DEFAULT '{}',          -- JSON evidence map
            ai_analysis      TEXT DEFAULT '{}',          -- JSON AI output
            response_actions TEXT DEFAULT '[]',          -- JSON action history
            created_at       TEXT DEFAULT (datetime('now')),
            updated_at       TEXT DEFAULT (datetime('now'))
        );

        -- ─────────────────────────────────────────────────────────────────
        -- incidents: groupings of related alerts for case management
        -- ─────────────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS incidents (
            id          TEXT PRIMARY KEY,
            title       TEXT NOT NULL,
            description TEXT DEFAULT '',
            severity    TEXT DEFAULT 'medium',
            status      TEXT DEFAULT 'open'
                            CHECK(status IN ('open','investigating','contained',
                                             'remediated','closed')),
            alert_ids   TEXT DEFAULT '[]',   -- JSON array
            ai_summary  TEXT DEFAULT '',
            timeline    TEXT DEFAULT '[]',   -- JSON array of timeline events
            assigned_to TEXT DEFAULT '',
            created_at  TEXT DEFAULT (datetime('now')),
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        -- ─────────────────────────────────────────────────────────────────
        -- uploaded_files: metadata for every file upload session
        -- ─────────────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id                TEXT PRIMARY KEY,
            filename          TEXT NOT NULL,
            original_name     TEXT NOT NULL,
            file_type         TEXT DEFAULT '',
            file_size         INTEGER DEFAULT 0,
            log_format        TEXT DEFAULT '',
            status            TEXT DEFAULT 'pending'
                                  CHECK(status IN ('pending','processing','completed','error')),
            total_logs        INTEGER DEFAULT 0,
            parsed_logs       INTEGER DEFAULT 0,
            alerts_generated  INTEGER DEFAULT 0,
            analysis_results  TEXT DEFAULT '{}',
            upload_session_id TEXT DEFAULT '',
            created_at        TEXT DEFAULT (datetime('now'))
        );

        -- ─────────────────────────────────────────────────────────────────
        -- Indexes — covering the most common query patterns
        -- ─────────────────────────────────────────────────────────────────

        -- log_entries
        CREATE INDEX IF NOT EXISTS idx_log_severity   ON log_entries(severity);
        CREATE INDEX IF NOT EXISTS idx_log_source_type ON log_entries(source_type);
        CREATE INDEX IF NOT EXISTS idx_log_created    ON log_entries(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_log_timestamp  ON log_entries(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_log_source     ON log_entries(source);
        CREATE INDEX IF NOT EXISTS idx_log_upload     ON log_entries(upload_session_id)
                                                       WHERE upload_session_id != '';
        -- composite for deduplication query (event_id + timestamp + source)
        CREATE UNIQUE INDEX IF NOT EXISTS idx_log_dedup
            ON log_entries(event_id, timestamp, source)
            WHERE event_id != '' AND timestamp != '';

        -- alerts
        CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alert_status   ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alert_created  ON alerts(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_alert_rule     ON alerts(rule_name);
        CREATE INDEX IF NOT EXISTS idx_alert_source_ip ON alerts(source_ip)
                                                        WHERE source_ip != '';

        -- incidents
        CREATE INDEX IF NOT EXISTS idx_incident_status  ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_incident_created ON incidents(created_at DESC);

        -- ─────────────────────────────────────────────────────────────────
        -- users: production user accounts with hashed passwords
        -- ─────────────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS users (
            id           TEXT PRIMARY KEY,
            email        TEXT NOT NULL UNIQUE COLLATE NOCASE,
            name         TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            role         TEXT NOT NULL DEFAULT 'analyst'
                             CHECK(role IN ('admin','senior_analyst','analyst','readonly')),
            is_active    INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT DEFAULT (datetime('now')),
            updated_at   TEXT DEFAULT (datetime('now'))
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_user_email ON users(email COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_user_active ON users(is_active);

        -- ─────────────────────────────────────────────────────────────────
        -- sessions: DB-backed sessions; only the SHA-256 hash is stored
        -- ─────────────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS sessions (
            id           TEXT PRIMARY KEY,      -- SHA-256(token) hex
            user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at   TEXT DEFAULT (datetime('now')),
            expires_at   TEXT NOT NULL,
            last_used_at TEXT DEFAULT (datetime('now')),
            revoked_at   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_session_user   ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_session_expiry ON sessions(expires_at);

        -- ─────────────────────────────────────────────────────────────────
        -- ingest_keys: API keys for log forwarder agents
        -- ─────────────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS ingest_keys (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,           -- human label e.g. "windows-forwarder-01"
            key_hash    TEXT NOT NULL UNIQUE,    -- SHA-256(raw_key) hex; raw key never stored
            is_active   INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT DEFAULT (datetime('now')),
            last_used_at TEXT,
            revoked_at  TEXT
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_ingest_key_hash ON ingest_keys(key_hash);

        -- ─────────────────────────────────────────────────────────────────
        -- app_settings: persistent key-value pairs for runtime state
        -- ─────────────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alert_status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            previous_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            changed_by TEXT NOT NULL,
            changed_by_email TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_alert_status_history_alert ON alert_status_history(alert_id);
        CREATE INDEX IF NOT EXISTS idx_alert_status_history_created ON alert_status_history(created_at DESC);

        CREATE TRIGGER IF NOT EXISTS prevent_alert_status_history_update
        BEFORE UPDATE ON alert_status_history
        BEGIN
            SELECT RAISE(ABORT, 'alert status history is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS prevent_alert_status_history_delete
        BEFORE DELETE ON alert_status_history
        BEGIN
            SELECT RAISE(ABORT, 'alert status history is immutable');
        END;

        CREATE TABLE IF NOT EXISTS detection_rules (
            name TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            threshold INTEGER,
            time_window_seconds INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON detection_rules(enabled);
    """)

    conn.commit()

    # Phase-2 additive migrations (safe on fresh and existing databases)
    _migrate_alert_status_constraint(conn)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            timestamp TEXT DEFAULT (datetime('now')),
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            severity TEXT DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
            status TEXT DEFAULT 'new' CHECK(status IN ('new','acknowledged','investigating','resolved','false_positive','escalated')),
            rule_name TEXT DEFAULT '', confidence INTEGER DEFAULT 50, threat_score INTEGER DEFAULT 0,
            source TEXT DEFAULT '', source_ip TEXT DEFAULT '', destination_ip TEXT DEFAULT '', username TEXT DEFAULT '',
            hostname TEXT DEFAULT '', mitre_techniques TEXT DEFAULT '[]', kill_chain_phase TEXT DEFAULT '',
            related_log_ids TEXT DEFAULT '[]', evidence TEXT DEFAULT '{}', ai_analysis TEXT DEFAULT '{}',
            response_actions TEXT DEFAULT '[]', created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alerts_legacy'").fetchone():
        conn.execute(
            """INSERT INTO alerts
               (id, timestamp, title, description, severity, status, rule_name, confidence,
                threat_score, source, source_ip, destination_ip, username, hostname,
                mitre_techniques, kill_chain_phase, related_log_ids, evidence, ai_analysis,
                response_actions, created_at, updated_at)
               SELECT id, timestamp, title, description, severity, status, rule_name, confidence,
                threat_score, source, source_ip, destination_ip, username, hostname,
                mitre_techniques, kill_chain_phase, related_log_ids, evidence, ai_analysis,
                response_actions, created_at, updated_at FROM alerts_legacy"""
        )
        conn.execute("DROP TABLE alerts_legacy")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_created ON alerts(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_rule ON alerts(rule_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_source_ip ON alerts(source_ip) WHERE source_ip != ''")
    _migrate_phase2(conn)
    _migrate_phase3(conn)

    conn.close()
    print("✅ Database initialised — tables and indexes ready")


def row_to_dict(row) -> dict | None:
    """
    Convert a sqlite3.Row to a plain dict.
    JSON-encoded fields are decoded transparently.
    Returns None if row is None.
    """
    if row is None:
        return None
    d = dict(row)
    _JSON_FIELDS = {
        'tags', 'mitre_techniques', 'related_log_ids', 'ai_analysis',
        'response_actions', 'alert_ids', 'timeline', 'analysis_results', 'evidence',
        'incident_content', 'report_meta', 'anomaly_reasons', 'result',
        'affected_hosts', 'affected_users', 'source_ips',
    }
    for field in _JSON_FIELDS:
        if field in d and isinstance(d[field], str):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                d[field] = [] if field.endswith('s') or field.endswith('ids') else {}
    return d
