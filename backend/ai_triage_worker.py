"""
ai_triage_worker.py — Background AI triage job processor.

Design:
- Runs as a single daemon thread started at server startup via
  socketio.start_background_task() so it can emit WebSocket events.
- Polls ai_jobs WHERE status='pending' every POLL_INTERVAL seconds.
- Processes at most MAX_CONCURRENT jobs per poll cycle (default 3).
- Never blocks log ingestion — runs entirely in its own thread.
- Each job cycle opens and closes its own DB connection (WAL-safe).
- Jobs survive process restarts (persisted in SQLite).
- Bounded retries with exponential back-off (retry_count <= max_retries).
- On OpenAI failure → deterministic fallback triage (ai_engine._mock_analyze).
- Emits 'alert_triage_complete' WebSocket event so the UI updates in real time.

Triage result stored in alerts.ai_analysis and alerts.threat_score.
Job outcome stored in ai_jobs.status + ai_jobs.result.
"""
from __future__ import annotations

import json
import time
import traceback
import uuid
from datetime import datetime, timezone

import ai_engine
from database import get_db, row_to_dict

# ── Configuration ─────────────────────────────────────────────────────────────
POLL_INTERVAL     = 5    # seconds between poll cycles
MAX_CONCURRENT    = 3    # max jobs processed per poll cycle
MAX_RETRIES       = 3    # hard retry cap per job
RETRY_BACKOFF_SEC = [0, 30, 120]   # wait before retry[n]; retry_count 0 = immediate

_running = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def enqueue_triage_job(db, alert_id: str) -> str | None:
    """
    Insert a pending ai_jobs row for the given alert_id.
    Idempotent: if a non-failed job already exists for this alert, skip.
    Returns the job id if created, else None.
    """
    existing = db.execute(
        "SELECT id, status FROM ai_jobs WHERE alert_id=? AND status NOT IN ('failed') LIMIT 1",
        (alert_id,),
    ).fetchone()
    if existing:
        return None   # already queued or completed

    job_id = str(uuid.uuid4())
    db.execute(
        """INSERT INTO ai_jobs (id, job_type, alert_id, status, retry_count, max_retries)
           VALUES (?, 'alert_triage', ?, 'pending', 0, ?)""",
        (job_id, alert_id, MAX_RETRIES),
    )
    return job_id


def _process_job(job: dict, socketio) -> None:
    """Process one triage job — called from the worker thread."""
    job_id   = job["id"]
    alert_id = job["alert_id"]

    db = get_db()
    try:
        # Mark as running
        db.execute(
            "UPDATE ai_jobs SET status='running', started_at=?, next_retry_at=NULL WHERE id=?",
            (_now_iso(), job_id),
        )
        db.commit()

        # Load alert
        alert_row = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not alert_row:
            db.execute(
                "UPDATE ai_jobs SET status='failed', error_msg='Alert not found', completed_at=? WHERE id=?",
                (_now_iso(), job_id),
            )
            db.execute(
                "UPDATE alerts SET ai_triage_status='failed' WHERE id=?", (alert_id,)
            )
            db.commit()
            return

        alert = row_to_dict(alert_row)
        db.close()   # close BEFORE calling OpenAI (never hold connection during I/O)
        db = None

        # ── Run AI analysis (live or mock fallback) ──────────────────────
        used_fallback = False
        try:
            result = ai_engine.analyze_alert(alert)
            if not result.get("summary"):
                raise ValueError("Empty AI result")
        except Exception:
            result = ai_engine._mock_analyze(alert)
            used_fallback = True

        result_status = "fallback" if used_fallback else "completed"

        # ── Write results back to DB ──────────────────────────────────────
        db = get_db()
        db.execute(
            """UPDATE alerts
               SET ai_analysis=?, threat_score=?, ai_triage_status=?, updated_at=?
               WHERE id=?""",
            (
                json.dumps(result),
                result.get("threat_score", 50),
                result_status,
                _now_iso(),
                alert_id,
            ),
        )
        db.execute(
            """UPDATE ai_jobs
               SET status=?, completed_at=?, result=?
               WHERE id=?""",
            (
                result_status,
                _now_iso(),
                json.dumps({
                    "threat_score": result.get("threat_score"),
                    "summary":      str(result.get("summary", ""))[:200],
                    "attack_type":  result.get("attack_type", ""),
                    "fallback":     used_fallback,
                }),
                job_id,
            ),
        )
        db.commit()

        # ── Emit real-time update ─────────────────────────────────────────
        if socketio:
            socketio.emit("alert_triage_complete", {
                "alert_id":       alert_id,
                "triage_status":  result_status,
                "threat_score":   result.get("threat_score", 50),
                "summary":        str(result.get("summary", ""))[:200],
                "attack_type":    result.get("attack_type", ""),
                "fallback":       used_fallback,
            })

    except Exception as exc:
        err = traceback.format_exc()[:500]
        if db is None:
            db = get_db()
        retry_count = job.get("retry_count", 0) + 1
        if retry_count >= MAX_RETRIES:
            db.execute(
                "UPDATE ai_jobs SET status='failed', error_msg=?, completed_at=?, retry_count=? WHERE id=?",
                (err, _now_iso(), retry_count, job_id),
            )
            db.execute(
                "UPDATE alerts SET ai_triage_status='failed' WHERE id=?", (alert_id,)
            )
        else:
            # Schedule retry: set status back to 'pending' with incremented retry_count
            wait_secs = RETRY_BACKOFF_SEC[retry_count] if retry_count < len(RETRY_BACKOFF_SEC) else 120
            retry_after = datetime.now(timezone.utc).timestamp() + wait_secs
            retry_after_iso = datetime.fromtimestamp(retry_after, timezone.utc).isoformat()
            db.execute(
                "UPDATE ai_jobs SET status='pending', retry_count=?, error_msg=?, next_retry_at=? WHERE id=?",
                (retry_count, f"retry {retry_count}: {err[:200]}", retry_after_iso, job_id),
            )
        db.commit()
    finally:
        if db:
            db.close()


def run_worker(socketio) -> None:
    """
    Main worker loop. Called via socketio.start_background_task() at startup.
    Polls for pending jobs and processes them in bounded batches.
    """
    global _running
    _running = True

    while _running:
        try:
            db = get_db()
            pending = db.execute(
                """SELECT id, alert_id, retry_count, max_retries
                   FROM ai_jobs
                         WHERE status='pending'
                            AND (next_retry_at IS NULL OR next_retry_at <= ?)
                   ORDER BY created_at ASC
                   LIMIT ?""",
                     (_now_iso(), MAX_CONCURRENT),
            ).fetchall()
            db.close()

            for row in pending:
                job = dict(row)
                _process_job(job, socketio)

        except Exception:
            pass   # worker must never crash

        time.sleep(POLL_INTERVAL)


def stop_worker() -> None:
    """Signal the worker to stop (for clean shutdown / testing)."""
    global _running
    _running = False
