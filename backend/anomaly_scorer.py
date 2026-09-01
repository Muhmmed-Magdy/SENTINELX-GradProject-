"""
anomaly_scorer.py — Local, statistical anomaly scoring for log entries.

Design:
- Zero OpenAI calls; all logic is deterministic in-process.
- Scores run synchronously at ingest time; each score takes < 1 ms.
- Uses lightweight counters and heuristics; no ML libraries required.
- Scorer version 1 (bump SCORER_VERSION when logic changes).

Score bands:
    0–29   normal
    30–59  unusual
    60–79  suspicious
    80–100 highly_anomalous

Signals evaluated:
    • Log severity weight
    • Detection-rule match (rule_name present → alert already triggered)
    • Rare or new source IP
    • Rare or new user/host combination
    • Unusual login hour (outside 06:00–22:00 local time)
    • Unusual event frequency spike per source
    • High-risk event IDs (Windows: 4625, 4648, 4720, 7045, 4672, …)
    • Presence of suspicious message keywords
    • Message template rarity (normalized, stripped of IPs/UUIDs)

All signals are additive and capped at 100.  No single signal can exceed 50.
Reasons are human-readable strings explaining the score.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock
from typing import Any

SCORER_VERSION = "1"

# ── In-process frequency counters (reset on restart — intentional; stale
# data from a previous run would skew scores against historical baselines)
_lock = Lock()
_source_ip_counts: dict[str, int] = defaultdict(int)    # {ip: total_seen}
_user_host_pairs: dict[str, int]  = defaultdict(int)    # {"user@host": count}
_source_counts:   dict[str, int]  = defaultdict(int)    # {source: count}
_template_counts: dict[str, int]  = defaultdict(int)    # {msg_template_hash: count}
_hour_counts:     dict[str, int]  = defaultdict(int)    # {"source|hour": count}

# Windows event IDs known to be high-risk
_HIGH_RISK_EVENT_IDS = frozenset({
    "4625",   # failed logon
    "4648",   # logon with explicit credentials
    "4720",   # user account created
    "4728",   # member added to security-enabled global group
    "4732",   # member added to local group
    "4756",   # member added to universal group
    "4672",   # special privileges assigned
    "7045",   # new service installed
    "4698",   # scheduled task created
    "4702",   # scheduled task updated
    "1102",   # audit log cleared
    "4719",   # system audit policy changed
    "4771",   # Kerberos pre-auth failed
    "4776",   # NTLM auth failure
})

# Message keywords that are always suspicious
_SUSPICIOUS_KEYWORDS = [
    "mimikatz", "meterpreter", "invoke-expression", "iex", "downloadstring",
    "frombase64string", "encodedcommand", "bypass", "shellcode", "powershell -enc",
    "certutil -decode", "bitsadmin", "rundll32", "regsvr32", "mshta", "wscript",
    "cmd.exe /c", "net user /add", "net localgroup administrators",
    "whoami /priv", "whoami /all", "lsass.exe", "sekurlsa",
    "procdump", "ntdsutil", "shadow copy",
    "disable-windowsdefender", "set-mppreference",
]

# Severity weight map
_SEV_WEIGHT = {"critical": 50, "high": 35, "medium": 20, "low": 10, "info": 0}


def _normalize_message(msg: str) -> str:
    """Strip IPs, UUIDs, timestamps, port numbers → stable template for hashing."""
    msg = msg.lower()[:300]
    msg = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<ip>", msg)
    msg = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>", msg)
    msg = re.sub(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*\b", "<ts>", msg)
    msg = re.sub(r"\b\d{5,}\b", "<num>", msg)
    return msg


def score_log(log: dict[str, Any]) -> tuple[int, str, list[str]]:
    """
    Score one log entry.

    Returns:
        (score: int 0-100, level: str, reasons: list[str])

    This function is thread-safe; call it from the ingest loop without locking.
    """
    score = 0
    reasons: list[str] = []

    severity   = (log.get("severity") or "info").lower()
    source_ip  = (log.get("source_ip") or "").strip()
    username   = (log.get("username") or "").strip()
    hostname   = (log.get("hostname") or "").strip()
    source     = (log.get("source") or "").strip()
    event_id   = str(log.get("event_id") or "").strip()
    message    = str(log.get("message") or "")
    rule_name  = (log.get("rule_name") or "").strip()
    source_type = (log.get("source_type") or "").strip()

    # ── 1. Severity weight ────────────────────────────────────────────────
    sev_score = _SEV_WEIGHT.get(severity, 0)
    if sev_score > 0:
        score += sev_score
        reasons.append(f"Log severity is {severity} (+{sev_score})")

    # ── 2. Detection rule fired (rule_engine already matched) ────────────
    if rule_name:
        score += 20
        reasons.append(f"Detection rule matched: {rule_name} (+20)")

    # ── 3. High-risk Windows event ID ────────────────────────────────────
    if event_id in _HIGH_RISK_EVENT_IDS:
        score += 20
        reasons.append(f"High-risk event ID {event_id} (+20)")

    # ── 4. Suspicious message keywords ───────────────────────────────────
    msg_lower = message.lower()
    found_keywords = [k for k in _SUSPICIOUS_KEYWORDS if k in msg_lower]
    if found_keywords:
        kw_score = min(30, len(found_keywords) * 10)
        score += kw_score
        reasons.append(f"Suspicious keyword(s): {', '.join(found_keywords[:3])} (+{kw_score})")

    with _lock:
        # ── 5. New/rare source IP ─────────────────────────────────────────
        if source_ip and source_ip not in ("", "0.0.0.0"):
            prev_ip = _source_ip_counts[source_ip]
            _source_ip_counts[source_ip] += 1
            if prev_ip == 0:
                score += 15
                reasons.append(f"First-seen source IP {source_ip} (+15)")
            elif prev_ip < 5:
                score += 8
                reasons.append(f"Rare source IP {source_ip} (seen {prev_ip}x) (+8)")

        # ── 6. New/rare user@host pair ────────────────────────────────────
        if username and hostname:
            pair_key = f"{username}@{hostname}"
            prev_pair = _user_host_pairs[pair_key]
            _user_host_pairs[pair_key] += 1
            if prev_pair == 0:
                score += 10
                reasons.append(f"First-seen user-host pair {pair_key} (+10)")

        # ── 7. Message template rarity ────────────────────────────────────
        tmpl = _normalize_message(message)
        tmpl_hash = hashlib.md5(tmpl.encode(), usedforsecurity=False).hexdigest()[:8]
        prev_tmpl = _template_counts[tmpl_hash]
        _template_counts[tmpl_hash] += 1
        if prev_tmpl == 0 and len(tmpl) > 20:
            score += 8
            reasons.append(f"First-seen message template ({tmpl_hash}) (+8)")

        # ── 8. Unusual hour (outside 06:00–22:00) ────────────────────────
        ts_str = str(log.get("timestamp") or "")
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                hour = dt.hour
                hour_key = f"{source}|{hour}"
                prev_hour = _hour_counts[hour_key]
                _hour_counts[hour_key] += 1
                if not (6 <= hour <= 22) and prev_hour == 0:
                    score += 12
                    reasons.append(f"Activity at unusual hour {hour:02d}:xx (+12)")
                elif not (6 <= hour <= 22):
                    score += 5
                    reasons.append(f"Activity at unusual hour {hour:02d}:xx (+5)")
            except ValueError:
                pass

    # ── Cap at 100 ────────────────────────────────────────────────────────
    score = min(100, max(0, score))

    # ── Determine level ───────────────────────────────────────────────────
    if score >= 80:
        level = "highly_anomalous"
    elif score >= 60:
        level = "suspicious"
    elif score >= 30:
        level = "unusual"
    else:
        level = "normal"

    return score, level, reasons[:6]  # cap reasons at 6 for readability


def reset_counters() -> None:
    """Reset in-process counters. Called by tests to ensure isolation."""
    with _lock:
        _source_ip_counts.clear()
        _user_host_pairs.clear()
        _source_counts.clear()
        _template_counts.clear()
        _hour_counts.clear()
