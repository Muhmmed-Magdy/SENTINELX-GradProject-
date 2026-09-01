# AI SOC Dashboard — Project Analysis Report

**Prepared by:** Senior Software Architect & Product Manager Review  
**Date:** August 2026  
**Codebase inspected:** `c:\Users\USER\OneDrive\Desktop\ai-soc-dashboard`  
**Method:** Full source inspection — all Python, TypeScript, shell scripts, config, tests, and environment files read directly. No guessing or inference from README alone.

---

## 1. Project Overview

### Purpose

The AI SOC Dashboard is a full-stack Security Operations Center (SOC) monitoring platform that collects, stores, analyzes, and visualizes security events from multiple machines in real time. It is designed to give a security analyst a single pane of glass across Windows, Linux, and firewall log sources — with automated threat detection and AI-assisted triage.

### Target Users

- **Security Operations Center (SOC) analysts** — primary users who triage alerts, investigate incidents, and respond to threats
- **IT administrators** — secondary users who monitor system health and suspicious activity
- **Security students / learners** — the demo mode and seed data make it usable for hands-on cybersecurity learning

### Problem It Solves

Without this tool, a small SOC would need separate tools for log collection, a SIEM for correlation, and manual ticket management. This project consolidates all of that into a single local dashboard: log collection agents (PowerShell + shell scripts), a detection engine, AI-assisted analysis, and a case management UI.

### Typical User Workflow

1. **Collect** — Windows forwarder (Task Scheduler) and Linux/firewall systemd service send events to `/api/logs/ingest` every 5 seconds
2. **Detect** — Backend rule engine evaluates every incoming log against 13 detection rules, generates alerts with MITRE ATT&CK mappings
3. **Triage** — Analyst opens the Dashboard to see severity counts and recent alerts; clicks into an alert for AI analysis and investigation context
4. **Respond** — Analyst marks alerts as Investigating / Resolved / False Positive / Escalated; groups related alerts into an Incident
5. **Investigate** — Uses Log Explorer to search raw logs; AI Copilot for natural language queries
6. **Review** — Settings page shows rule list, AI status, and data management options

---

## 2. Technology and Architecture

### Stack

| Layer | Technology | Version | File Evidence |
|---|---|---|---|
| Frontend framework | React | 18.2 | `package.json` |
| Frontend language | TypeScript | 5.3 | `tsconfig.json` |
| Build tool | Vite | 5.0 | `vite.config.ts` |
| Styling | Tailwind CSS | 3.4 | `tailwind.config.js` |
| State management | Zustand | 4.4 | `store/useStore.ts` |
| HTTP client | Axios | 1.6 | `services/api.ts` |
| Charts | Recharts | 2.10 | `pages/Dashboard.tsx` |
| Real-time | Socket.IO client | 4.7 | `pages/LiveIngestion.tsx` |
| Routing | React Router | 6.20 | `App.tsx` |
| Backend framework | Flask | 3.1.1 | `requirements.txt` |
| WebSocket server | Flask-SocketIO | 5.5.1 | `run.py` |
| Database | SQLite (WAL mode) | built-in | `database.py` |
| AI provider | OpenAI (optional) | latest | `ai_engine.py` |
| Encoding detection | chardet | 5.2 | `run.py` |
| Config/env loading | python-dotenv | 1.0.1 | `config.py` |
| Test runner | pytest | 9.x | `pytest.ini` |

### Folder Structure

```
ai-soc-dashboard/
├── backend/
│   ├── run.py                  ← Flask app + all API routes (entry point)
│   ├── config.py               ← Settings class, env var loading
│   ├── database.py             ← SQLite schema, get_db(), row_to_dict()
│   ├── log_ingestion.py        ← 7-format log parser (LogIngestionService)
│   ├── rule_engine.py          ← 13 detection rules, sliding-window counters
│   ├── ai_engine.py            ← OpenAI integration + mock fallback
│   ├── seed_data.py            ← Demo data generator (disabled by default)
│   ├── soc_dashboard.db        ← SQLite database file
│   ├── pytest.ini              ← Test configuration
│   ├── requirements.txt
│   ├── tests/
│   │   ├── conftest.py         ← Isolated DB fixture, factory helpers
│   │   ├── test_detection_reporting.py  (46 tests)
│   │   ├── test_log_ingestion.py        (45 tests)
│   │   └── test_security.py             (57 tests)
│   └── scripts/                ← Operational utility scripts
│
├── frontend/
│   └── src/
│       ├── App.tsx             ← Root, auth guard, routing
│       ├── pages/              ← 9 page components
│       ├── components/layout/  ← DashboardLayout, Sidebar, TopBar
│       ├── services/api.ts     ← Axios client with auth interceptors
│       ├── store/useStore.ts   ← Zustand state
│       └── types/index.ts      ← Shared TypeScript interfaces
│
├── windows-log-forwarder.ps1   ← PowerShell event log collector
├── linux-log-forwarder.sh      ← Linux journald/file collector
├── firewall-log-forwarder.sh   ← Firewall log collector + syslog listener
├── START-SOC-FORWARDER.bat     ← UAC-elevated launcher for Windows forwarder
└── setup.bat / setup.sh        ← One-time dependency installer
```

### Communication Flow

```
Windows (Task Scheduler)          Linux VM (systemd)         Firewall (syslog/iptables)
       |                                 |                              |
       └──────────────── POST /api/logs/ingest ───────────────────────┘
                                         |
                              Flask backend (port 8001)
                              ├── rule_engine.evaluate_log()
                              ├── ai_engine.analyze_alert()
                              ├── SQLite (WAL mode)
                              └── Socket.IO emit → browser
                                         |
                              React frontend (port 5173)
                              ├── Vite dev proxy → /api/* → :8001
                              ├── Socket.IO client (live feed)
                              └── Axios REST calls (polling every 10-15s)
```

### Entry Points

- **Backend:** `backend/run.py` — `if __name__ == '__main__': startup(); socketio.run(...)`
- **Frontend:** `frontend/src/main.tsx` → `App.tsx`
- **Log collection (Windows):** `windows-log-forwarder.ps1` / `START-SOC-FORWARDER.bat`
- **Log collection (Linux):** `/usr/local/bin/soc-forwarder.sh` via systemd
- **Authentication:** `POST /api/auth/login` → session token stored in `localStorage`

---

## 3. Existing Features

### Authentication & Session Management
**Status: Complete**
- `POST /api/auth/login` — validates against `DEMO_USERS` dict, issues `secrets.token_urlsafe(32)` session token
- `GET /api/auth/me` — returns current user from in-memory `_SESSION_TOKENS`
- 24-hour session TTL with automatic expiry on `_expire_sessions()`
- Rate limiting: 10 attempts per IP per 5 minutes → 429
- Frontend: `App.tsx` validates token via `api.auth.me()` on load; `TopBar.tsx` profile dropdown with logout
- Evidence: `run.py` lines 36–95, `Login.tsx`, `TopBar.tsx`

### Dashboard Overview
**Status: Complete**
- Live/Uploaded toggle — two separate data views
- Severity stat cards (Critical, High, Medium, Low, Total Alerts, Total Logs)
- Executive summary + AI threat assessment score (0–100 gauge)
- Log sources pie chart, Top attacking IPs bar, Top active hosts chart
- Recent Alerts feed and Recent Log stream
- 15-second auto-refresh + manual Refresh button
- Responds immediately to `soc:alert-updated` custom event from Alerts page
- Evidence: `Dashboard.tsx`, `GET /api/dashboard/stats`, `GET /api/ai/threat-assessment`

### Security Alerts
**Status: Complete**
- Alert list with severity filter buttons (All/Critical/High/Medium/Low) and free-text search
- Click-to-expand detail panel: rule name, source IP, username, hostname, MITRE techniques
- Detection evidence viewer (raw key/value from rule engine)
- AI Analysis panel: summary, attack type, confidence, false-positive likelihood, recommended actions
- Investigation Context: related logs, related alerts by same IP/user/host, next-step recommendations
- Response actions: Investigating, Resolve, False Positive, Escalate
- Resolve/False Positive → alert vanishes immediately (optimistic UI + `updated_at` backdated 31 min)
- `soc:alert-updated` event dispatched to refresh Dashboard and bell count instantly
- Evidence: `Alerts.tsx`, `PATCH /api/alerts/<id>/status`, `GET /api/alerts/<id>/investigation-context`

### Detection Rule Engine
**Status: Complete — 13 rules**

| Rule | Trigger | MITRE |
|---|---|---|
| BRUTE_FORCE_LOGIN | 3 failures / 5 min, same IP+user | T1110 |
| PASSWORD_SPRAYING | 3 failures / 5 min, ≥2 accounts | T1110.003 |
| PRIVILEGE_ESCALATION | Event IDs 4728/4732/4756/4720, usermod/groupadd | T1078, T1068 |
| SUSPICIOUS_POWERSHELL | Encoded commands, download cradles, Mimikatz | T1059.001, T1027 |
| DATA_EXFILTRATION | Keyword match | T1048 |
| LATERAL_MOVEMENT | RDP logon type 10, external network logon, lateral tools | T1021, T1570 |
| MALWARE_DETECTED | AV/EDR threat-detected keywords | T1204, T1059 |
| UNUSUAL_LOGIN_TIME | Successful logon 23:00–06:00 | T1078 |
| SERVICE_INSTALLATION | Event ID 7045, excludes known-safe paths | T1543.003 |
| FIREWALL_ANOMALY | Firewall rule change keywords | T1562.004 |
| DNS_TUNNELING | Large DNS + high Shannon entropy, keywords | T1071.004 |
| ACCOUNT_LOCKOUT | Event ID 4740 | T1110.003 |
| SCHEDULED_TASK_CREATED | Event IDs 4698/4702, excludes Microsoft tasks | T1053.005 |

- Sliding-window counters in memory (reset on restart)
- Confidence scales with failure count (brute force: 85→95)
- Own-tool suppression (forwarder scripts never trigger alerts)
- Evidence: `rule_engine.py`

### Log Explorer
**Status: Complete**
- Full-text search across message, source, source_ip, username
- Filters: source type, severity, uploaded-only toggle
- Pagination (limit/offset, server-enforced max 1000)
- CSV export of current result set
- Sources summary chips
- Event type colored pill (windows=blue, linux=orange, firewall=red)
- Evidence: `LogExplorer.tsx`, `GET /api/logs`

### Live Ingestion View
**Status: Complete**
- Socket.IO real-time log stream (500-event rolling buffer)
- Pause/Resume and Clear controls
- Detected alerts panel (collapsible)
- Severity stat counters (auto-refresh every 15s)
- Ingestion endpoint display with copy button
- Winlogbeat config snippet with copy button
- Evidence: `LiveIngestion.tsx`, Socket.IO `new_log` / `new_alert` events

### File Upload & Analysis
**Status: Complete**
- Drag-and-drop or click-to-browse upload
- 7 format options with auto-detect
- File extension allowlist (`.log .txt .xml .json .ndjson .csv`)
- Results: log count, alert count, severity breakdown
- Inline log viewer with CSV export
- Upload history with per-file delete (cascades to logs and alerts)
- Confirm-before-delete modal
- Evidence: `FileUpload.tsx`, `POST /api/upload/file`, `DELETE /api/upload/<id>`

### AI Copilot Chat
**Status: Complete (with graceful mock fallback)**
- Chat UI with message history, typing indicator
- OpenAI `gpt-4o-mini` when `OPENAI_API_KEY` is set
- Mock responses for 7 query patterns when no key
- Quick-question sidebar
- AI status banner (shows model, health, quota errors)
- Evidence: `AICopilot.tsx`, `POST /api/ai/chat`, `ai_engine._mock_chat()`

### Incident Management
**Status: Partial**
- List and create incidents with title, description, severity
- Status update (open → investigating → contained → remediated → closed)
- View incident with linked alerts
- **Missing:** Cannot link existing alerts to an incident from the UI; `alert_ids` field exists in DB but no route or UI to populate it. `ai_summary` and `timeline` fields exist in DB but are never populated.
- Evidence: `Incidents.tsx`, `POST /api/incidents`, `database.py` incidents table

### Settings & Configuration
**Status: Complete**
- AI Engine status (live/mock, model name, connectivity health)
- Detection rules viewer (all 13 rules with MITRE mappings)
- System information panel
- **Data Management:** Clear live logs button with two-step confirmation; success/error feedback
- Evidence: `Settings.tsx`, `DELETE /api/data/live-logs`

### Multi-Source Log Collection
**Status: Complete (3 of 5 source types active)**

| Source | Forwarder | Auto-start | Status |
|---|---|---|---|
| Windows Event Log | `windows-log-forwarder.ps1` | Task Scheduler | ✅ Active |
| Linux (journald) | `linux-log-forwarder.sh` / `soc-forwarder.sh` | systemd service | ✅ Active |
| Firewall (iptables/syslog) | `soc-forwarder.sh` (combined) | systemd service | ✅ Active |
| IDS/NIDS | None | — | ❌ Not implemented |
| Network flow | None | — | ❌ Not implemented |

### WebSocket Real-Time Updates
**Status: Complete**
- Socket.IO server with token-based authentication (unauthenticated connections rejected)
- Events: `new_log`, `new_alert`, `alert_update`, `connected`, `pong`
- DashboardLayout maintains persistent connection, updates bell badge on `new_alert`
- Evidence: `run.py` WebSocket section, `DashboardLayout.tsx`

### Log Ingestion Pipeline
**Status: Complete**
- `POST /api/logs/ingest` (no auth — design decision for background agents)
- Payload size cap: 2 MB (enforced in `enforce_payload_limits` before_request)
- Watermark filter: rejects logs older than last "Clear" operation (persisted to `app_settings` table)
- Deduplication: unique index on `(event_id, timestamp, source)`
- Field sanitization: all fields coerced to string, max 500 chars
- Evidence: `run.py` `ingest_logs()`, `database.py` `idx_log_dedup`

---

## 4. Setup and Usage

### Prerequisites

| Requirement | Minimum | Check |
|---|---|---|
| Python | 3.9 | `python --version` |
| Node.js | 18 | `node --version` |
| npm | 9 | `npm --version` |

### Installation

**Windows:**
```bat
setup.bat
```
**Linux/macOS:**
```bash
chmod +x setup.sh && ./setup.sh
```
Both scripts: install Python packages, copy `.env.example` → `.env`, run `npm install`.

### Running Locally

```bash
# Terminal 1 — Backend
cd backend
python run.py
# Listening on http://localhost:8001

# Terminal 2 — Frontend
cd frontend
npm run dev
# Listening on http://localhost:5173
```

### Environment Variables

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `OPENAI_API_KEY` | *(empty)* | No | Live AI analysis; omit for mock mode |
| `OPENAI_MODEL` | `gpt-4o-mini` | No | OpenAI model name |
| `SECRET_KEY` | insecure default | **Yes for prod** | Session token signing |
| `FLASK_DEBUG` | `false` | No | Auto-reload in development |
| `FLASK_HOST` | `0.0.0.0` | No | Bind address |
| `PORT` | `8001` | No | Backend port |
| `CORS_ORIGINS` | localhost origins | **Yes for prod** | Allowed frontend origins |
| `MAX_UPLOAD_SIZE` | 52428800 (50 MB) | No | Max file upload |
| `MAX_INGEST_PAYLOAD_SIZE` | 2097152 (2 MB) | No | Max ingest body |
| `UPLOAD_DIR` | `backend/uploads/` | No | File upload directory |

### Demo Accounts

| Email | Password | Role |
|---|---|---|
| admin@soc.local | admin123 | Admin |
| analyst@soc.local | analyst123 | Senior Analyst |
| junior@soc.local | junior123 | Analyst |

### Running Tests

```bash
cd backend
python -m pytest
# 148 tests, ~7 seconds
```

### Windows Log Collection

```bat
START-SOC-FORWARDER.bat   # one-time manual start (UAC prompt)
```
Or auto-start via Task Scheduler (registered during session setup).

### Linux Log Collection

```bash
sudo SOC_URL=http://YOUR_WINDOWS_IP:8001/api/logs/ingest ./linux-log-forwarder.sh
# Or via systemd: sudo systemctl start soc-forwarder
```

### Things That May Prevent the Project from Running

1. **Port 8001 not open on Windows firewall** — Linux forwarder cannot POST to dashboard (fix: `netsh advfirewall firewall add rule name="SOC" dir=in action=allow protocol=TCP localport=8001`)
2. **VirtualBox network mode = NAT** — VM cannot reach host IP; must use Bridged Adapter
3. **Backend not restarted after code changes** — in-memory state (`_LIVE_CLEARED_AT`, session tokens, rule counters) won't update
4. **`openai` package not installed** — AI features silently fall back to mock; add `openai` to `requirements.txt` if live AI is needed
5. **Default `SECRET_KEY`** — startup warning printed; sessions still work but insecure in production

---

## 5. Current Problems and Gaps

### Critical

| # | Problem | Evidence | Impact |
|---|---|---|---|
| C1 | **Passwords stored in plaintext in source code** — `DEMO_USERS` dict in `run.py` has hardcoded credentials. No hashing. Anyone with repo access knows all credentials. | `run.py` `DEMO_USERS` | Auth bypass if repo is shared |
| C2 | **Session tokens stored only in memory** — `_SESSION_TOKENS` dict resets on every backend restart, logging out all users silently | `run.py` `_SESSION_TOKENS` | All sessions lost on restart |
| C3 | **No role-based access control** — all authenticated users have identical access to all data and destructive operations (Clear All Logs, Delete upload) | `require_auth` decorator, `Settings.tsx` | Any analyst can wipe data |

### High

| # | Problem | Evidence | Impact |
|---|---|---|---|
| H1 | **Rule counters reset on backend restart** — brute force sliding windows are in-memory; restarting the backend resets all in-progress attack detection | `rule_engine.py` `_FAILED_LOGINS` | Missed alerts post-restart |
| H2 | **Incident ↔ Alert linking not implemented** — `alert_ids` column exists, `ai_summary` and `timeline` columns exist, but no UI or route to populate them | `Incidents.tsx`, `database.py` | Incident management is incomplete |
| H3 | **`openai` package missing from `requirements.txt`** — AI works only if manually installed; setup scripts won't install it | `requirements.txt` | AI silently uses mock after fresh install |
| H4 | **Kali forwarder service stops unexpectedly** — observed in production; `journalctl` pipe breaks when journal rotates or system is idle | `soc-forwarder.sh` | Linux/firewall logs silently stop |
| H5 | **No user management UI** — cannot add, remove, or change passwords for dashboard users without editing source code | `run.py` `DEMO_USERS` | Operational limitation |

### Medium

| # | Problem | Evidence | Impact |
|---|---|---|---|
| M1 | **CORS allows all origins for Socket.IO** — `SocketIO(app, cors_allowed_origins="*")` while REST CORS is restricted | `run.py` line 32 | WebSocket open to any origin |
| M2 | **No pagination on incidents, upload history** — both endpoints have hard `LIMIT 50` with no offset parameter | `GET /api/incidents`, `GET /api/upload/history` | Lists truncate silently |
| M3 | **Alert noise from event 4100 (PowerShell warnings)** — partially filtered but 4100 is still the top event ID (678 entries) | `check_sources.py` output | Inflated log counts, storage waste |
| M4 | **`_safe_int` not applied to upload pagination** — `GET /api/upload/<id>/logs` uses `int(request.args.get(...))` without try/except | `run.py` `uploaded_logs()` | 500 error on non-integer input |
| M5 | **No timestamp on alert status changes** — response_actions tracks timestamps but status changes via `PATCH` do not record who changed it or when (only `updated_at`) | `run.py` `update_alert_status` | No audit trail |
| M6 | **`hashlib` and `date-fns` imported but unused** — `hashlib` imported in `run.py` but never called; `date-fns` in `package.json` but no component uses it | `run.py` imports, `package.json` | Dead code / unnecessary dependency |

### Low

| # | Problem | Evidence | Impact |
|---|---|---|---|
| L1 | **`DashboardLayout` sidebar margin hardcoded** — `ml-64` in CSS doesn't animate with collapse | `DashboardLayout.tsx` style | Minor UI jitter on collapse |
| L2 | **`seed_data.py` generates data but `seed_database()` is disabled** — function exists and is well-implemented but always skips | `seed_data.py` `seed_database()` | Demo mode non-functional |
| L3 | **Geo fields (lat/lon/country/city) in schema but never populated** — columns exist, forwarders don't collect them | `database.py` `log_entries` table | Unused schema weight |
| L4 | **No loading skeleton on initial dashboard** — blank cards flash during first load | `Dashboard.tsx` | Minor UX |
| L5 | **Scripts directory has debug/test files committed** — `check_ai.py`, `test_openai.py` etc. are dev artifacts | `backend/scripts/` | Clutter |

---

## 6. Features I Can Add

### a. Quick Wins (1–4 hours each)

| Feature | Value | Difficulty | Files to Change |
|---|---|---|---|
| **Add `openai` to requirements.txt** | Unblocks live AI after fresh install | Trivial | `requirements.txt` |
| **Hash demo passwords with bcrypt/hashlib** | Removes plaintext credentials from source | Easy | `run.py` `DEMO_USERS`, add `bcrypt` to deps |
| **Alert export to CSV/JSON** | Analysts can share or archive alert lists | Easy | `Alerts.tsx` (add export button), no backend change |
| **Bell dropdown links to alert detail** | Clicking a notification goes directly to the alert | Easy | `TopBar.tsx` |
| **Persist rule counters to DB** | Brute-force detection survives backend restart | Medium | `rule_engine.py`, `database.py` (new table) |
| **Fix CORS wildcard on Socket.IO** | Closes security gap | Easy | `run.py` line 32 |
| **Apply `_safe_int` to all pagination** | Prevent 500 errors on bad query params | Easy | `run.py` `uploaded_logs()`, 2 other endpoints |

### b. Medium-Sized Improvements (1–3 days each)

| Feature | Value | Difficulty | Dependencies | Files |
|---|---|---|---|---|
| **Alert → Incident linking UI** | Complete the incident management workflow | Medium | Existing DB schema ready | `Incidents.tsx`, `Alerts.tsx`, `run.py` `update_incident` |
| **User management page** | Add/remove/change-password without editing code | Medium | Needs user table in DB | `run.py`, `database.py`, new `Users.tsx` |
| **Persistent session storage** | Sessions survive backend restart | Medium | Needs DB table or Redis | `run.py` session functions, `database.py` |
| **Alert timeline view** | Chronological view of all events in an incident | Medium | `timeline` column exists in DB | `Incidents.tsx`, `run.py` |
| **Email/webhook notifications** | Alert on critical alerts without watching the UI | Medium | SMTP or webhook config | New `notifications.py`, `config.py`, `Settings.tsx` |
| **GeoIP enrichment** | Populate country/city on ingest for map visualization | Medium | Needs `geoip2` or IP-API | `run.py` `ingest_logs()`, `database.py` |
| **Search result highlighting** | Highlight search terms in log messages | Easy-Medium | Frontend only | `LogExplorer.tsx` |
| **Alert acknowledge/assign to analyst** | Track who is investigating what | Medium | `assigned_to` field needed in alerts | `run.py`, `Alerts.tsx`, `database.py` |

### c. Major / Advanced Features (1–2 weeks each)

| Feature | Value | Difficulty | Dependencies | Files |
|---|---|---|---|---|
| **Interactive world map** | Visual attack origin map using GeoIP data | High | GeoIP enrichment must be done first, `react-leaflet` | New `MapView.tsx`, `Dashboard.tsx` |
| **Threat intelligence integration** | Check IPs/hashes against AbuseIPDB, VirusTotal | High | External API keys, rate limiting | New `threat_intel.py`, `run.py` ingest pipeline |
| **Automated incident response playbooks** | Pre-defined response steps that auto-execute (block IP via firewall rule, disable account) | Very High | Firewall API access, AD/LDAP integration | New `playbooks.py`, `Incidents.tsx` |
| **Machine learning anomaly detection** | Baseline normal behavior, alert on deviations | Very High | `scikit-learn`, historical data, training pipeline | New `ml_engine.py`, replaces some rule engine logic |
| **Multi-user role-based access** | Admin, Analyst, Read-only roles with enforced permissions | High | Proper user table, JWT, RBAC middleware | `run.py`, `database.py`, all pages |
| **SIEM integration export** | Send alerts to Splunk/Elastic/QRadar via API | High | External SIEM access | New `siem_exporter.py`, `Settings.tsx` |
| **PDF report generation** | Generate executive PDF reports from alerts | Medium | `reportlab` or `weasyprint` | New `reports.py`, `Settings.tsx` |

---

## 7. Recommended Roadmap

### Phase 1 — Immediate Fixes (This week)

These must be done before showing the project to anyone or using it in any real environment.

1. **Hash passwords** — Replace plaintext `DEMO_USERS` passwords with bcrypt hashes. ~30 mins. `run.py`.
2. **Fix CORS wildcard on Socket.IO** — Change `cors_allowed_origins="*"` to `settings.CORS_ORIGINS`. ~5 mins. `run.py`.
3. **Add `openai` to `requirements.txt`** — So fresh installs get live AI. ~2 mins.
4. **Apply `_safe_int` everywhere** — Prevent 500 on bad pagination params. ~30 mins. `run.py`.
5. **Persist session tokens to DB** — So backend restarts don't log everyone out. ~2 hours. `run.py`, `database.py`.

### Phase 2 — Core Completions (Next 2 weeks)

Complete the features that are partially built.

6. **Incident ↔ Alert linking** — Add UI to link alerts to incidents and view the full incident timeline. The DB schema is already complete; only the routes and UI are missing.
7. **Persist rule engine counters** — Write brute-force sliding windows to an `app_settings` or dedicated table so detection survives restarts.
8. **Forwarder reliability** — Make the Linux `soc-forwarder.sh` reconnect cleanly when journald pipe breaks; add watchdog.
9. **User management page** — Basic admin UI to add/change/remove users without editing source code.

### Phase 3 — Enrichment & Visibility (Month 2)

10. **GeoIP enrichment on ingest** — Add country/city to every log entry with external IP; enables map visualization.
11. **World map dashboard widget** — Visual attack origin map.
12. **Email/webhook alerts** — Critical alert → immediate notification without watching the UI.
13. **Alert assignment** — Analyst can claim and be assigned alerts; reduces duplicate work in a team.

### Phase 4 — Advanced (Month 3+)

14. **Threat intelligence lookups** — Auto-check attacker IPs against AbuseIPDB on alert generation.
15. **PDF report export** — Executive summary as downloadable PDF.
16. **Multi-tenant RBAC** — Proper role enforcement (admin vs analyst vs read-only).
17. **ML anomaly baseline** — Replace keyword-matching rules with behavioral baselines for login patterns.

### Best Three Tasks to Start With Right Now

| Priority | Task | Why | Time |
|---|---|---|---|
| 1 | Hash demo passwords | Security hygiene before any sharing | 30 min |
| 2 | Persist session tokens to DB | Backend restarts silently break the app | 2 hours |
| 3 | Incident ↔ Alert linking UI | The biggest incomplete feature; DB is already ready | 4 hours |

---

## Summary Table

| Feature / Area | Current Status | Evidence | Recommended Action | Priority |
|---|---|---|---|---|
| Authentication | Partial — works but plaintext passwords | `run.py` `DEMO_USERS` | Hash passwords with bcrypt | Critical |
| Session management | Partial — in-memory, lost on restart | `run.py` `_SESSION_TOKENS` | Persist to DB | Critical |
| Role-based access control | Missing — all users have equal access | `require_auth` decorator | Implement RBAC | Critical |
| Dashboard stats accuracy | Complete — active-only counts | `run.py` `dashboard_stats()` | No action needed | — |
| Alert detection (13 rules) | Complete | `rule_engine.py` | Persist counters to DB | High |
| Alert triage UI | Complete | `Alerts.tsx` | No action needed | — |
| Alert resolve/vanish | Complete | `run.py` `update_alert_status()` | No action needed | — |
| AI analysis (mock+live) | Complete | `ai_engine.py` | Add `openai` to requirements.txt | High |
| AI threat assessment | Complete — active-only scoring | `ai_engine._mock_assessment()` | No action needed | — |
| Live log stream | Complete | `LiveIngestion.tsx`, Socket.IO | No action needed | — |
| Log Explorer | Complete | `LogExplorer.tsx` | No action needed | — |
| File upload & analysis | Complete | `FileUpload.tsx` | No action needed | — |
| Incident management | Partial — no alert linking | `Incidents.tsx`, DB schema | Build alert linking UI | High |
| Incident timeline/AI summary | Not implemented — fields exist in DB | `database.py` incidents table | Implement | Medium |
| Windows log collection | Complete | `windows-log-forwarder.ps1` | No action needed | — |
| Linux log collection | Complete but unstable | `soc-forwarder.sh`, systemd | Add reconnect/watchdog | High |
| Firewall log collection | Complete | `soc-forwarder.sh` | No action needed | — |
| IDS/network log collection | Not implemented | No forwarder exists | Add if needed | Low |
| GeoIP enrichment | Not implemented — schema exists | `database.py` geo columns | Add geoip2 enrichment | Medium |
| Email/webhook notifications | Not implemented | No code exists | Add for critical alerts | Medium |
| Threat intelligence | Not implemented | No code exists | Add AbuseIPDB integration | Medium |
| PDF reports | Not implemented | No code exists | Add reportlab export | Low |
| Test coverage | Good — 148 tests | `tests/` directory | Maintain as features added | — |
| CORS security | Gap — Socket.IO wildcard | `run.py` line 32 | Restrict to settings.CORS_ORIGINS | High |
| Pagination safety | Partial — missing in 2 endpoints | `run.py` `uploaded_logs()` | Apply `_safe_int` everywhere | Medium |
| Data clear / watermark | Complete | `run.py` `clear_live_logs()` | No action needed | — |
| Setup scripts | Complete | `setup.bat`, `setup.sh` | Add `openai` to requirements | High |

---

*Report generated from direct source code inspection. All findings are verified against actual implementation files.*
