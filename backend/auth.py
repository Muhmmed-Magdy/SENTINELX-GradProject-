"""
auth.py — Production authentication helpers.

Provides:
  - Password hashing / verification via werkzeug
  - DB-backed session creation / lookup / revocation
  - Ingest-key validation with constant-time comparison
  - Bootstrap helper to create the initial admin account
  - require_auth / require_role decorators
  - get_current_user() helper for route handlers
"""
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import request, jsonify

# ---------------------------------------------------------------------------
# Password hashing — werkzeug ships with Flask, no extra dep needed
# ---------------------------------------------------------------------------
try:
    from werkzeug.security import generate_password_hash, check_password_hash
    _HASH_METHOD = "scrypt"   # werkzeug ≥2.3 default; falls back to pbkdf2 on older
except ImportError:  # pragma: no cover
    raise ImportError("werkzeug is required (it ships with Flask)")


def hash_password(plaintext: str) -> str:
    """Return a salted hash of *plaintext*. Never store the plaintext."""
    return generate_password_hash(plaintext, method=_HASH_METHOD)


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """Constant-time password verification. Returns False on any error."""
    try:
        return check_password_hash(stored_hash, plaintext)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------
_SESSION_TTL_SECONDS = 24 * 60 * 60   # 24 h


def _hash_token(token: str) -> str:
    """SHA-256 hex digest of *token*. This is what we store in the DB."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db, user_id: str) -> str:
    """
    Generate a cryptographically random token, store its hash, return the
    raw token (sent to the client exactly once — never stored here).
    """
    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=_SESSION_TTL_SECONDS)
    db.execute(
        """INSERT INTO sessions (id, user_id, created_at, expires_at, last_used_at)
           VALUES (?, ?, ?, ?, ?)""",
        (token_hash, user_id,
         now.isoformat(), expires.isoformat(), now.isoformat()),
    )
    # no commit here — caller commits
    return token


def get_session_user(db, token: str) -> dict | None:
    """
    Look up a session by token hash. Returns the user dict or None.
    Updates last_used_at on success. Caller must commit.
    """
    if not token:
        return None
    token_hash = _hash_token(token)
    now = datetime.now(timezone.utc)

    row = db.execute(
        """SELECT s.id, s.user_id, s.expires_at, s.revoked_at,
                  u.email, u.name, u.role, u.is_active
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.id = ?""",
        (token_hash,),
    ).fetchone()

    if not row:
        return None

    # Revoked?
    if row["revoked_at"] is not None:
        return None

    # Expired?
    try:
        exp = datetime.fromisoformat(row["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now >= exp:
            return None
    except Exception:
        return None

    # Inactive user?
    if not row["is_active"]:
        return None

    # Touch last_used_at (best-effort; non-fatal if it fails)
    try:
        db.execute(
            "UPDATE sessions SET last_used_at=? WHERE id=?",
            (now.isoformat(), token_hash),
        )
    except Exception:
        pass

    return {
        "user_id": row["user_id"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
    }


def revoke_session(db, token: str) -> bool:
    """Mark a session as revoked. Returns True if a row was updated."""
    if not token:
        return False
    token_hash = _hash_token(token)
    result = db.execute(
        "UPDATE sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
        (datetime.now(timezone.utc).isoformat(), token_hash),
    )
    return result.rowcount > 0


def purge_expired_sessions(db) -> int:
    """Delete sessions that expired more than 7 days ago. Returns rows deleted."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    result = db.execute(
        "DELETE FROM sessions WHERE expires_at < ?", (cutoff,)
    )
    return result.rowcount


# ---------------------------------------------------------------------------
# Ingest key helpers
# ---------------------------------------------------------------------------

def _hash_key(raw_key: str) -> str:
    """SHA-256 hex digest used as the stored identifier for an ingest key."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def validate_ingest_key(db, raw_key: str) -> bool:
    """
    Constant-time check: is *raw_key* a known active ingest key?
    Also checks the INGEST_KEY env var as a single-key shortcut.
    Updates last_used_at. Caller must commit.
    """
    if not raw_key:
        return False

    # Fast path: single-key mode via environment variable
    from config import settings
    env_key = settings.INGEST_KEY
    if env_key:
        # Use hmac.compare_digest for constant-time comparison
        if hmac.compare_digest(raw_key, env_key):
            return True
        # Don't short-circuit — also check DB keys below

    key_hash = _hash_key(raw_key)
    row = db.execute(
        "SELECT id FROM ingest_keys WHERE key_hash=? AND is_active=1 AND revoked_at IS NULL",
        (key_hash,),
    ).fetchone()
    if row:
        try:
            db.execute(
                "UPDATE ingest_keys SET last_used_at=? WHERE key_hash=?",
                (datetime.now(timezone.utc).isoformat(), key_hash),
            )
        except Exception:
            pass
        return True
    return False


def create_ingest_key(db, name: str) -> str:
    """Generate a new ingest key, store its hash, return the raw key (shown once)."""
    raw_key = "soc-" + secrets.token_urlsafe(32)
    key_hash = _hash_key(raw_key)
    db.execute(
        "INSERT INTO ingest_keys (id, name, key_hash) VALUES (?, ?, ?)",
        (str(uuid.uuid4()), name[:200], key_hash),
    )
    return raw_key   # caller commits; raw key never stored after this return


# ---------------------------------------------------------------------------
# Flask decorators
# ---------------------------------------------------------------------------

# Role hierarchy: higher index = more permissions
_ROLE_RANK = {
    "readonly": 0,
    "analyst": 1,
    "senior_analyst": 2,
    "admin": 3,
}


def _extract_token() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return ""


def require_auth(f):
    """Decorator: reject unauthenticated requests with 401."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        from database import get_db
        token = _extract_token()
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        db = get_db()
        user = get_session_user(db, token)
        if user is None:
            db.close()
            return jsonify({"error": "Authentication required"}), 401
        db.commit()
        db.close()
        # Stash user on request context for downstream use
        request.current_user = user
        return f(*args, **kwargs)
    return wrapper


def require_role(*roles: str):
    """
    Decorator factory: require auth AND one of the specified roles.
    Returns 401 if not authenticated, 403 if authenticated but wrong role.
    """
    allowed = frozenset(roles)
    def decorator(f):
        @wraps(f)
        @require_auth
        def wrapper(*args, **kwargs):
            user = getattr(request, "current_user", {})
            if user.get("role") not in allowed:
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_min_role(min_role: str):
    """
    Decorator: require auth AND a role with rank >= min_role.
    Accepts admin/senior_analyst/analyst/readonly.
    """
    min_rank = _ROLE_RANK.get(min_role, 99)
    def decorator(f):
        @wraps(f)
        @require_auth
        def wrapper(*args, **kwargs):
            user = getattr(request, "current_user", {})
            rank = _ROLE_RANK.get(user.get("role", ""), -1)
            if rank < min_rank:
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def get_current_user() -> dict:
    """Return the current authenticated user dict (set by require_auth)."""
    return getattr(request, "current_user", {})


# ---------------------------------------------------------------------------
# Bootstrap: create initial admin from env vars (run once at startup)
# ---------------------------------------------------------------------------

def bootstrap_admin(db) -> None:
    """
    If no users exist AND ADMIN_EMAIL + ADMIN_PASSWORD are set in the
    environment, create the initial admin account. Safe to call repeatedly.
    Never re-creates or overwrites an existing account.
    Never logs the password.
    """
    from config import settings

    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count > 0:
        return   # users already exist — nothing to do

    email = settings.ADMIN_EMAIL
    password = settings.ADMIN_PASSWORD
    if not email or not password:
        print(
            "⚠️  No users in DB and ADMIN_EMAIL/ADMIN_PASSWORD not set. "
            "Set both env vars to create the initial admin account."
        )
        return

    if len(password) < 12:
        print("ERROR: ADMIN_PASSWORD must be at least 12 characters. Admin not created.")
        return

    uid = str(uuid.uuid4())
    pwd_hash = hash_password(password)
    db.execute(
        "INSERT INTO users (id, email, name, password_hash, role, is_active) VALUES (?,?,?,?,?,1)",
        (uid, email.strip().lower(), "Admin User", pwd_hash, "admin"),
    )
    print(f"[OK] Bootstrap admin created: {email}")
