"""
AI SOC Dashboard Configuration
Loads from .env file automatically via python-dotenv.
"""
import os
from pathlib import Path

# Load .env file only for local non-production development. In production we require
# explicit environment variables and refuse to silently inherit values from a dev .env file.
try:
    from dotenv import load_dotenv
    # Check for .env in backend/ and the project root so developers can place it either place
    _env_backend = Path(__file__).parent / '.env'
    _env_project = Path(__file__).parent.parent / '.env'
    if os.environ.get("APP_ENV", "").strip().lower() != "production":
        if _env_backend.exists():
            load_dotenv(_env_backend)
            print(f"[OK] Loaded environment from {_env_backend}")
        elif _env_project.exists():
            load_dotenv(_env_project)
            print(f"[OK] Loaded environment from {_env_project}")
        else:
            # Fall back to any .env on PATH (dotenv default behavior)
            load_dotenv()
            # No explicit message here — silent fallback
except ImportError:
    pass  # dotenv not installed — environment vars must be set manually

class Settings:
    APP_NAME = "AI SOC Dashboard"
    ENVIRONMENT = os.environ.get("APP_ENV", "development").lower()
    IS_PRODUCTION = ENVIRONMENT == "production"
    # Never run with debug=True in production — read from env, default False
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "8001"))
    
    # Database (SQLite - built into Python; PostgreSQL is not yet supported)
    DATABASE_URL = os.environ.get("DATABASE_URL", "")
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc_dashboard.db"),
    )
    if DATABASE_URL.startswith("sqlite:///"):
        DATABASE_PATH = DATABASE_URL[len("sqlite:///"):]
    elif DATABASE_URL:
        raise RuntimeError(
            "This release supports SQLite DATABASE_URL values only; PostgreSQL support is not enabled."
        )
    
    # JWT / session signing
    # Warn loudly at startup if the default insecure key is still in use
    SECRET_KEY = os.environ.get("SECRET_KEY", "soc-dashboard-secret-key-change-in-production")

    @classmethod
    def validate(cls) -> None:
        """Call once at startup to surface dangerous misconfiguration early."""
        import warnings
        if cls.IS_PRODUCTION and (
            cls.SECRET_KEY == "soc-dashboard-secret-key-change-in-production"
            or len(cls.SECRET_KEY) < 32
        ):
            raise RuntimeError(
                "Production requires SECRET_KEY to be a unique value of at least 32 characters."
            )
        if cls.SECRET_KEY == "soc-dashboard-secret-key-change-in-production":
            warnings.warn(
                "SECRET_KEY is set to the default insecure value. "
                "Set the SECRET_KEY environment variable before deploying.",
                stacklevel=2,
            )
        if cls.IS_PRODUCTION and (
            not cls.CORS_ORIGINS_RAW
            or "*" in cls.CORS_ORIGINS
            or any(origin.startswith("http://") for origin in cls.CORS_ORIGINS)
        ):
            raise RuntimeError(
                "Production requires CORS_ORIGINS with explicit HTTPS frontend origins."
            )
        if not cls.IS_PRODUCTION and not cls.CORS_ORIGINS_RAW:
            warnings.warn(
                "CORS_ORIGINS is using localhost defaults. Set APP_ENV=production and "
                "CORS_ORIGINS before deploying.",
                stacklevel=2,
            )
    
    # OpenAI
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    # Log ingestion API key (single-key shortcut; use DB ingest_keys table for multi-agent)
    INGEST_KEY = os.environ.get("INGEST_KEY", "")

    # Bootstrap admin (used ONCE to seed the first admin account; clear after setup)
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
    DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() in ("1", "true", "yes")
    
    # Upload — configurable via env
    UPLOAD_DIR = os.environ.get(
        "UPLOAD_DIR",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads"),
    )
    MAX_UPLOAD_SIZE = int(os.environ.get("MAX_UPLOAD_SIZE", str(50 * 1024 * 1024)))   # 50 MB
    MAX_INGEST_PAYLOAD_SIZE = int(os.environ.get("MAX_INGEST_PAYLOAD_SIZE", str(2 * 1024 * 1024)))  # 2 MB

    # Allowed file extensions for log uploads (lower-case)
    ALLOWED_UPLOAD_EXTENSIONS = frozenset({
        ".log", ".txt", ".xml", ".json", ".ndjson", ".csv",
    })

    # CORS — override via env (comma-separated origins) in production
    CORS_ORIGINS_RAW = os.environ.get("CORS_ORIGINS", "")
    CORS_ORIGINS: list = (
        [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()]
        if CORS_ORIGINS_RAW
        else ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"]
    )

    # ── Phase 2: Anomaly Scoring ──────────────────────────────────────────
    # Set ANOMALY_SCORING_ENABLED=false to disable scoring at ingest time.
    ANOMALY_SCORING_ENABLED: bool = os.environ.get(
        "ANOMALY_SCORING_ENABLED", "true"
    ).lower() not in ("false", "0", "no")

    # Score threshold above which a log is highlighted as high-anomaly.
    ANOMALY_SCORE_THRESHOLD: int = int(os.environ.get("ANOMALY_SCORE_THRESHOLD", "60"))

    # ── Phase 2: AI Auto-Triage ───────────────────────────────────────────
    # Set AUTO_TRIAGE_ENABLED=false to disable the background triage worker.
    AUTO_TRIAGE_ENABLED: bool = os.environ.get(
        "AUTO_TRIAGE_ENABLED", "true"
    ).lower() not in ("false", "0", "no")

settings = Settings()
