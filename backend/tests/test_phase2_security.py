"""Focused Phase 2 production configuration and API hardening tests."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def validate_config(env):
    clean_env = os.environ.copy()
    for key in ("APP_ENV", "SECRET_KEY", "CORS_ORIGINS", "DATABASE_URL", "PYTHONPATH"):
        clean_env.pop(key, None)
    clean_env.update(env)
    clean_env["PYTHONPATH"] = str(ROOT)
    return subprocess.run(
        [sys.executable, "-c", "from config import settings; settings.validate()"],
        cwd=ROOT,
        env=clean_env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "secret, origins",
    [
        (None, "https://soc.example.com"),
        ("short", "https://soc.example.com"),
        ("soc-dashboard-secret-key-change-in-production", "https://soc.example.com"),
        ("0123456789abcdef0123456789abcdef", None),
        ("0123456789abcdef0123456789abcdef", "*"),
        ("0123456789abcdef0123456789abcdef", "http://soc.example.com"),
    ],
)
def test_production_rejects_unsafe_configuration(secret, origins):
    env = {"APP_ENV": "production"}
    if secret is not None:
        env["SECRET_KEY"] = secret
    if origins is not None:
        env["CORS_ORIGINS"] = origins
    result = validate_config(env)
    assert result.returncode != 0
    assert "SECRET_KEY" in result.stderr or "CORS_ORIGINS" in result.stderr
    assert secret not in result.stderr if secret else True


def test_production_accepts_strong_secret_and_https_origin():
    result = validate_config({
        "APP_ENV": "production",
        "SECRET_KEY": "0123456789abcdef0123456789abcdef",
        "CORS_ORIGINS": "https://soc.example.com",
    })
    assert result.returncode == 0


def test_sqlite_database_url_is_supported():
    result = validate_config({"DATABASE_URL": "sqlite:///test.db"})
    assert result.returncode == 0


def test_non_sqlite_database_url_is_rejected_explicitly():
    result = validate_config({"DATABASE_URL": "postgresql://db.example.invalid/soc"})
    assert result.returncode != 0
    assert "SQLite" in result.stderr


def test_security_headers_and_endpoint_limit(client, monkeypatch):
    from config import settings
    from run import _ENDPOINT_ATTEMPTS, _ENDPOINT_LIMITS

    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    if settings.IS_PRODUCTION:
        assert "Strict-Transport-Security" in response.headers
    else:
        assert "Strict-Transport-Security" not in response.headers

    monkeypatch.setitem(_ENDPOINT_LIMITS, "ai", (2, 300))
    _ENDPOINT_ATTEMPTS.clear()
    for _ in range(2):
        assert client.get("/api/ai/status").status_code == 401
    assert client.get("/api/ai/status").status_code == 429

    _ENDPOINT_ATTEMPTS.clear()
    for _ in range(2):
        assert client.get("/api/alerts/missing/ai-analysis").status_code == 401
    assert client.get("/api/alerts/missing/ai-analysis").status_code == 429
