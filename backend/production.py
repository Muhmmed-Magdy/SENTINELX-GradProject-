"""Production entry point for Gunicorn.

Run from the backend directory after setting APP_ENV=production.
"""
from config import settings

settings.validate()

from run import app, startup  # noqa: E402

startup()

application = app
