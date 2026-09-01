# Security

## Deployment model

Terminate TLS at a reverse proxy and keep the backend bound to a private interface. The provided Caddy and Nginx examples proxy `/api/` and `/socket.io/`; do not expose the database or backend port directly.

## Authentication and authorization

Passwords are stored with Werkzeug's salted password hashing. Login creates a random, database-backed session token with a 24-hour expiry. The database stores only a SHA-256 token hash. Sensitive routes use role checks, and inactive or revoked sessions are rejected.

Browser Socket.IO clients send the token in Socket.IO handshake authentication. Older forwarders may still use the query-token compatibility path; migrate them to header or handshake authentication where supported.

## Secrets

Never commit `.env`, API keys, ingest keys, database files, or generated credentials. Set `APP_ENV=production`, a unique `SECRET_KEY` of at least 32 characters, explicit HTTPS `CORS_ORIGINS`, and a long one-time `ADMIN_PASSWORD`. Rotate any credential that has previously appeared in repository history; deleting a file does not revoke an exposed credential.

## Input and API security

The backend uses parameterized SQL, request-size limits, upload extension checks, role-based access control, login rate limiting, and generic authentication errors. Keep production debug mode disabled and review reverse-proxy access logs without recording authorization headers or request bodies.

## Dependency and CI security

Run `pip-audit`, `bandit`, `npm audit`, and the test/build pipeline before release. Pin or review dependency upgrades and rebuild images regularly for base-image security updates.

## Current limitations

The application currently uses SQLite. It is suitable for local development and a small single-backend deployment, but PostgreSQL support requires a deliberate database adapter/migration project because the schema and SQL currently use SQLite-specific behavior. Do not attach a PostgreSQL service and assume it is being used.

PostgreSQL support pending. The required migration work is to introduce a connection/repository abstraction, replace SQLite placeholders and `INSERT OR IGNORE`, translate SQLite datetime and pragma usage, create PostgreSQL migrations, add pooling, and test transaction/concurrency behavior. Until that work is complete, non-SQLite `DATABASE_URL` values are rejected explicitly.

## Reporting

Do not disclose credentials or sensitive log data in an issue. Report security findings privately to the project owner with reproduction steps, impact, and a proposed mitigation.
