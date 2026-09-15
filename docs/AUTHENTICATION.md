# Forecast Authentication & Authorization

## Endpoints

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/auth/users` (ADMIN)
- `PATCH /api/auth/users/{user_id}/role` (ADMIN)

Authentication uses a signed JWT carried in an HttpOnly cookie. The token is also represented by a server-side `user_sessions` row, so logout revokes the session immediately and role/active-state changes are checked against PostgreSQL on every protected request.

## Passwords

Passwords are hashed with Argon2id and are never returned to clients. Registration requires 8+ characters plus uppercase, lowercase, number and special character. Common weak passwords are rejected.

## Roles

| Role | Access |
| --- | --- |
| ADMIN | Full platform access, user/role management, security configuration |
| DATA_SCIENTIST | Detection, model/forecast operations, dataset/evidence write operations |
| ANALYST | Forecast execution and operational response operations; no user/security administration |
| VIEWER | Read-only dashboards/results |

Backend dependencies enforce authentication and role checks. Frontend checks are UX-only.

## First admin

1. Apply `backend/migrations/001_auth.sql` to PostgreSQL.
2. Set `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD` in the backend environment.
3. Run from the `backend` directory: `python -m scripts.create_admin`.
4. Do not commit the environment file or print the password.

## Required production variables

`DATABASE_URL`, `SECRET_KEY`, `BACKEND_CORS_ORIGINS`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `AUTH_COOKIE_NAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` for the one-time bootstrap. Set `AUTH_COOKIE_SECURE=true` in normal production configuration; the application also forces Secure cookies for production environments.

## Test suite

`backend/tests/test_auth_security.py` covers Argon2id hashing, registration, login failure behavior, `/me`, logout/session revocation, password-hash non-disclosure, unauthenticated forecast access and Viewer RBAC.

## Remaining deployment considerations

- Login throttling is process-local; use a shared Redis-backed rate limiter for multi-instance deployments.
- Production PostgreSQL schema changes must be applied through migrations before starting the server.
- HTTPS and a same-site deployment/proxy arrangement are required for the secure cookie design.
- Existing Forecast/Threat/Evidence records are shared application resources because the current domain models do not have an owner/user column. Add resource ownership and row-level authorization if per-user isolation is required.
