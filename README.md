# auth

Authentication microservice for the **blob** project. Handles email/password registration and login, Google OAuth2, Telegram Login Widget, JWT session management, password reset, and email change — all over a JSON HTTP API.

## Features

- Email/password registration and login (bcrypt cost 12)
- Google OAuth2 (OpenID Connect)
- Telegram Login Widget
- JWT access tokens (15 min) and rotating refresh tokens (30 days)
- Refresh tokens stored as SHA-256 hashes — raw tokens never persisted
- Password reset via email link (1-hour token)
- Email change via confirmation link (24-hour token)
- Per-IP rate limiting: 100 req/min globally, 10 req/min on auth endpoints
- Request body limit: 64 KiB; header limit: 16 KiB
- HTTP security headers on every response
- Structured JSON logging via `log/slog`
- Graceful shutdown

## Requirements

- Go 1.26.2 or later
- PostgreSQL 14 or later
- `psql` CLI (for `make migrate`)
- `golangci-lint` (for `make lint`, optional)

## Quick Start

```bash
# 1. Clone
git clone https://github.com/NKolosov097/auth.git
cd auth

# 2. Configure
cp .env.example .env
# Edit .env — at minimum set DATABASE_URL, JWT_ACCESS_SECRET, JWT_REFRESH_SECRET

# 3. Apply database migrations
make migrate

# 4. Run
make run or go run ./cmd/auth
```

The server starts on `:8080` by default.

## Configuration

All configuration is read from environment variables. Copy `.env.example` to `.env` for local development; the application loads it automatically via `godotenv`.

| Variable               | Required | Default                                         | Description                                                                            |
| ---------------------- | -------- | ----------------------------------------------- | -------------------------------------------------------------------------------------- |
| `DATABASE_URL`         | Yes      | —                                               | PostgreSQL DSN, e.g. `postgres://user:pass@localhost:5432/auth?sslmode=disable`        |
| `JWT_ACCESS_SECRET`    | Yes      | —                                               | HMAC secret for access tokens. Minimum 32 characters.                                  |
| `JWT_REFRESH_SECRET`   | Yes      | —                                               | HMAC secret for refresh tokens. Minimum 32 characters. Must differ from access secret. |
| `HTTP_ADDR`            | No       | `:8080`                                         | TCP address the HTTP server listens on                                                 |
| `APP_URL`              | No       | `http://localhost:3000`                         | Base URL of the frontend app. Used to build reset/confirmation links in emails.        |
| `GOOGLE_CLIENT_ID`     | No       | —                                               | Google OAuth2 client ID                                                                |
| `GOOGLE_CLIENT_SECRET` | No       | —                                               | Google OAuth2 client secret                                                            |
| `GOOGLE_REDIRECT_URL`  | No       | `http://localhost:8080/v1/auth/google/callback` | OAuth2 redirect URI registered in Google Cloud Console                                 |
| `TELEGRAM_BOT_TOKEN`   | No       | —                                               | Bot token from @BotFather, used to verify Telegram Login Widget HMAC                   |
| `SMTP_HOST`            | No       | `smtp.gmail.com`                                | SMTP server hostname                                                                   |
| `SMTP_PORT`            | No       | `587`                                           | SMTP port. Use `465` with `SMTP_IMPLICIT_TLS=true`.                                    |
| `SMTP_USERNAME`        | No       | —                                               | SMTP authentication username                                                           |
| `SMTP_PASSWORD`        | No       | —                                               | SMTP authentication password                                                           |
| `SMTP_FROM`            | No       | `noreply@example.com`                           | Sender address used in outgoing emails                                                 |
| `SMTP_IMPLICIT_TLS`    | No       | `false`                                         | Set to `true` for implicit TLS (port 465). `false` uses STARTTLS (port 587).           |

`JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET` are validated at startup. The process panics immediately if either is absent or shorter than 32 characters.

## API Reference

All endpoints are under `/v1/auth`. Responses are JSON. Errors have the shape `{"error": "message"}`.

### Public endpoints (rate-limited: 10 req/min per IP)

#### `POST /v1/auth/register`

Create a new email/password account. Returns a token pair.

```json
// Request
{ "email": "user@example.com", "password": "correct-horse-battery" }

// 201 Created
{ "AccessToken": "eyJ...", "RefreshToken": "eyJ..." }
```

Password must be 12–72 characters.

---

#### `POST /v1/auth/login`

Authenticate with email and password.

```json
// Request
{ "email": "user@example.com", "password": "correct-horse-battery" }

// 200 OK
{ "AccessToken": "eyJ...", "RefreshToken": "eyJ..." }
```

---

#### `POST /v1/auth/refresh`

Rotate the refresh token. The old refresh token is invalidated.

```json
// Request
{ "refresh_token": "eyJ..." }

// 200 OK
{ "AccessToken": "eyJ...", "RefreshToken": "eyJ..." }
```

---

#### `POST /v1/auth/forgot-password`

Send a password-reset link to the given address. Always returns 200 to prevent email enumeration.

```json
// Request
{ "email": "user@example.com" }

// 200 OK
{ "message": "if the email exists you will receive a reset link" }
```

---

#### `POST /v1/auth/reset-password`

Apply a password-reset token received by email.

```json
// Request
{ "token": "<token from email>", "password": "new-password-here" }

// 200 OK
{ "message": "password updated" }
```

All active sessions for the user are invalidated on success.

---

#### `POST /v1/auth/telegram`

Authenticate using the [Telegram Login Widget](https://core.telegram.org/widgets/login). Send the widget's form fields as `application/x-www-form-urlencoded`. Auth data older than 60 seconds is rejected.

```
// Request (form-encoded)
id=123456789&first_name=Jane&username=janesmith&auth_date=1700000000&hash=<hmac>

// 200 OK
{ "AccessToken": "eyJ...", "RefreshToken": "eyJ..." }
```

---

### OAuth endpoints

#### `GET /v1/auth/google`

Redirects the browser to Google's OAuth2 consent screen. A CSRF state value is set as a short-lived `HttpOnly` cookie.

#### `GET /v1/auth/google/callback`

OAuth2 redirect URI. Validates the CSRF state cookie, exchanges the code for tokens, fetches the user's OpenID profile, and returns a token pair.

```json
// 200 OK
{ "AccessToken": "eyJ...", "RefreshToken": "eyJ..." }
```

---

### Protected endpoints (Bearer JWT required)

Include the access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

#### `POST /v1/auth/logout`

Invalidate a refresh token (delete its session).

```json
// Request
{ "refresh_token": "eyJ..." }

// 204 No Content
```

---

#### `POST /v1/auth/change-password`

Change the password for the authenticated account. Only available for email/password accounts. Invalidates all active sessions on success.

```json
// Request
{ "old_password": "correct-horse-battery", "new_password": "new-secure-password" }

// 200 OK
{ "message": "password changed" }
```

---

#### `POST /v1/auth/change-email`

Request an email address change. A confirmation link is sent to the new address. The link is valid for 24 hours.

```json
// Request
{ "new_email": "newemail@example.com" }

// 200 OK
{ "message": "confirmation link sent to new email" }
```

---

#### `GET /v1/auth/confirm-email-change?token=<token>`

Apply an email change. The `token` query parameter comes from the link sent to the new address. All active sessions are invalidated on success.

```json
// 200 OK
{ "message": "email changed" }
```

---

### HTTP status codes

| Code | Meaning                                              |
| ---- | ---------------------------------------------------- |
| 200  | Success                                              |
| 201  | Resource created                                     |
| 204  | Success, no body                                     |
| 400  | Bad request / validation error                       |
| 401  | Missing or invalid credentials / expired token       |
| 404  | Resource not found                                   |
| 409  | Conflict (account already exists, provider mismatch) |
| 429  | Rate limit exceeded                                  |
| 500  | Internal server error                                |

## Database Schema

Applied by `make migrate` (`migrations/001_init.sql`). All tables cascade-delete from `users`.

```sql
CREATE TABLE users (
    id               BIGSERIAL PRIMARY KEY,
    email            TEXT        NOT NULL UNIQUE,
    password_hash    TEXT        NOT NULL DEFAULT '',
    provider         TEXT        NOT NULL DEFAULT 'email', -- 'email' | 'google' | 'telegram'
    provider_id      TEXT        NOT NULL DEFAULT '',
    email_confirmed  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token TEXT        NOT NULL UNIQUE, -- SHA-256 hash of the raw token
    user_agent    TEXT        NOT NULL DEFAULT '',
    ip            TEXT        NOT NULL DEFAULT '',
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE reset_tokens (
    user_id    BIGINT      NOT NULL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL
    -- one active reset token per user; upserted on repeat requests
);

CREATE TABLE change_email_tokens (
    user_id    BIGINT      NOT NULL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    new_email  TEXT        NOT NULL,
    token      TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL
    -- one pending change per user; upserted on repeat requests
);
```

## Security Notes

**Passwords**

- bcrypt with cost 12.
- When a login attempt is made for an unknown email, a dummy bcrypt comparison is performed to equalise response time and prevent user enumeration.

**JWT**

- HS256 algorithm only. Any token presenting a different algorithm is rejected.
- Access tokens expire after 15 minutes. Refresh tokens expire after 30 days.
- Refresh tokens are stored as SHA-256 hashes. The raw token is never written to the database.
- Tokens carry a random JTI and are validated for issuer, audience, and expiry with a 30-second leeway.

**OAuth**

- Google: a 32-byte random CSRF state is set as a `HttpOnly; Secure; SameSite=Lax` cookie scoped to the callback path. The callback verifies the state with `subtle.ConstantTimeCompare`.
- Telegram: the server recomputes the HMAC-SHA256 from the widget fields using `SHA256(bot_token)` as the key and rejects any payload older than 60 seconds.

**Transport and headers**
Every response includes:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cache-Control: no-store
```

**Rate limiting**
Per-IP token-bucket limiter, tracked in memory with a 5-minute idle eviction window.

- Global: 100 req/min, burst 20
- Auth endpoints: 10 req/min, burst 5

**Input limits**

- Request body: 64 KiB
- Request headers: 16 KiB (`MaxHeaderBytes`)
- Email addresses validated with `net/mail.ParseAddress` and checked for CR/LF injection before any SMTP use.

## Development Commands

```bash
# Run in development (loads .env automatically)
make run

# Compile to bin/auth
make build

# Run all tests with race detection
make test

# Lint with golangci-lint
make lint

# Apply migrations (requires DATABASE_URL to be set or exported)
make migrate
```

## Project Structure

```
auth/
├── cmd/auth/
│   └── main.go               # Entry point: wires config, DB pool, repos, service, handler
├── internal/
│   ├── config/
│   │   └── config.go         # Env-var loading and validation
│   ├── domain/
│   │   ├── user.go           # Core types: User, Session, ResetToken, ChangeEmailToken
│   │   └── errors.go         # Sentinel errors
│   ├── handler/
│   │   ├── handler.go        # Chi router setup and middleware chain
│   │   ├── auth.go           # All HTTP handlers
│   │   ├── middleware.go     # Auth middleware, security headers, request logger
│   │   └── ratelimit.go      # Per-IP token-bucket rate limiter
│   ├── service/
│   │   └── auth.go           # Business logic (Auth service)
│   ├── token/
│   │   └── jwt.go            # JWT issue and parse (HS256)
│   ├── mailer/
│   │   └── mailer.go         # SMTP mailer (STARTTLS and implicit TLS)
│   └── repository/
│       └── postgres/
│           └── user.go       # UserRepo, SessionRepo, TokenRepo (pgx/v5)
├── migrations/
│   └── 001_init.sql          # Creates all four tables
├── .env.example
├── Makefile
└── go.mod
```

## License

Not specified. Contact the repository owner for terms.
