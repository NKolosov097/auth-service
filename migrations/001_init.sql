-- migrations/001_init.sql

CREATE TABLE IF NOT EXISTS users (
    id               BIGSERIAL PRIMARY KEY,
    email            TEXT        NOT NULL UNIQUE,
    password_hash    TEXT        NOT NULL DEFAULT '',
    provider         TEXT        NOT NULL DEFAULT 'email',
    provider_id      TEXT        NOT NULL DEFAULT '',
    email_confirmed  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_provider_provider_id ON users (provider, provider_id);

CREATE TABLE IF NOT EXISTS sessions (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token TEXT        NOT NULL UNIQUE,
    user_agent    TEXT        NOT NULL DEFAULT '',
    ip            TEXT        NOT NULL DEFAULT '',
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);

CREATE TABLE IF NOT EXISTS reset_tokens (
    user_id    BIGINT      NOT NULL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS change_email_tokens (
    user_id    BIGINT      NOT NULL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    new_email  TEXT        NOT NULL,
    token      TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL
);
