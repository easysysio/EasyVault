-- =============================================================================
-- 004_approle.sql — AppRole auth (machine login)
--
-- An AppRole binds a stable role_id (+ one or more secret_ids) to a vault and a
-- path/IP/TTL policy. `POST /v1/auth/approle/login` with role_id + secret_id
-- mints a per-vault API token. Only SHA-256(secret_id) is stored.
-- =============================================================================

CREATE TABLE approles (
    id              TEXT PRIMARY KEY,        -- UUID
    name            TEXT NOT NULL UNIQUE,
    vault_id        TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    role_id         TEXT NOT NULL UNIQUE,    -- stable identifier (not secret)
    allowed_paths   TEXT NOT NULL DEFAULT '["*"]',
    allowed_ips     TEXT NOT NULL DEFAULT '[]',
    token_ttl       INTEGER,                 -- seconds; NULL = no expiry
    created_by      TEXT REFERENCES users(id),
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE approle_secrets (
    id              TEXT PRIMARY KEY,        -- UUID
    approle_id      TEXT NOT NULL REFERENCES approles(id) ON DELETE CASCADE,
    secret_id_hash  TEXT NOT NULL,           -- SHA-256(secret_id)
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at    DATETIME
);

CREATE INDEX idx_approle_secret_hash ON approle_secrets(secret_id_hash);
CREATE INDEX idx_approle_role_id ON approles(role_id);
