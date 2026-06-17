-- =============================================================================
-- 001_initial.sql — EasyVault initial schema
--
-- Tables for instance init/seal state, users, vaults, per-user vault keys,
-- versioned secrets, API tokens, GUI sessions, ACL policies and the audit log.
-- =============================================================================

-- Instance init state and master-key verification material.
CREATE TABLE system_init (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    initialized         BOOLEAN NOT NULL DEFAULT 0,
    sealed              BOOLEAN NOT NULL DEFAULT 1,
    master_key_enc      BLOB,           -- AES-GCM(verification constant, master_key)
    master_key_nonce    BLOB,
    key_shares          INTEGER,        -- total Shamir shares issued
    key_threshold       INTEGER,        -- shares required to unseal
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Management users. password_hash verifies login; private_key_enc is unlocked
-- by the user_key derived from the password (never stored).
CREATE TABLE users (
    id                  TEXT PRIMARY KEY,       -- UUID
    username            TEXT NOT NULL UNIQUE,
    password_hash       BLOB NOT NULL,          -- Argon2id login-verification hash
    salt                BLOB NOT NULL,          -- 256-bit random (hash + key derivation)
    public_key          BLOB NOT NULL,          -- X25519 public key
    private_key_enc     BLOB NOT NULL,          -- AES-GCM(private_key, user_key)
    private_key_nonce   BLOB NOT NULL,
    is_master           BOOLEAN DEFAULT 0,
    active              BOOLEAN DEFAULT 1,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vaults. The vault key is never stored here; only its ACL and metadata are.
CREATE TABLE vaults (
    id                  TEXT PRIMARY KEY,       -- UUID
    name                TEXT NOT NULL UNIQUE,
    description         TEXT,
    acl_subnets         TEXT DEFAULT '[]',      -- JSON array of CIDR strings
    acl_ips             TEXT DEFAULT '[]',      -- JSON array of IP strings
    locked              BOOLEAN DEFAULT 0,
    created_by          TEXT REFERENCES users(id),
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Per-(vault,user) wrapped vault key, sealed under an ECDH shared secret.
CREATE TABLE vault_user_keys (
    vault_id            TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id             TEXT NOT NULL REFERENCES users(id),
    vault_key_enc       BLOB NOT NULL,          -- AES-GCM(vault_key, ecdh_shared_secret)
    vault_key_nonce     BLOB NOT NULL,
    granter_public_key  BLOB NOT NULL,          -- granting user's public key at grant time
    key_version         INTEGER DEFAULT 1,
    granted_by          TEXT REFERENCES users(id),
    granted_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, user_id)
);

-- Versioned secrets. Writes always INSERT a new version; values stay encrypted.
CREATE TABLE secrets (
    id                  TEXT PRIMARY KEY,       -- UUID
    vault_id            TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    path                TEXT NOT NULL,
    version             INTEGER NOT NULL DEFAULT 1,
    value_enc           BLOB NOT NULL,          -- AES-GCM(json_value, vault_key)
    value_nonce         BLOB NOT NULL,
    metadata            TEXT DEFAULT '{}',
    created_by          TEXT REFERENCES users(id),
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME,
    destroyed           BOOLEAN DEFAULT 0,
    UNIQUE(vault_id, path, version)
);

-- API tokens. The vault key is reachable via the master-key → token-key path.
CREATE TABLE api_tokens (
    id                  TEXT PRIMARY KEY,       -- UUID
    vault_id            TEXT NOT NULL REFERENCES vaults(id),
    token_hash          TEXT NOT NULL UNIQUE,   -- SHA-256(raw_token)
    display_name        TEXT,
    vault_key_enc       BLOB NOT NULL,          -- AES-GCM(vault_key, token_key)
    vault_key_nonce     BLOB NOT NULL,
    token_key_enc       BLOB NOT NULL,          -- AES-GCM(token_key, master_key)
    token_key_nonce     BLOB NOT NULL,
    allowed_paths       TEXT DEFAULT '["*"]',
    allowed_ips         TEXT DEFAULT '[]',
    expires_at          DATETIME,
    renewable           BOOLEAN DEFAULT 0,
    revoked             BOOLEAN DEFAULT 0,
    created_by          TEXT REFERENCES users(id),
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at        DATETIME
);

-- Web GUI sessions, keyed by a hashed session token.
CREATE TABLE gui_sessions (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id),
    session_hash        TEXT NOT NULL UNIQUE,   -- SHA-256(session_token)
    expires_at          DATETIME NOT NULL,
    ip_address          TEXT,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Named ACL policies (path → capabilities), referenced by tokens/roles.
CREATE TABLE policies (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    rules               TEXT NOT NULL,          -- JSON [{path, capabilities[]}]
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Append-only audit trail with an HMAC over each row for tamper detection.
CREATE TABLE audit_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id          TEXT NOT NULL,
    timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
    operation           TEXT NOT NULL,
    vault_id            TEXT,
    path                TEXT,
    actor_type          TEXT NOT NULL,          -- 'api_token' | 'gui_session' | 'system'
    actor_hash          TEXT,
    source_ip           TEXT,
    response_code       INTEGER,
    hmac                TEXT NOT NULL
);

CREATE INDEX idx_secrets_vault_path ON secrets(vault_id, path);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_tokens_hash ON api_tokens(token_hash);
