# EasyVault — Claude Code Briefing

## Project Overview

EasyVault is a self-hosted secrets manager written in Rust, designed as a HashiCorp Vault-compatible
alternative with improved ease of use and a stronger security model.

**Core security principle:** Secrets never touch client server storage. Servers hold only a
short-lived API token. All secrets live encrypted in EasyVault and are fetched at runtime via REST API.

**No CLI. No agent. Server only.** Clients interact exclusively via REST API.
Management (creating vaults, users, tokens, secrets) is done via Web GUI or REST API.

---

## Goals

- Drop-in Vault REST API compatibility (KV v2, AppRole, Token auth, PKI, sys endpoints)
- Single binary, zero external dependencies for basic operation
- SQLite by default, optional PostgreSQL for production
- True open source (MIT license)
- Envelope encryption: each vault has its own key, distributed per-user via ECDH
- Always-on audit log with optional EasyLog sink
- Web GUI for management (user+password login)
- Per-vault IP/subnet ACL
- Time-limited, path-scoped, IP-bound API tokens
- Master user who manages vaults and users
- Part of the Easy* self-hosted product family (OpenSCM, EasyLog, EasyDC, EasyNAS)

---

## Tech Stack

- **Language:** Rust (stable)
- **Web framework:** Axum
- **Database:** SQLite via sqlx (async, with migrations), optional PostgreSQL
- **Crypto:** AES-256-GCM (encryption), Argon2id (key derivation), X25519 (ECDH key exchange),
  SHA-256 (token hashing + HMAC audit)
- **Serialization:** serde + serde_json
- **Config:** TOML via config crate
- **Logging:** tracing + tracing-subscriber
- **TLS:** rustls (auto self-signed on first run, optional ACME)
- **Memory safety:** zeroize crate on all key material structs

### Cargo dependencies
```toml
[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
sqlx = { version = "0.7", features = ["sqlite", "runtime-tokio", "migrate"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
argon2 = "0.5"
aes-gcm = "0.10"
x25519-dalek = { version = "2", features = ["static_secrets"] }
rand = "0.8"
zeroize = { version = "1.7", features = ["derive"] }
sha2 = "0.10"
hmac = "0.12"
uuid = { version = "1", features = ["v4"] }
sharks = "0.5"
rustls = "0.22"
tower = "0.4"
tower-http = { version = "0.5", features = ["trace", "cors"] }
tracing = "0.1"
tracing-subscriber = "0.3"
config = "0.14"
toml = "0.8"
ipnet = "2"                  # for subnet ACL matching
chrono = { version = "0.4", features = ["serde"] }
```

---

## Project Structure

```
easyvault/
├── Cargo.toml
├── config.toml.example
├── CLAUDE.md
├── migrations/
│   ├── 001_initial.sql
│   └── 002_vault_keys.sql
└── src/
    ├── main.rs               # startup, config loading, router assembly, mlock master key
    ├── config.rs             # Config struct, TOML parsing
    ├── error.rs              # AppError type, Vault-compatible error responses
    ├── state.rs              # AppState (db pool, master key in memory, config)
    ├── api/
    │   ├── mod.rs            # Router assembly
    │   ├── middleware.rs     # Token auth, IP ACL check, audit log middleware
    │   ├── response.rs       # VaultResponse<T> envelope type
    │   └── routes/
    │       ├── sys.rs        # /v1/sys/* handlers
    │       ├── kv.rs         # /v1/secret/* handlers (KV v2)
    │       ├── auth/
    │       │   ├── token.rs  # /v1/auth/token/*
    │       │   └── approle.rs# /v1/auth/approle/*
    │       ├── pki.rs        # /v1/pki/* handlers
    │       ├── dynamic.rs    # /v1/dynamic/database/* handlers
    │       └── gui.rs        # Web GUI routes (login, dashboard, vault mgmt)
    ├── engines/
    │   ├── mod.rs
    │   ├── kv.rs             # KV v2 engine (versioning, metadata, envelope decrypt)
    │   ├── pki.rs            # PKI engine (CA, cert issuance)
    │   └── dynamic/
    │       ├── mod.rs
    │       └── database.rs   # Dynamic DB credential generation
    ├── auth/
    │   ├── mod.rs
    │   ├── token.rs          # API token creation, lookup, revocation
    │   ├── approle.rs        # AppRole role-id / secret-id flow
    │   ├── session.rs        # Web GUI session management
    │   └── policy.rs         # ACL policy engine, path matching
    ├── crypto/
    │   ├── mod.rs
    │   ├── aes.rs            # AES-256-GCM encrypt/decrypt
    │   ├── argon2.rs         # Key derivation (user_key) + password hashing (separate)
    │   ├── ecdh.rs           # X25519 keypair generation + shared secret derivation
    │   └── shamir.rs         # Master key splitting/reconstruction (unseal)
    ├── vault/
    │   ├── mod.rs
    │   ├── manager.rs        # Vault CRUD, user grant/revoke, key rotation
    │   └── acl.rs            # IP/subnet ACL enforcement
    ├── storage/
    │   ├── mod.rs
    │   └── sqlite.rs         # sqlx queries, migrations
    └── audit/
        ├── mod.rs
        └── easylog.rs        # EasyLog HTTP sink
```

---

## Security Architecture — Envelope Encryption

### Key Hierarchy

```
User Password
    │
    ▼ Argon2id (+ user salt)
User Key (never stored)
    │
    ▼ AES-256-GCM decrypt
User Private Key (X25519)
    │
    ▼ X25519 ECDH (with granting user's private key + recipient's public key)
Shared Secret
    │
    ▼ AES-256-GCM decrypt
Vault Key (per-vault, never stored in plaintext)
    │
    ▼ AES-256-GCM decrypt
Secret Plaintext
```

**Master Key** (separate hierarchy, for API token path):
```
Init ceremony → random 256-bit master key → held in memory (mlock'd page)
    │
    ▼ AES-256-GCM encrypt
Token Key (per API token, stored encrypted with master key)
    │
    ▼ AES-256-GCM decrypt
Vault Key (same vault key, different encryption path)
```

### Critical Rules
- `user_key` is NEVER stored — derived fresh from password+salt at each login
- `vault_key` is NEVER stored in plaintext — only stored encrypted per-user via ECDH
- `master_key` lives only in memory (mlock'd) — lost on restart, requires unseal
- Secret values are NEVER logged — audit log records paths and token hashes only
- Use `zeroize::Zeroize` on ALL structs holding key material

---

## Database Schema

### `system_init`
EasyVault instance init state and master key material.
```sql
CREATE TABLE system_init (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    initialized         BOOLEAN NOT NULL DEFAULT FALSE,
    sealed              BOOLEAN NOT NULL DEFAULT TRUE,
    master_key_enc      BLOB,           -- AES-GCM(master_key, bootstrap_key)
    master_key_nonce    BLOB,
    key_shares          INTEGER,        -- total Shamir shares
    key_threshold       INTEGER,        -- shares needed to unseal
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### `users`
```sql
CREATE TABLE users (
    id                  TEXT PRIMARY KEY,       -- UUID
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,          -- Argon2id hash (login verification only)
    salt                BLOB NOT NULL,          -- 256-bit random (key derivation)
    public_key          BLOB NOT NULL,          -- X25519 public key
    private_key_enc     BLOB NOT NULL,          -- AES-GCM(private_key, user_key)
    private_key_nonce   BLOB NOT NULL,
    is_master           BOOLEAN DEFAULT FALSE,
    active              BOOLEAN DEFAULT TRUE,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### `vaults`
```sql
CREATE TABLE vaults (
    id                  TEXT PRIMARY KEY,       -- UUID
    name                TEXT NOT NULL UNIQUE,
    description         TEXT,
    acl_subnets         TEXT DEFAULT '[]',      -- JSON: ["192.168.1.0/24", "10.0.0.0/8"]
    acl_ips             TEXT DEFAULT '[]',      -- JSON: ["1.2.3.4"]
    locked              BOOLEAN DEFAULT FALSE,
    created_by          TEXT REFERENCES users(id),
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### `vault_user_keys`
One row per (vault, user) — vault key encrypted with ECDH shared secret.
```sql
CREATE TABLE vault_user_keys (
    vault_id            TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id             TEXT NOT NULL REFERENCES users(id),
    vault_key_enc       BLOB NOT NULL,          -- AES-GCM(vault_key, ecdh_shared_secret)
    vault_key_nonce     BLOB NOT NULL,
    granter_public_key  BLOB NOT NULL,          -- granting user's public key at time of grant
    key_version         INTEGER DEFAULT 1,      -- increments on vault key rotation
    granted_by          TEXT REFERENCES users(id),
    granted_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, user_id)
);
```

### `secrets`
```sql
CREATE TABLE secrets (
    id                  TEXT PRIMARY KEY,       -- UUID
    vault_id            TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    path                TEXT NOT NULL,          -- e.g. "db/postgres/password"
    version             INTEGER NOT NULL DEFAULT 1,
    value_enc           BLOB NOT NULL,          -- AES-GCM(json_value, vault_key)
    value_nonce         BLOB NOT NULL,
    metadata            TEXT DEFAULT '{}',      -- JSON: custom_metadata
    created_by          TEXT REFERENCES users(id),
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    deleted_at          DATETIME,
    destroyed           BOOLEAN DEFAULT FALSE,
    UNIQUE(vault_id, path, version)
);
```

### `api_tokens`
```sql
CREATE TABLE api_tokens (
    id                  TEXT PRIMARY KEY,       -- UUID
    vault_id            TEXT NOT NULL REFERENCES vaults(id),
    token_hash          TEXT NOT NULL UNIQUE,   -- SHA-256(raw_token)
    display_name        TEXT,
    vault_key_enc       BLOB NOT NULL,          -- AES-GCM(vault_key, token_key)
    vault_key_nonce     BLOB NOT NULL,
    token_key_enc       BLOB NOT NULL,          -- AES-GCM(token_key, master_key)
    token_key_nonce     BLOB NOT NULL,
    allowed_paths       TEXT DEFAULT '["*"]',   -- JSON path patterns
    allowed_ips         TEXT DEFAULT '[]',      -- JSON: [] means inherit vault ACL
    expires_at          DATETIME,               -- NULL = never
    renewable           BOOLEAN DEFAULT FALSE,
    revoked             BOOLEAN DEFAULT FALSE,
    created_by          TEXT REFERENCES users(id),
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at        DATETIME
);
```

### `gui_sessions`
```sql
CREATE TABLE gui_sessions (
    id                  TEXT PRIMARY KEY,       -- UUID session token
    user_id             TEXT NOT NULL REFERENCES users(id),
    session_hash        TEXT NOT NULL UNIQUE,   -- SHA-256(session_token)
    expires_at          DATETIME NOT NULL,
    ip_address          TEXT,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### `policies`
```sql
CREATE TABLE policies (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    rules               TEXT NOT NULL,          -- JSON: [{path, capabilities[]}]
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### `audit_log`
```sql
CREATE TABLE audit_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id          TEXT NOT NULL,
    timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
    operation           TEXT NOT NULL,          -- READ, WRITE, DELETE, LOGIN, GRANT, REVOKE
    vault_id            TEXT,
    path                TEXT,
    actor_type          TEXT NOT NULL,          -- 'api_token' | 'gui_session' | 'system'
    actor_hash          TEXT,                   -- SHA-256 of token or session id
    source_ip           TEXT,
    response_code       INTEGER,
    hmac                TEXT NOT NULL           -- HMAC-SHA256 of row content (tamper detection)
);
```

---

## Crypto Flows

### Flow 1 — User Registration
```
1. Generate 256-bit random salt
2. password_hash = Argon2id(password, salt)          -- for login verification
3. user_key = Argon2id_derive(password, salt, KEY_CONTEXT)  -- for crypto (separate derivation)
4. Generate X25519 keypair (public_key, private_key)
5. nonce = random 96-bit
6. private_key_enc = AES-256-GCM(private_key, nonce, user_key)
7. Store: username, password_hash, salt, public_key, private_key_enc, nonce
8. NEVER store user_key or private_key in plaintext
```

**Note:** Use different Argon2id parameters/context strings for password_hash vs user_key
to ensure they produce different outputs from the same input.

### Flow 2 — User Login (Web GUI)
```
1. Fetch user.salt from DB
2. Verify: Argon2id(password, salt) == password_hash
3. Derive user_key = Argon2id_derive(password, salt, KEY_CONTEXT)
4. Decrypt: private_key = AES-GCM-decrypt(private_key_enc, nonce, user_key)
5. Hold (user_key, private_key) in server-side session (memory only)
6. Zeroize user_key immediately after decrypting private_key
7. Create gui_sessions row with session token
8. Return session cookie to browser
```

### Flow 3 — Vault Creation
```
1. Authenticated master user request
2. Generate 256-bit random vault_key
3. Derive ECDH shared secret for master user:
      shared_secret = X25519(master_private_key, master_public_key)
      (self-encryption: use own keypair)
4. nonce = random 96-bit
5. vault_key_enc = AES-GCM(vault_key, nonce, shared_secret)
6. Insert vaults row + vault_user_keys row for master user
7. Zeroize vault_key and shared_secret
```

### Flow 4 — Grant Vault Access to Another User
```
1. Granting user (User A) must have vault access
2. Fetch User A's private_key from their session
3. Fetch vault_key:
      shared_secret_A = X25519(private_key_A, public_key_A)   -- self ECDH
      vault_key = AES-GCM-decrypt(vault_key_enc_A, nonce_A, shared_secret_A)
4. Fetch User B's public_key from users table
5. Compute ECDH shared secret for B:
      shared_secret_AB = X25519(private_key_A, public_key_B)
6. nonce = random 96-bit
7. vault_key_enc_B = AES-GCM(vault_key, nonce, shared_secret_AB)
8. Insert vault_user_keys row for User B:
      (vault_key_enc_B, nonce, granter_public_key=public_key_A)
9. Zeroize vault_key, shared_secret_A, shared_secret_AB
```

### Flow 5 — User B Accesses Vault After Grant
```
1. User B logs in (gets private_key_B in session)
2. Fetch their vault_user_keys row (has vault_key_enc_B, granter_public_key)
3. shared_secret_AB = X25519(private_key_B, granter_public_key)
4. vault_key = AES-GCM-decrypt(vault_key_enc_B, nonce, shared_secret_AB)
5. Use vault_key to decrypt secrets
6. Zeroize vault_key and shared_secret_AB after use
```

### Flow 6 — Write a Secret
```
1. Resolve vault_key (from session for GUI, from token path for API)
2. value_json = JSON.serialize({"key": "value", ...})
3. nonce = random 96-bit
4. value_enc = AES-GCM(value_json, nonce, vault_key)
5. INSERT secrets row (new version if path exists)
6. Zeroize vault_key and value_json
7. Audit log: WRITE, vault_id, path, actor
```

### Flow 7 — API Token Creation
```
1. User (with vault access) creates token via GUI or API
2. Resolve vault_key for this vault (via user's ECDH path)
3. Generate: raw_token (random 32 bytes, base64url encoded, prefix "ev.")
4. Generate: token_key (random 256-bit)
5. vault_key_enc = AES-GCM(vault_key, nonce1, token_key)
6. token_key_enc = AES-GCM(token_key, nonce2, master_key_in_memory)
7. Store in api_tokens: SHA-256(raw_token), vault_key_enc, token_key_enc, allowed_paths, allowed_ips, expires_at
8. Return raw_token to user ONCE — never stored
9. Zeroize vault_key, token_key
```

### Flow 8 — API Token Read Secret
```
1. Client sends: X-Vault-Token: ev.<base64url>
2. token_hash = SHA-256(raw_token)
3. Fetch api_tokens row by token_hash
4. Validate: not revoked, not expired, source IP in allowed_ips (or vault ACL)
5. Check source IP against vault.acl_subnets / vault.acl_ips
6. Validate path against allowed_paths patterns
7. token_key = AES-GCM-decrypt(token_key_enc, nonce, master_key_in_memory)
8. vault_key = AES-GCM-decrypt(vault_key_enc, nonce, token_key)
9. Fetch latest secret version for path
10. plaintext = AES-GCM-decrypt(value_enc, nonce, vault_key)
11. Update api_tokens.last_used_at
12. Audit log: READ, vault_id, path, token_hash, source_ip
13. Zeroize vault_key, token_key, keep plaintext only for response duration
```

### Flow 9 — Revoke User Access + Key Rotation
```
1. Delete vault_user_keys row for target user
2. Generate new vault_key
3. For each secret in vault:
   a. Decrypt with old vault_key
   b. Re-encrypt with new vault_key
4. For each remaining user: re-run grant flow with new vault_key
5. For each api_token of this vault:
   a. Re-encrypt new vault_key with token_key (fetch token_key via master_key)
6. Increment key_version in all vault_user_keys rows
7. Zeroize old vault_key
```

### Flow 10 — Password Change
```
1. Verify old password (Argon2id check)
2. Derive old user_key from old password + current salt
3. Decrypt private_key using old user_key
4. Generate new 256-bit salt
5. Derive new user_key from new password + new salt
6. new_password_hash = Argon2id(new_password, new_salt)
7. Re-encrypt: private_key_enc = AES-GCM(private_key, new_nonce, new_user_key)
8. Update users: salt, password_hash, private_key_enc, private_key_nonce
9. vault_user_keys UNCHANGED — they use ECDH shared secrets, not user_key
10. Zeroize old user_key, new user_key, private_key
```

---

## Key Material in Memory

| Material | Where held | Lifetime | Protection |
|---|---|---|---|
| `master_key` | AppState (Arc<RwLock>) | Server uptime | mlock'd memory page |
| `user_key` | Temporary local var | Login request only | Zeroize after use |
| `private_key` | GUI session (memory) | Session TTL | Zeroize on session drop |
| `vault_key` | Temporary local var | Per request | Zeroize after use |
| `token_key` | Temporary local var | Per request | Zeroize after use |
| Secret plaintext | Temporary local var | Response assembly | Zeroize after serialization |

**mlock implementation for master key:**
```rust
use std::alloc::{alloc, Layout};
use libc::mlock;

// Allocate master key in mlock'd memory to prevent swap
let layout = Layout::new::<[u8; 32]>();
let ptr = unsafe { alloc(layout) };
unsafe { mlock(ptr as *const _, 32) };
```

---

## Vault API Compatibility

### Response Envelope (match Vault exactly)
```json
{
  "request_id": "uuid-v4",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {},
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

### Auth Header
`X-Vault-Token: ev.<base64url>` — EasyVault uses `ev.` prefix (Vault uses `s.`).
For strict Vault SDK compatibility mode, also accept `s.` prefix.

### Error Response
```json
{ "errors": ["permission denied"] }
```
HTTP codes: 400 bad request, 403 permission denied, 404 not found, 503 sealed/locked.

### Priority Endpoints

**Phase 1 — Core KV + Auth**
```
POST   /v1/sys/init
POST   /v1/sys/unseal
GET    /v1/sys/seal-status
GET    /v1/sys/health
POST   /v1/auth/token/create
GET    /v1/auth/token/lookup-self
POST   /v1/auth/token/revoke-self
POST   /v1/auth/token/renew-self
GET    /v1/secret/data/:path
POST   /v1/secret/data/:path
DELETE /v1/secret/data/:path
GET    /v1/secret/metadata/:path     (?list=true for directory listing)
DELETE /v1/secret/metadata/:path     (delete all versions)
```

**Phase 2 — AppRole + Policies**
```
PUT    /v1/auth/approle/role/:name
GET    /v1/auth/approle/role/:name/role-id
POST   /v1/auth/approle/role/:name/secret-id
POST   /v1/auth/approle/login
PUT    /v1/sys/policy/:name
GET    /v1/sys/policy/:name
DELETE /v1/sys/policy/:name
GET    /v1/sys/policy
```

**Phase 3 — PKI + Dynamic Secrets**
```
POST   /v1/pki/root/generate/:type
POST   /v1/pki/roles/:name
POST   /v1/pki/issue/:name
GET    /v1/pki/ca
POST   /v1/dynamic/database/config/:name
PUT    /v1/dynamic/database/roles/:name
GET    /v1/dynamic/database/creds/:name
```

**EasyVault Extensions**
```
GET    /v1/sys/health/extended       -- secret expiry stats, lease counts, vault summary
POST   /v1/sys/audit/easylog        -- configure EasyLog sink
GET    /v1/easyvault/version

# Vault management (GUI and admin API)
POST   /ev/vaults                   -- create vault
GET    /ev/vaults                   -- list vaults
GET    /ev/vaults/:id
PATCH  /ev/vaults/:id               -- update ACL, description
POST   /ev/vaults/:id/lock
POST   /ev/vaults/:id/users         -- grant user access
DELETE /ev/vaults/:id/users/:uid    -- revoke user access (triggers key rotation)
POST   /ev/vaults/:id/tokens        -- create API token
DELETE /ev/vaults/:id/tokens/:tid   -- revoke API token

# User management
POST   /ev/users                    -- create user (master only)
GET    /ev/users
PATCH  /ev/users/:id
POST   /ev/users/:id/password

# Web GUI
GET    /gui/                        -- dashboard
POST   /gui/login
POST   /gui/logout
```

---

## IP/Subnet ACL Enforcement

ACL is enforced at two levels:

1. **Vault-level ACL** — applies to all access (GUI and API) to that vault
2. **Token-level ACL** — additional restriction on a specific API token (subset of vault ACL)

```rust
// Middleware pseudocode
fn check_vault_acl(vault: &Vault, source_ip: IpAddr) -> Result<(), AppError> {
    if vault.acl_subnets.is_empty() && vault.acl_ips.is_empty() {
        return Ok(()); // no restriction
    }
    let allowed = vault.acl_ips.contains(&source_ip)
        || vault.acl_subnets.iter().any(|net| net.contains(&source_ip));
    if !allowed {
        return Err(AppError::Forbidden("source IP not permitted"));
    }
    Ok(())
}
```

Use `ipnet` crate for subnet matching. Extract real client IP from `X-Forwarded-For` header
when behind a reverse proxy (Traefik), with configurable trusted proxy list.

---

## Web GUI

Minimal, functional management UI. Not a React SPA — server-rendered HTML with minimal JS
(HTMX or plain fetch calls) for simplicity and to keep the binary self-contained.

Pages:
- `/gui/login` — username + password, brute-force protected (5 attempts → 15min lockout)
- `/gui/dashboard` — vault list, system health, recent audit events
- `/gui/vaults/:id` — secret browser, user access list, token list
- `/gui/vaults/:id/secrets/:path` — view/edit secret (shows current version + history)
- `/gui/vaults/:id/tokens/new` — create API token (set paths, IPs, TTL)
- `/gui/users` — user management (master only)
- `/gui/audit` — audit log viewer with filters

Session: cookie-based (`ev_session`), 8h TTL by default, configurable.
Brute force: track failed attempts per IP + per username in memory (or DB).

---

## Config (`config.toml`)

```toml
[server]
address = "0.0.0.0"
port = 8200                        # match Vault default
tls = true
tls_cert = ""                      # empty = auto self-signed
tls_key = ""

[storage]
type = "sqlite"                    # or "postgres"
path = "./easyvault.db"
url = ""                           # postgres DSN

[security]
session_ttl_hours = 8
max_login_attempts = 5
lockout_minutes = 15
trusted_proxies = ["127.0.0.1"]   # for X-Forwarded-For

[audit]
enabled = true
log_raw_values = false             # NEVER set to true in production
easylog_url = ""

[init]
default_key_shares = 5
default_key_threshold = 3
```

---

## Development Notes

- `AppState` holds: db pool, `Arc<RwLock<Option<MasterKey>>>` (None when sealed), config
- Master key type must `#[derive(Zeroize, ZeroizeOnDrop)]`
- All handlers receive `State<Arc<AppState>>`
- Middleware stack (inner to outer): audit → IP ACL → token auth → handler
- Token auth skips: `/v1/sys/health`, `/v1/sys/seal-status`, `/v1/sys/init`, `/v1/sys/unseal`, `/gui/*`
- All `/ev/*` routes require GUI session or master token
- Use `sqlx::migrate!()` at startup
- Secret versioning: always INSERT new version, never UPDATE value_enc
- Path patterns in allowed_paths: support `*` wildcard, e.g. `"db/*"` matches `"db/postgres/pass"`

---

## Key Design Principles

1. **Vault compatibility first** — match Vault's API behavior exactly where applicable
2. **Envelope encryption** — vault_key never stored plaintext, distributed per-user via ECDH
3. **Fail closed** — deny by default on ACL, policy, and sealed state
4. **Sealed = 503** — master key not in memory = no secret operations possible
5. **Never log secret values** — audit logs paths, actors, timestamps only
6. **Zeroize everything** — all key material structs use `ZeroizeOnDrop`
7. **mlock master key** — prevent OS from swapping master key to disk
8. **Idempotent writes** — new version on every write, never overwrite
9. **Immediate revocation** — token revoke is effective instantly via `revoked` flag check

---

## Related Projects (Easy* family)
- **OpenSCM** — security compliance platform (Rust/Axum) — yariv@openscm.io
- **EasyLog** — log management (EasyVault audit sink target)
- **EasyDC** — data center management
- **EasyNAS** — network attached storage
