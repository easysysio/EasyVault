# Changelog

All notable changes to EasyVault are documented here.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] — 2026-06-17

First foundation increment: a Vault-compatible server that boots **sealed** and
can be initialized and unsealed.

### Added
- **Project skeleton** — Cargo (edition 2024), Axum 0.8, SQLite via sqlx 0.8.
- **Config** (`config.rs`) — TOML loading via `$EASYVAULT_CONFIG` (default
  `./config.toml`); all fields default so a missing file still works.
- **Crypto primitives** (`crypto/`) with unit tests:
  - `aes` — AES-256-GCM seal/open with per-call random nonces.
  - `argon2` — Argon2id password hashing **and** user-key derivation from the
    same salt, domain-separated so the two outputs differ.
  - `ecdh` — X25519 keypair generation + shared-secret derivation.
  - `shamir` — master-key split / threshold reconstruction (sharks).
- **Storage** (`storage/sqlite.rs`) — pool creation, foreign keys, embedded
  migrations.
- **Schema** (`migrations/001_initial.sql`) — `system_init`, `users`, `vaults`,
  `vault_user_keys`, `secrets`, `api_tokens`, `gui_sessions`, `policies`,
  `audit_log`.
- **AppState + MasterKey** (`state.rs`) — shared state holding the SQLite pool,
  config, and the in-memory master key (`ZeroizeOnDrop`, best-effort `mlock`).
- **Error envelope** (`error.rs`) — Vault-compatible `{"errors":[…]}` responses.
- **Response envelope** (`api/response.rs`) — `VaultResponse<T>`.
- **System endpoints** (`api/routes/sys.rs`):
  - `POST /v1/sys/init` — generate master key, Shamir-split, return shares once.
  - `POST /v1/sys/unseal` — accumulate shares, reconstruct + verify, unseal.
  - `GET  /v1/sys/seal-status` — initialized / sealed / share progress.
  - `GET  /v1/sys/health` — 200 active, 503 sealed, 501 uninitialized.

### Verified
- 11 crypto unit tests pass.
- End-to-end: pre-init `health` 501 → `init` (3-of-5) → sealed `health` 503 →
  three-share `unseal` → `health` 200; re-init rejected with 400.

[0.1.0]: https://github.com/yarivha/EasyVault/releases/tag/v0.1.0
