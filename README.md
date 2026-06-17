# EasyVault

Self-hosted, HashiCorp Vault–compatible secrets manager written in Rust.

Secrets never touch client storage — servers hold only a short-lived API token
and fetch secrets at runtime over a Vault-compatible REST API. Everything is
sealed with envelope encryption: each vault has its own key, distributed
per-user via X25519 ECDH, and the master key lives only in memory (unseal with
Shamir shares). See [`CLAUDE.md`](CLAUDE.md) for the full design.

> **Status:** early development. v0.1.0 boots **sealed** and supports the
> init / unseal lifecycle. Users, vaults, KV secrets, and API tokens are next.
> See [`CHANGELOG.md`](CHANGELOG.md).

## Quick start

```bash
cp config.toml.example config.toml      # optional — sensible defaults otherwise
cargo run                               # listens on 0.0.0.0:8200, starts sealed

# Initialize (returns Shamir shares — shown ONCE, store them safely)
curl -s -X POST localhost:8200/v1/sys/init \
  -H 'Content-Type: application/json' \
  -d '{"secret_shares":5,"secret_threshold":3}'

# Unseal by submitting threshold-many shares (one call per share)
curl -s -X POST localhost:8200/v1/sys/unseal \
  -H 'Content-Type: application/json' -d '{"key":"<share>"}'

curl -s localhost:8200/v1/sys/health    # 200 once unsealed
```

## Build & test

```bash
cargo build
cargo test            # crypto primitives have unit tests
```

## Tech

Rust · Axum · SQLite (sqlx) · AES-256-GCM · Argon2id · X25519 · Shamir · zeroize

Part of the Easy* self-hosted family (OpenSCM, EasyLog, EasyDC, EasyNAS).
MIT licensed.
