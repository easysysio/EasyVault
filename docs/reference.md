# API reference

EasyVault speaks a subset of the HashiCorp Vault HTTP API, so Vault clients and
scripts that use token auth, AppRole and KV v2 work against it with little or no
change. Everything else — creating vaults, users, tokens and AppRoles — happens
in the Web GUI.

## Conventions

- **Authentication** — send the token in the `X-Vault-Token` header. EasyVault
  tokens start with `ev.` (Vault's own start with `s.` or `hvs.`).
- **Request bodies** — JSON, with `Content-Type: application/json`.
- **Responses** — Vault's envelope: `request_id`, `lease_id`, `renewable`,
  `lease_duration`, `data`, `wrap_info`, `warnings`, `auth`.
- **Errors** — `{"errors": ["permission denied"]}` with the HTTP status below.

| Status | Meaning |
|---|---|
| `400` | Malformed request |
| `403` | Missing, expired or revoked token; path or client IP not allowed; write with a read-only token |
| `404` | No such secret (or it was deleted, destroyed or burned) |
| `503` | The instance is sealed or not yet initialized |

## System

No token required.

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/sys/init` | Initialize: `{"secret_shares":5,"secret_threshold":3}`. Returns the unseal shares, once. |
| `POST` | `/v1/sys/unseal` | Submit one share: `{"key":"<share>"}`. Repeat until the threshold is met. |
| `GET` | `/v1/sys/seal-status` | `initialized`, `sealed`, threshold, shares and unseal progress. |
| `GET` | `/v1/sys/health` | `200` unsealed · `503` sealed · `501` not initialized. |

## Token auth

| Method | Path | Description |
|---|---|---|
| `GET` / `POST` | `/v1/auth/token/lookup-self` | Metadata for the calling token: name, allowed paths, TTL, expiry, vault. |
| `POST` | `/v1/auth/token/renew-self` | Extend a renewable token by `increment` seconds, or by its own TTL. |
| `POST` | `/v1/auth/token/revoke-self` | Revoke the calling token (`204`). |

Tokens themselves are created in the GUI — see [API tokens](secrets.md#api-tokens).

## AppRole

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/auth/approle/login` | Exchange `{"role_id":"…","secret_id":"…"}` for a token in the `auth` block. |

Roles and secret-ids are managed in the GUI — see [AppRole](secrets.md#approle-ci-automation).

## KV v2

The KV engine is mounted at `secret/`. Every call needs a token for the vault
that holds the path.

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/secret/data/<path>` | Read the latest version: `data.data` and `data.metadata` (`version`, `destroyed`, `reads_remaining`). |
| `POST` | `/v1/secret/data/<path>` | Write a new version: `{"data":{…}}`, optionally `"options":{"max_reads":N}`. |
| `DELETE` | `/v1/secret/data/<path>` | Soft-delete the latest version. |
| `GET` | `/v1/secret/metadata/<prefix>/?list=true` | List the keys under a prefix (`/v1/secret/metadata?list=true` for the root). Keep the trailing slash so a `db/*` token matches `db/`. |

## Differences from HashiCorp Vault

- **One KV mount per vault.** The mount is always `secret/`; the token decides
  which vault it reads from.
- **No policy language.** A token or AppRole is scoped by allowed paths,
  allowed IPs / CIDRs, a TTL and read-only or read-write access, set when it is
  issued.
- **No token-create endpoint.** Tokens are minted in the GUI, or by an AppRole
  login.
- **Burn after read.** `options.max_reads` is an EasyVault extension.

!!! note "Roadmap"
    **PKI** (a CA and certificate issuance) and **dynamic database credentials**
    are planned. The KV secrets engine, per-vault tokens, AppRole and token
    self-management are available today.
