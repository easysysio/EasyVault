-- =============================================================================
-- 002_roles_escrow.sql — per-vault roles and master-key vault-key escrow
--
-- Adds a per-vault role to each membership row and stores each vault key sealed
-- under the master key, so the (unsealed) server can re-wrap it for users that
-- the blind master assigns — without master ever holding a readable copy.
-- =============================================================================

-- Per-vault role: 'admin' | 'editor' | 'viewer'. Existing rows default to admin.
ALTER TABLE vault_user_keys ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';

-- Master-key escrow of the vault key: AES-GCM(vault_key, master_key).
ALTER TABLE vaults ADD COLUMN vault_key_enc_master BLOB;
ALTER TABLE vaults ADD COLUMN vault_key_nonce_master BLOB;
