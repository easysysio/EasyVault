-- =============================================================================
-- 003_token_renew.sql — token renewal support
--
-- `renew_period` is the TTL (seconds) a renewable token's lifetime is extended
-- by on renew-self. Tokens created with a TTL are renewable; NULL = no renewal.
-- =============================================================================

ALTER TABLE api_tokens ADD COLUMN renew_period INTEGER;
