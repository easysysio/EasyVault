-- =============================================================================
-- 007_token_writable.sql — read-only vs read-write tokens / AppRoles
--
-- `writable` = 1 lets the credential write/delete secrets; 0 makes it read-only
-- (reads still allowed within its path/IP ACL). Existing rows default to
-- writable for backward compatibility.
-- =============================================================================

ALTER TABLE api_tokens ADD COLUMN writable BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE approles   ADD COLUMN writable BOOLEAN NOT NULL DEFAULT 1;
