// =============================================================================
// crypto/argon2.rs — password hashing and user-key derivation
//
// From the SAME (password, salt) we derive two independent 32-byte outputs:
//   * password_hash — stored, used only to verify login
//   * user_key      — never stored, used to decrypt the user's X25519 private key
// Domain-separation tags on the input guarantee the two outputs differ.
// =============================================================================

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use super::KEY_LEN;

/// Salt length in bytes (stored per-user as a BLOB).
pub const SALT_LEN: usize = 32;

/// Domain-separation prefix for the login-verification hash.
const PWHASH_CONTEXT: &[u8] = b"easyvault:pwhash:v1:";
/// Domain-separation prefix for the crypto key-derivation output.
const USERKEY_CONTEXT: &[u8] = b"easyvault:userkey:v1:";

/// Error raised when Argon2 derivation fails (only on pathological params).
#[derive(Debug, thiserror::Error)]
#[error("argon2 derivation failed")]
pub struct Argon2Error;

// ─────────────────────────────────────────────────────────────────────────────
// argon2id
// Construct the Argon2id hasher with EasyVault's fixed parameters so that
// every derivation across the codebase is reproducible.
// ─────────────────────────────────────────────────────────────────────────────
fn argon2id() -> Argon2<'static> {
    // 19 MiB, 2 passes, 1 lane — OWASP-recommended baseline for Argon2id.
    let params = Params::new(19 * 1024, 2, 1, Some(KEY_LEN)).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

// ─────────────────────────────────────────────────────────────────────────────
// derive
// Internal helper: hash `context || password` with `salt` into 32 bytes.
// ─────────────────────────────────────────────────────────────────────────────
fn derive(context: &[u8], password: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], Argon2Error> {
    let mut input = Vec::with_capacity(context.len() + password.len());
    input.extend_from_slice(context);
    input.extend_from_slice(password);
    let mut out = [0u8; KEY_LEN];
    argon2id()
        .hash_password_into(&input, salt, &mut out)
        .map_err(|_| Argon2Error)?;
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// password_hash
// Derive the stored login-verification hash from (password, salt).
// ─────────────────────────────────────────────────────────────────────────────
pub fn password_hash(password: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], Argon2Error> {
    derive(PWHASH_CONTEXT, password, salt)
}

// ─────────────────────────────────────────────────────────────────────────────
// verify_password
// Constant-time check of a candidate password against the stored hash.
// ─────────────────────────────────────────────────────────────────────────────
pub fn verify_password(password: &[u8], salt: &[u8], expected: &[u8]) -> bool {
    match password_hash(password, salt) {
        Ok(got) => constant_time_eq(&got, expected),
        Err(_) => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// derive_user_key
// Derive the in-memory user_key used to unlock the user's private key.
// Wrapped in Zeroizing so it is wiped when the binding is dropped.
// ─────────────────────────────────────────────────────────────────────────────
pub fn derive_user_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Argon2Error> {
    Ok(Zeroizing::new(derive(USERKEY_CONTEXT, password, salt)?))
}

// ─────────────────────────────────────────────────────────────────────────────
// constant_time_eq
// Length-checked, branch-free byte comparison to avoid timing leaks.
// ─────────────────────────────────────────────────────────────────────────────
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pwhash_and_userkey_differ_for_same_input() {
        let salt = [7u8; SALT_LEN];
        let pw = b"correct horse battery staple";
        let h = password_hash(pw, &salt).unwrap();
        let k = derive_user_key(pw, &salt).unwrap();
        assert_ne!(&h, k.as_ref(), "domain separation must change the output");
    }

    #[test]
    fn derivation_is_deterministic() {
        let salt = [9u8; SALT_LEN];
        let pw = b"hunter2";
        assert_eq!(password_hash(pw, &salt).unwrap(), password_hash(pw, &salt).unwrap());
    }

    #[test]
    fn verify_accepts_correct_rejects_wrong() {
        let salt = [3u8; SALT_LEN];
        let h = password_hash(b"swordfish", &salt).unwrap();
        assert!(verify_password(b"swordfish", &salt, &h));
        assert!(!verify_password(b"swordfis", &salt, &h));
    }
}
