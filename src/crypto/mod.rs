// =============================================================================
// crypto/mod.rs — cryptographic primitives for EasyVault's envelope encryption
//
// Submodules:
//   aes    — AES-256-GCM authenticated encryption (the envelope sealer)
//   argon2 — password hashing + user-key derivation (two separate derivations)
//   ecdh   — X25519 keypair generation + shared-secret derivation
//   shamir — master-key splitting / reconstruction for the unseal ceremony
//
// All key material is held in zeroizing wrappers; nothing here logs secrets.
// =============================================================================

pub mod aes;
pub mod argon2;
pub mod ecdh;
pub mod shamir;

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Length of an AES-256 / master / vault / token key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of an AES-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;

// ─────────────────────────────────────────────────────────────────────────────
// random_bytes
// Fill a fixed-size array with cryptographically secure random bytes.
// ─────────────────────────────────────────────────────────────────────────────
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

// ─────────────────────────────────────────────────────────────────────────────
// random_key
// Generate a fresh 256-bit symmetric key (vault key, token key, master key).
// ─────────────────────────────────────────────────────────────────────────────
pub fn random_key() -> [u8; KEY_LEN] {
    random_bytes::<KEY_LEN>()
}

// ─────────────────────────────────────────────────────────────────────────────
// sha256_hex
// Lowercase-hex SHA-256 digest, used to store session/token lookup hashes.
// ─────────────────────────────────────────────────────────────────────────────
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
