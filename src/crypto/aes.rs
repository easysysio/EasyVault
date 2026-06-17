// =============================================================================
// crypto/aes.rs — AES-256-GCM authenticated encryption helpers
//
// Every secret, vault key, token key and private key in EasyVault is sealed
// with one of these two functions. Each call generates a fresh random nonce;
// callers store (nonce, ciphertext) together.
// =============================================================================

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use super::{KEY_LEN, NONCE_LEN, random_bytes};

/// Error returned when AEAD sealing or opening fails (bad key, tampered data).
#[derive(Debug, thiserror::Error)]
pub enum AesError {
    #[error("AES-GCM encryption failed")]
    Encrypt,
    #[error("AES-GCM decryption failed (wrong key or tampered ciphertext)")]
    Decrypt,
}

// ─────────────────────────────────────────────────────────────────────────────
// encrypt
// Seal `plaintext` under a 256-bit `key`, returning (nonce, ciphertext).
// The nonce is random per call and must be stored alongside the ciphertext.
// ─────────────────────────────────────────────────────────────────────────────
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>), AesError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| AesError::Encrypt)?;
    Ok((nonce_bytes, ciphertext))
}

// ─────────────────────────────────────────────────────────────────────────────
// decrypt
// Open a ciphertext sealed by `encrypt`, given the same key and stored nonce.
// Fails (Decrypt) if the key is wrong or the ciphertext/tag was modified.
// ─────────────────────────────────────────────────────────────────────────────
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AesError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|_| AesError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_key;

    #[test]
    fn round_trip_recovers_plaintext() {
        let key = random_key();
        let msg = b"super secret value";
        let (nonce, ct) = encrypt(&key, msg).unwrap();
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn wrong_key_fails() {
        let key = random_key();
        let other = random_key();
        let (nonce, ct) = encrypt(&key, b"x").unwrap();
        assert!(decrypt(&other, &nonce, &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = random_key();
        let (nonce, mut ct) = encrypt(&key, b"hello").unwrap();
        ct[0] ^= 0xff;
        assert!(decrypt(&key, &nonce, &ct).is_err());
    }
}
