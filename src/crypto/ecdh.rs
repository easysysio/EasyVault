// =============================================================================
// crypto/ecdh.rs — X25519 keypair generation and shared-secret derivation
//
// Vault keys are distributed per-user by encrypting them under an X25519 ECDH
// shared secret. A user encrypts to themselves (self-ECDH) when they own a
// vault, or to another user's public key when granting access.
// =============================================================================

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::KEY_LEN;

/// Length of an X25519 public or private key in bytes.
pub const X25519_LEN: usize = 32;

/// A freshly generated X25519 keypair (raw bytes, ready to store/seal).
pub struct Keypair {
    pub public: [u8; X25519_LEN],
    pub private: Zeroizing<[u8; X25519_LEN]>,
}

// ─────────────────────────────────────────────────────────────────────────────
// generate_keypair
// Create a new X25519 keypair using the OS CSPRNG.
// ─────────────────────────────────────────────────────────────────────────────
pub fn generate_keypair() -> Keypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    Keypair {
        public: public.to_bytes(),
        private: Zeroizing::new(secret.to_bytes()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// shared_secret
// Derive the 32-byte ECDH shared secret between `private` and `public`.
// Self-ECDH (own private + own public) is the owner's vault-key wrapping path.
// ─────────────────────────────────────────────────────────────────────────────
pub fn shared_secret(
    private: &[u8; X25519_LEN],
    public: &[u8; X25519_LEN],
) -> Zeroizing<[u8; KEY_LEN]> {
    let secret = StaticSecret::from(*private);
    let public = PublicKey::from(*public);
    let shared = secret.diffie_hellman(&public);
    Zeroizing::new(shared.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_is_symmetric() {
        let a = generate_keypair();
        let b = generate_keypair();
        let ab = shared_secret(&a.private, &b.public);
        let ba = shared_secret(&b.private, &a.public);
        assert_eq!(ab.as_ref(), ba.as_ref());
    }

    #[test]
    fn self_ecdh_is_stable() {
        let a = generate_keypair();
        let s1 = shared_secret(&a.private, &a.public);
        let s2 = shared_secret(&a.private, &a.public);
        assert_eq!(s1.as_ref(), s2.as_ref());
    }

    #[test]
    fn different_pairs_differ() {
        let a = generate_keypair();
        let b = generate_keypair();
        let c = generate_keypair();
        let ab = shared_secret(&a.private, &b.public);
        let ac = shared_secret(&a.private, &c.public);
        assert_ne!(ab.as_ref(), ac.as_ref());
    }
}
