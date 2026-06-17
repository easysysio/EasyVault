// =============================================================================
// crypto/shamir.rs — master-key splitting and reconstruction (unseal ceremony)
//
// At init the 256-bit master key is split into N Shamir shares with a recovery
// threshold T. Shares are handed to operators and never stored. At unseal the
// operator submits T shares and the master key is reconstructed in memory.
// =============================================================================

use sharks::{Share, Sharks};
use zeroize::Zeroizing;

/// Error wrapping the sharks crate's reconstruction failures.
#[derive(Debug, thiserror::Error)]
pub enum ShamirError {
    #[error("invalid share encoding")]
    BadShare,
    #[error("could not recover secret: {0}")]
    Recover(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// split
// Split `secret` into `shares` pieces, any `threshold` of which can recover it.
// Returns the raw share bytes for the caller to encode and distribute.
// ─────────────────────────────────────────────────────────────────────────────
pub fn split(secret: &[u8], shares: u8, threshold: u8) -> Vec<Vec<u8>> {
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    dealer.take(shares as usize).map(|s| Vec::from(&s)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// combine
// Reconstruct the secret from `threshold` share byte-slices.
// Returns a zeroizing buffer so the recovered key is wiped on drop.
// ─────────────────────────────────────────────────────────────────────────────
pub fn combine(threshold: u8, share_bytes: &[Vec<u8>]) -> Result<Zeroizing<Vec<u8>>, ShamirError> {
    let mut shares = Vec::with_capacity(share_bytes.len());
    for raw in share_bytes {
        let share = Share::try_from(raw.as_slice()).map_err(|_| ShamirError::BadShare)?;
        shares.push(share);
    }
    let sharks = Sharks(threshold);
    let secret = sharks
        .recover(shares.iter())
        .map_err(|e| ShamirError::Recover(e.to_string()))?;
    Ok(Zeroizing::new(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_shares_recover_secret() {
        let secret = [42u8; 32];
        let shares = split(&secret, 5, 3);
        assert_eq!(shares.len(), 5);
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = combine(3, &subset).unwrap();
        assert_eq!(recovered.as_slice(), &secret);
    }

    #[test]
    fn below_threshold_does_not_recover() {
        let secret = [7u8; 32];
        let shares = split(&secret, 5, 3);
        let subset = vec![shares[0].clone(), shares[1].clone()];
        // With fewer than threshold shares the recovered value must not match.
        match combine(3, &subset) {
            Ok(recovered) => assert_ne!(recovered.as_slice(), &secret),
            Err(_) => {}
        }
    }
}
