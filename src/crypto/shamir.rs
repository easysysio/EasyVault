// =============================================================================
// crypto/shamir.rs — master-key splitting and reconstruction (unseal ceremony)
//
// At init the 256-bit master key is split into N Shamir shares with a recovery
// threshold T. Shares are handed to operators and never stored. At unseal the
// operator submits T shares and the master key is reconstructed in memory.
// =============================================================================

use blahaj::{Share, Sharks};
use zeroize::Zeroizing;

/// Error wrapping the blahaj crate's reconstruction failures.
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

    /// Shares issued by the `sharks` 0.5 crate (EasyVault ≤ 0.1.6) must still
    /// unseal after the move to `blahaj`. Vector: secret 0x00..=0x1f, 3-of-5.
    #[test]
    fn shares_from_sharks_still_recover() {
        let issued = [
            "010993d7e04944746d138757995967c5b290fcdb1151fd2b2568d30766533a8996",
            "02fc82385f44da51c15b919c628ecbd1162d29ecb373c90aa89089a654b454d939",
            "03f510edbc099b23ab401fc1f0dba11aabadc425b13621379ae043bb29fb734eb0",
            "047ac8789dcbcf5ede277a8b84b5d4e0d8eaba2ae449f4ab3fa8405d6b89937af7",
            "05735aad7e868e2cb43cf4d616e0be2b656a57e3e60c1c960dd88a4016c6b4ed7e",
        ];
        let decode = |h: &str| (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>();
        let secret: Vec<u8> = (0u8..32).collect();
        for subset in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]] {
            let picked: Vec<Vec<u8>> = subset.iter().map(|&i| decode(issued[i])).collect();
            assert_eq!(combine(3, &picked).unwrap().as_slice(), secret.as_slice());
        }
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
