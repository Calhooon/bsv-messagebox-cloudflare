//! Synthetic-identity generation via bsv-rs ProtoWallet.
//!
//! Each ProtoWallet is a fresh, self-contained BSV identity with its
//! own secp256k1 keypair. No SQLite, no HTTP, no port-3321 wallet
//! dependency — pure crypto in-process. This is the unlock that makes
//! 10k-identity load tests cheap and deterministic.

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;

/// Generate `n` synthetic identities. Each `ProtoWallet` carries a
/// freshly-random root private key.
pub fn generate_n(n: usize) -> Vec<ProtoWallet> {
    (0..n)
        .map(|_| ProtoWallet::new(Some(PrivateKey::random())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_identity_is_distinct() {
        let wallets = generate_n(8);
        let mut keys: Vec<String> = wallets.iter().map(|w| w.identity_key_hex()).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 8, "every ProtoWallet must have a unique identity key");
    }
}
