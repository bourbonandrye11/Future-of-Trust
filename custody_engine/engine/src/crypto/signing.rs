//! Handles nonce generation, partial signing, and signature share aggregation.

use ed25519_dalek::{VerifyingKey, Signature};
use sha2::{Sha512, Digest};

/// Verify a signature against a message and public key.
pub fn verify_signature(
    pubkey_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), String> {
    let pubkey = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|e| format!("Invalid public key: {:?}", e))?;

    let signature = Signature::from_bytes(signature_bytes)
        .map_err(|e| format!("Invalid signature format: {:?}", e))?;

    let hash = Sha512::digest(message);

    pubkey.verify_prehashed(
        Some(ed25519_dalek::SignatureDigest::default()),
        &hash,
        &signature,
    ).map_err(|e| format!("Signature verification failed: {:?}", e))
}
