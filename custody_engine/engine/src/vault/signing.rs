

use frost_ed25519::prelude::*;
use frost_ed25519::round1::generate_nonce;
use frost_core::Group;
use frost_ed25519::SigningNonces;

use rand_core::OsRng;
use base64;
use bincode;

use frost_ed25519::round2::sign;
use frost_ed25519::keys::{SigningPackage, SecretShare};
use zeroize::Zeroizing;

/// Generates a new FROST nonce and stores the sealed result in the vault
pub fn generate_nonce(
    registry: &OperationalDIDRegistry,
    op_did: &str,
) -> Result<Vec<u8>, String> {
    let shard_b64 = get_shard(registry, op_did)?;
    let shard_bytes = base64::decode(&shard_b64).map_err(|_| "bad base64")?;
    let _share = frost_ed25519::keys::SecretShare::deserialize(&shard_bytes)
        .map_err(|_| "bad shard")?;

    let mut rng = rand_core::OsRng;
    let nonces = Zeroizing::new(generate_nonce(&mut rng));
    let commitment = nonces.commitment.serialize();

    // 🔐 Serialize and store securely in vault
    let encoded = bincode::serialize(&*nonces).map_err(|_| "serialize failed")?;
    set_nonce(registry, op_did, encoded)?;

    Ok(commitment)
}

/// Uses stored share + nonce to compute a real signature share
pub fn partial_sign(
    registry: &OperationalDIDRegistry,
    op_did: &str,
    message: &[u8],
    incoming_commitments: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, String> {
    let shard_b64 = get_shard(registry, op_did)?;
    let shard_bytes = base64::decode(&shard_b64).map_err(|_| "bad base64")?;
    let share = SecretShare::deserialize(&shard_bytes).map_err(|_| "bad shard")?;

    let nonce_bytes = get_nonce(registry, op_did)?;
    let nonces: SigningNonces = bincode::deserialize(&nonce_bytes).map_err(|_| "bad nonce format")?;

    let mut commitments = HashMap::new();
    for (peer_id, raw) in incoming_commitments {
        let id = Identifier::try_from(peer_id.as_bytes()).map_err(|_| "bad id")?;
        let c = frost_ed25519::keys::NonceCommitment::deserialize(raw).map_err(|_| "bad commitment")?;
        commitments.insert(id, c);
    }

    let signing_pkg = SigningPackage::new(message.to_vec(), commitments);
    let sig = sign(&signing_pkg, &share, &nonces)
        .map_err(|e| format!("signing failed: {e:?}"))?;

    Ok(sig.to_bytes().to_vec())
}