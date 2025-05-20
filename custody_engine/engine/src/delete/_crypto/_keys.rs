//! Handles key generation, custody shard serialization, and deserialization.

use frost_ed25519::keys::{generate_with_dealer, Identifier};
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::parameters::FrostEd25519;
use rand::rngs::OsRng;

use crate::types::{CustodyShard, ShardId};
use crate::vault::Vault;
use crate::error::CustodyError;

/// Generate a new FROST key set and return sealed custody shards and group public key.
///
/// Returns a tuple of:
/// - `Vec<Vec<u8>>`: Sealed custody shards
/// - `Vec<u8>`: Group public key bytes

pub fn generate_and_seal_key_shards(
    threshold: usize,
    participants: usize
) -> Result<(Vec<Vec<u8>>, Vec<u8>), CustodyError> {
    // step 1: Initialize secure randomness source
    let mut rng = OsRng; 

    // step 2: Run FROST Dealer-based key generation
    let (key_packages, public_key_package) = 
        generate_with_dealer(threshold, participants, &mut rng)
        .map_err(|e| CustodyError::MPCError(format!("keygen failed: {:?}", e)))?;

    //step 3: Create sealed custody shards
    let mut sealed_shards = Vec::new();

    for (identifier, key_package) in key_packages { 
        let shard = CustodyShard { 
            id: ShardId(identifier.serialize()),
            pubkey: key_package.public.share.to_bytes().to_vec(),
            share: bincode::serialize(&key_package)
                .map_err(|e| CustodyError::VaultError(format!("Serialization failed: {:?}", e)))?,
        };

        //step 4: seal the shard (for real TEE storage later) 
        let sealed = Vault::seal(&shard)?;
        sealed_shards.push(sealed);
        }

        //step 5: Serialize the group public key for later use
        let group_pubkey_bytes = public_key_package.group_public.to_bytes().to_vec();

        Ok((sealed_shards, group_pubkey_bytes))
}

/// Unseal a custody shard and deserialize into a usable KeyPackage.
pub fn unseal_and_load_key_package(
    sealed: &[u8],
) -> Result<KeyPackage<FrostEd25519>, CustodyError> {
let custody_shard = Vault::unseal(sealed_shard)?;
let key_package: KeyPackage<FrostEd25519> =
    bincode::deserialize(&custody_shard.share)
        .map_err(|e| CustodyError::VaultError(format!("Shard deserialize failed: {:?}", e)))?;

        Ok(key_package)
}