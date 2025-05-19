/// This was the original backend that we built and needed refactoring.
/// made a few updates and then decided to implement new files. 
/// keeping this for records for now but can be deleted later. 
/// updated file is vault/backend/simulated.rs

use crate::types::CustodyShard; // The MPC shard struct we encrypt
use crate::types::VaultRecord;
use crate::error::CustodyError; // Our centralized error type
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use bincode; // Binary serializer
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-256-GCM encryption primitive
use aes_gcm::aead::{Aead, KeyInit}; // Traits for using AES-GCM securely
use rand::RngCore; // For generating random keys/nonces
use zeroize::Zeroizing; // Secure memory wipe when dropped
use serde_json;
use crate::vault::*;

/// Trait for pluggable secure vault sealing (TEE, simulated, or mock).
/// might separate out the trait to vault/backend/mod.rs
pub trait VaultBackend: Send + Sync {
    /// seal a custody shard securely.
    fn store_record(&self, vault_id: &str, record: &VaultRecord) -> Result<(), String>;
    // Original fn commenting out for now to replace with refactor
    //fn seal(&self, shard: &CustodyShard) -> Result<Vec<u8>, CustodyError>;

    /// Unseal a custody shard securely.
    fn load_record(&self, vault_id: &str) -> Result<VaultRecord, String>;
    // Original fn commenting out for now to replace with refactor
    //fn unseal(&self, data: &[u8]) -> Result<CustodyShard, CustodyError>;
}

/// This gives us a runtime-pluggable vault implementation interface.

/// add MemoryVaultBackend to the list of vaults for non-encrypted serialization.
pub struct MemoryVaultBackend;

impl VaultBackend for MemoryVaultBackend {
    fn seal(&self, shard: &CustodyShard) -> Result<Vec<u8>, CustodyError> {
        // Serialize the shard to a byte vector
        bincode::serialize(shard)
            .map_err(|e| CustodyError::SerdeError(format!("Sealing shard failed: {:?}", e)))
    }

    fn unseal(&self, data: &[u8]) -> Result<CustodyShard, CustodyError> {
        // Deserialize the byte vector back into a custody shard
        bincode::deserialize(data)
            .map_err(|e| CustodyError::SerdeError(format!("Deserialization failed: {:?}", e)))
    }
}

/// Sealed vault blob, encrypted using AES-GCM
struct SealedBlob {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}

/// Simulated TEE vault that encrypts data using AES-256-GCM.
/// This acts like an enclave: secrets only exist inside this struct.
pub struct SimulatedTEEBackend {
    store: Arc<RwLock<HashMap<String, SealedBlob>>>,
    cipher: Aes256Gcm,
    /// This key simulates what would be generated/stored in SGX or TrustZone.
    /// It is wrapped in Zeroizing to auto-clear memory when dropped.
    // refactored code commented below out.
    //key: Zeroizing<[u8; 32]>,
}

impl SimulatedTEEBackend {
    /// Create a new simulated TEE with a fresh key (ephemeral).
    /// In a real TEE, this would come from sealed enclave memory.
    pub fn new() -> Self {
        let mut key = [0u8; 32]; // Allocate 32-byte array (256-bit key)
        rand::thread_rng().fill_bytes(&mut key);  // Fill it with secure random bytes
        Self {
            key: Zeroizing::new(key), // Wrap key to auto-zero on drop
        }
    }
}

impl VaultBackend for SimulatedTEEBackend {
    /// Encrypt the serialized CustodyShard using AES-GCM.
    fn seal(&self, shard: &CustodyShard) -> Result<Vec<u8>, CustodyError> {
        // Step 1: Serialize the shard into bytes
        let plaintext = bincode::serialize(shard)
            .map_err(|e| CustodyError::SerdeError(format!("Sealing shard failed: {:?}", e)))?;

            // AEAD encyrption: encrypts + authenticates in one shot
            // Step 2: Create AES-256-GCM cipher instance from our key
        let cipher = Aes256Gcm::new(Key::from_slice(&self.key));

        // Step 3: Generate a random 12-byte nonce (GCM standard)
        let nonce = rand:random::<[u8, 12]>(); // 96-bit GMC nonce
        // Step 4: Encrypt the plaintext using the cipher + nonce
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|e| CustodyError::CryptoError(format!("Encryption failed: {:?}", e)))?;

        // Step 5: Combine nonce + ciphertext into a single byte array
        let mut sealed = nonce.to_vec(); // nonce goes first (needed for decrypt)
        sealed.extend(ciphertext); // then encrypted payload
        Ok(sealed) // Return combined sealed blob
    }

    /// Decrypt and deserialize a sealed CustodyShard.
    fn unseal(&self, data: &[u8]) -> Result<CustodyShard, CustodyError> {
        // Step 1: Check that input is long enough to include a nonce
        if data.len() < 12 {
            return Err(CustodyError::CryptoError("Invalid sealed data".into()));
        }

        // Step 2: Split data into nonce + ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(12);
        // Step 3: Create AES-256-GCM cipher from our key
        let cipher = Aes256Gcm::new(Key::from_slice(&self.key));

        // Step 4: Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|e| CustodyError::CryptoError(format!("Decryption failed: {:?}", e)))?;

            // Step 5: Deserialize back into a CustodyShard
        let shard: CustodyShard = bincode::deserialize(&plaintext)
            .map_err(|e| CustodyError::SerdeError(format!("Deserialization failed: {:?}", e)));

        Ok(shard) // Return the restored MPC shard
    }
}
