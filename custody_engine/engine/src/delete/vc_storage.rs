

use crate::types::VerifiableCredential;
use crate::error::CustodyError;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::RngCore;
use zeroize::Zeroizing;

/// Vault storage backend for secure VC handling.
pub struct VaultStorage {
    encryption_key: Zeroizing<[u8, 32]>, // Symmetric encryption key (memory-wiped)
    stored_vcs: Mutex<Vec<Vec<u8>>>, // Encrypted VC blobs (in-memory)
}

impl VaultStorage {
    /// Initialize vault storage with a fresh encryption key.
    pub fn new() -> Self {
        let mut key = [0u8; 32]; // Allocate 32-byte array (256-bit key)
        rand::thread_rng().fill_bytes(&mut key); // Fill it with secure random bytes
        Self {
            encryption_key: Zeroizing::new(key), // Wrap key to auto-zero on drop
            stored_vcs: Mutex::new(vec![]), // Initialize empty vector for VCs
        }
    }

    /// Encrypt and store a new set of VCs
    pub fn add_or_rotate_vcs(&self, vcs: Vec<VerifiableCredential>) -> Result<(), CustodyError> {
        let cipher = Aes256Gcm::new(Key::from_slice(&self.encryption_key));
        let mut encrypted_vcs = vec![];

        // Iterates over each VC, generates a fresh 12-bytes nonce, serializes it to JSON.
        for vc in vcs {
            let nonce = rand::random::<[u8; 12]>(); // Generate a random nonce
            let serialized = serde_json::to_vec(&vc)
                .map_err(|e| CustodyError::SerdeError(format!("VC serialization failed: {:?}", e)))?;

                // Encrypts the serialized JSON
            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce), serialized.as_ref())
                .map_err(|e| CustodyError::CryptoError(format!("VC encryption failed: {:?}", e)))?;

                // Combines the nonce and ciphertext into a single blob
            let mut sealed_blob = nonce.to_vec();
            sealed_blob.extend(ciphertext);
            encrypted_vcs.push(sealed_blob);
        }

        // stores all blobs in memory
        let mut store = self.stored_vcs.lock().unwrap();
        *store = encrypted_vcs;
        Ok(())
    }

    /// Decrypt and return all stored VCs
    pub fn get_verifiable_credentials(&self) -> Result<Vec<VerifiableCredential>, CustodyError> {
        let cipher = Aes256Gcm::new(Key::from_slice(&self.encryption_key));
        let store = self.stored_vcs.lock().unwrap();
        let mut result = vec![];

        for blob in store.iter() {
            if blob.len() < 12 {
                return Err(CustodyError::CryptoError("Invalid VC blob format".into()));
            }

            let (nonce_bytes, ciphertext) = blob.split_at(12);
            let plaintext = cipher
                .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
                .map_err(|e| CustodyError::CryptoError(format!("VC decryption failed: {:?}", e)))?;

            let vc: VerifiableCredential = serde_json::from_slice(&plaintext)
                .map_err(|e| CustodyError::SerdeError(format!("VC deserialization failed: {:?}", e)))?;

            result.push(vc);
        }

        Ok(result)
    }

    /// Verify the integrity of a single VC
    pub fn verify_vc_integrity(&self, vc: &VerifiableCredential) -> Result<bool, CustodyError> {
        // 🔐 TODO: Check issuer signature + hash commitment (placeholder)
        Ok(true) // Stub: assumes VC is valid
    }
}

// we are missing a function for get_vc_audit_trail. it is already in proto and server. 