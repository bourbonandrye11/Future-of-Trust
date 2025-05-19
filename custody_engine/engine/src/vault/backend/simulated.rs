

use crate::error::CustodyError; // Our centralized error type
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or use XChaCha20Poly1305 if preferred
use aes_gcm::aead::{Aead, NewAead};
use rand::RngCore;
use serde_json;
use zeroize::Zeroizing;

use crate::vault::types::VaultRecord;
use crate::vault::backend::VaultBackend;

/// Sealed vault blob, encrypted using AES-GCM
struct SealedBlob {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}

pub struct SimulatedTEEBackend {
    store: Arc<RwLock<HashMap<String, SealedBlob>>>,
    cipher: Aes256Gcm,
}

impl SimulatedTEEBackend {
    pub fn new() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut key[..]);
        let cipher = Aes256Gcm::new(Key::from_slice(&key));

        SimulatedTEEBackend {
            store: Arc::new(RwLock::new(HashMap::new())),
            cipher,
        }
    }
}

impl VaultBackend for SimulatedTEEBackend {
    fn store_record(&self, vault_id: &str, record: &VaultRecord) -> Result<(), String> {
        let plaintext = serde_json::to_vec(record).map_err(|e| format!("Serialization failed: {e:?}"))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("Encryption failed: {e:?}"))?;

        let blob = SealedBlob {
            ciphertext,
            nonce: nonce_bytes,
        };

        let mut store = self.store.write().map_err(|_| "Vault lock poisoned".to_string())?;
        store.insert(vault_id.to_string(), blob);
        Ok(())
    }

    fn load_record(&self, vault_id: &str) -> Result<VaultRecord, String> {
        let store = self.store.read().map_err(|_| "Vault lock poisoned".to_string())?;
        let blob = store.get(vault_id).ok_or("Vault ID not found")?;

        let nonce = Nonce::from_slice(&blob.nonce);
        let plaintext = self.cipher.decrypt(nonce, blob.ciphertext.as_ref())
            .map_err(|e| format!("Decryption failed: {e:?}"))?;

        serde_json::from_slice(&plaintext).map_err(|e| format!("Deserialization failed: {e:?}"))
    }
}
