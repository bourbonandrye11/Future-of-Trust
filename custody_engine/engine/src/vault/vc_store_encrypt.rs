

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use rand::RngCore;
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM 256-bit
use aes_gcm::aead::{Aead, NewAead};

/// Represents a single VC record (encrypted storage)
#[derive(Clone)]
pub struct VcRecord {
    pub ciphertext: Vec<u8>, // encrypted VC
    pub nonce: [u8; 12],     // nonce used for encryption
    pub is_revoked: bool,
}

/// Represents the vault's secure internal storage
#[derive(Clone)]
pub struct VaultRecord {
    pub shards: Vec<String>,
    pub mpc_state: String,
    pub vcs: HashMap<String, VcRecord>, // VC storage keyed by VC ID
}

/// SimulatedVault: thread-safe in-memory vault with AES encryption
pub struct Vault {
    store: Arc<RwLock<HashMap<String, VaultRecord>>>,
    cipher: Aes256Gcm, // symmetric AES-GCM cipher initialized at vault startup
}

impl Vault {
    /// Initialize a new vault with a random AES-256 key
    pub fn new() -> Self {
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = Key::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        Vault {
            store: Arc::new(RwLock::new(HashMap::new())),
            cipher,
        }
    }

    /// Ensure VaultRecord exists for a DID
    fn ensure_vault_record(&self, did: &str) -> Result<(), String> {
        let mut store_guard = self.store.write().map_err(|e| format!("Lock error: {:?}", e))?;
        store_guard.entry(did.to_string()).or_insert_with(|| VaultRecord {
            shards: vec![],
            mpc_state: String::new(),
            vcs: HashMap::new(),
        });
        Ok(())
    }

    /// Encrypt and store VC
    pub fn store_vc(&self, did: &str, vc_id: &str, vc_json: &str) -> Result<(), String> {
        self.ensure_vault_record(did)?;

        // Generate random nonce (12 bytes)
        let mut nonce_bytes = [0u8; 12]; // ensyres encryption is non-deterministic + secure
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt VC payload
        let ciphertext = self.cipher.encrypt(nonce, vc_json.as_bytes())
            .map_err(|e| format!("Encryption error: {:?}", e))?;

        let mut store_guard = self.store.write().map_err(|e| format!("Lock error: {:?}", e))?;
        let record = store_guard.get_mut(did).ok_or("Vault record not found")?;

        record.vcs.insert(vc_id.to_string(), VcRecord {
            ciphertext,
            nonce: nonce_bytes, // required for decryption and stored alongside ciphertext
            is_revoked: false,
        });

        Ok(())
    }

    /// Decrypt and retrieve VC (only if not revoked)
    pub fn get_vc(&self, did: &str, vc_id: &str) -> Option<String> {
        let store_guard = self.store.read().ok()?;
        let record = store_guard.get(did)?;
        let vc_record = record.vcs.get(vc_id)?;

        if vc_record.is_revoked {
            return None;
        }

        let nonce = Nonce::from_slice(&vc_record.nonce);
        let plaintext = self.cipher.decrypt(nonce, vc_record.ciphertext.as_ref()).ok()?;

        String::from_utf8(plaintext).ok()
    }

    /// Mark VC as revoked
    pub fn revoke_vc(&self, did: &str, vc_id: &str) -> Result<(), String> {
        let mut store_guard = self.store.write().map_err(|e| format!("Lock error: {:?}", e))?;
        let record = store_guard.get_mut(did).ok_or("Vault record not found")?;
        let vc_record = record.vcs.get_mut(vc_id).ok_or("VC not found")?;

        vc_record.is_revoked = true;
        Ok(())
    }
}

// AES-256-GCM is authenticated encryption → protects confidentiality + integrity.
// Nonce reuse must be avoided (we generate random nonces per VC).
// The vault key is memory-resident; in production, it would live inside the TEE or be sealed.