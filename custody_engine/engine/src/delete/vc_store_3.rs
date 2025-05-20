

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Represents the vault's secure internal storage for one DID
#[derive(Clone)]
pub struct VaultRecord {
    pub shards: Vec<String>, // Custody shards (placeholder; would be secure types)
    pub mpc_state: String,   // MPC group metadata
    pub vcs: HashMap<String, VcRecord>, // VC storage keyed by VC ID
}

/// A single Verifiable Credential record
#[derive(Clone)]
pub struct VcRecord {
    pub vc_json: String,
    pub is_revoked: bool,
}

/// Thread-safe vault managing records per DID
pub struct Vault {
    store: Arc<RwLock<HashMap<String, VaultRecord>>>, // DID → VaultRecord
}

impl Vault {
    /// Initialize a new vault
    pub fn new() -> Self {
        Vault {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Ensure a VaultRecord exists for the DID (helper)
    fn ensure_vault_record(&self, did: &str) -> Result<(), String> {
        let mut store_guard = self.store.write().map_err(|e| format!("Lock error: {:?}", e))?;
        store_guard.entry(did.to_string()).or_insert_with(|| VaultRecord {
            shards: vec![],
            mpc_state: String::new(),
            vcs: HashMap::new(),
        });
        Ok(())
    }

    /// Store a new VC under a DID
    pub fn store_vc(&self, did: &str, vc_id: &str, vc_json: &str) -> Result<(), String> {
        self.ensure_vault_record(did)?;
        let mut store_guard = self.store.write().map_err(|e| format!("Lock error: {:?}", e))?;
        let record = store_guard.get_mut(did).ok_or("Vault record not found")?;

        record.vcs.insert(vc_id.to_string(), VcRecord {
            vc_json: vc_json.to_string(),
            is_revoked: false,
        });

        Ok(())
    }

    /// Retrieve a VC under a DID (only if not revoked)
    pub fn get_vc(&self, did: &str, vc_id: &str) -> Option<String> {
        let store_guard = self.store.read().ok()?;
        let record = store_guard.get(did)?;
        let vc_record = record.vcs.get(vc_id)?;

        if vc_record.is_revoked {
            None
        } else {
            Some(vc_record.vc_json.clone())
        }
    }

    /// Revoke a VC by VC ID (under a specific DID)
    pub fn revoke_vc(&self, did: &str, vc_id: &str) -> Result<(), String> {
        let mut store_guard = self.store.write().map_err(|e| format!("Lock error: {:?}", e))?;
        let record = store_guard.get_mut(did).ok_or("Vault record not found")?;
        let vc_record = record.vcs.get_mut(vc_id).ok_or("VC not found")?;

        vc_record.is_revoked = true;

        Ok(())
    }
}
