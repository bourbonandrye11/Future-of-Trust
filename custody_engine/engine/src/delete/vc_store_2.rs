
/// this gets us closer and actually creates a full VC store that maps closely to the APIs we built
/// but it still doesn't link back to the original vault that we created a backend for
/// and it doesn't associate with existing vaults where DIDs live
/// it also doesn't provide any encryption either
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A single Verifiable Credential record stored in the system
#[derive(Clone)]
pub struct VcRecord {
    pub vc_json: String,   // The full signed VC JSON
    pub is_revoked: bool,  // Revocation flag
}

/// Thread-safe storage for VCs, keyed by subject DID + VC ID
pub struct VcStore {
    // Top-level map: subject DID → (VC ID → VcRecord)
    store: Arc<RwLock<HashMap<String, HashMap<String, VcRecord>>>>,
}

impl VcStore {
    /// Create a new (empty) VC store
    pub fn new() -> Self {
        VcStore {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store a new VC under subject DID and VC ID
    pub fn store_vc(&self, subject_did: &str, vc_id: &str, vc_json: &str) -> Result<(), String> {
        let mut store_guard = self.store.write().map_err(|e| format!("Lock error: {:?}", e))?;

        let subject_entry = store_guard.entry(subject_did.to_string()).or_insert_with(HashMap::new);
        subject_entry.insert(vc_id.to_string(), VcRecord {
            vc_json: vc_json.to_string(),
            is_revoked: false,
        });

        Ok(())
    }

    /// Retrieve a VC by subject DID + VC ID, only if **not revoked**
    pub fn get_vc(&self, subject_did: &str, vc_id: &str) -> Option<String> {
        let store_guard = self.store.read().ok()?;
        let subject_entry = store_guard.get(subject_did)?;
        let vc_record = subject_entry.get(vc_id)?;

        if vc_record.is_revoked {
            None // Do not return revoked VCs
        } else {
            Some(vc_record.vc_json.clone())
        }
    }

    /// Mark a VC as revoked by VC ID (searches across all subjects)
    pub fn revoke_vc(&self, vc_id: &str) -> Result<(), String> {
        let mut store_guard = self.store.write().map_err(|e| format!("Lock error: {:?}", e))?;

        for (_subject_did, vc_map) in store_guard.iter_mut() {
            if let Some(vc_record) = vc_map.get_mut(vc_id) {
                vc_record.is_revoked = true;
                return Ok(());
            }
        }

        Err(format!("VC with ID {} not found", vc_id))
    }
}
