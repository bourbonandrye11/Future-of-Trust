

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use crate::vault::Vault;
use crate::types::{OperationalDID, RootDID, VerifiableCredential};
use crate::error::CustodyError;
use crate::audit::{AuditRecord, AuditEventType, AUDIT, now_rfc3339};
use blake3::Hasher;

/// Represents the mapping between an operational DID and its associated data.
pub struct OperationalDIDEntry {
    pub root_did_hash: String,                    // Internal root DID reference (masked externally)
    pub vault_id: String, // replaces embedded Vault
    pub mpc_group: Option<MPCGroupDescriptor>,   // NEW: Group-wide MPC info
    pub audit_trail: VecDeque<AuditRecord>,  // Local in-memory audit trail for VC changes (rotation, revocation)
    pub did_document: Option<Vec<u8>>, // Stores raw DID document (JSON-LD)
}

/// Central registry for managing operational DIDs and their vaults.
pub struct OperationalDIDRegistry {
    pub entries: Arc<RwLock<HashMap<OperationalDID, OperationalDIDEntry>>, // Thread-safe mapping
}

// when a DID is resolved we need to know where the shards are, which vaults hold which parts, & threshold.
pub struct MPCGroupDescriptor {
    pub group_id: String,                       // Unique identifier for the MPC group
    pub members: Vec<MPCMemberDescriptor>,      // All vaults/nodes in the group
    pub threshold: u8,                          // Minimum signatures required
    pub dkg_protocol: Option<String>, // e.g., "frost-dkg-v1"
    pub session_state: Option<Vec<u8>>, // optional serialized DKG or signing session state
}

pub struct MPCMemberDescriptor {
    pub vault_reference: String,                // Vault ID or address
    pub custody_node_id: String,                // Node identifier (if multi-node)
    pub shard_index: u8,                        // Index in the threshold scheme
}


impl OperationalDIDRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new operational DID and vault
    /// need to look into this. should verify root did vault location if exist and assign opdid to that location
    pub fn register_operational_did(
        &self,
        op_did: OperationalDID,
        root_did: RootDID,
        vault_id: String,
        did_doc: Vec<u8>,
    ) -> Result<(), CustodyError> {
        let mut entries = self.entries.write().unwrap();
    
        if entries.contains_key(&op_did) {
            return Err(CustodyError::AlreadyExists("Operational DID already registered".into()));
        }
    
        // Root DID privacy: hash root_did before storing
        let mut hasher = Hasher::new();
        hasher.update(root_did.as_bytes());
        let root_hash = format!("roothash:{}", hasher.finalize().to_hex());
    
        let entry = OperationalDIDEntry {
            root_did_hash: root_hash,
            vault_id,
            mpc_group: None,
            audit_trail: VecDeque::new(),
            did_document: Some(did_doc),
        };
    
        entries.insert(op_did, entry);
    
        Ok(())
    }

    /// Rotate the operational DID (link to a new operational handle)
    pub fn rotate_operational_did(&self,
        old_did: &OperationalDID,
        new_did: OperationalDID
    ) -> Result<(), CustodyError> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.remove(old_did)
            .ok_or_else(|| CustodyError::NotFound("Old operational DID not found".into()))?;

            AUDIT.log(AuditRecord {
                event_type: AuditEventType::Signing, // Could define new AuditEventType::DIDRotation later
                session_id: new_did.0.clone(),
                participant_id: None,
                message: format!("Rotated operational DID from {} to {}", old_did.0, new_did.0),
                timestamp: now_rfc3339(),
            });
    
            Ok(())
    }

    /// Revoke (remove) an operational DID entirely
    pub fn revoke_operational_did(
        &self,
        operational_did: &OperationalDID
    ) -> Result<(), CustodyError> {
        let mut entries = self.entries.lock().unwrap();
        entries.remove(operational_did)
            .ok_or_else(|| CustodyError::NotFound("Operational DID not found".into()))?;

            AUDIT.log(AuditRecord {
                event_type: AuditEventType::Signing, // Could define new AuditEventType::DIDRevocation later
                session_id: operational_did.0.clone(),
                participant_id: None,
                message: format!("Revoked operational DID {}", operational_did.0),
                timestamp: now_rfc3339(),
            });
    
            Ok(())
    }

    /// Retrieve all VC audit records for a DID
    pub fn get_vc_audit_records(
        &self,
        operational_did: OperationalDID 
    ) -> Result<Vec<AuditRecord>, CustodyError> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(operational_did)
            .ok_or_else(|| CustodyError::NotFound("Operational DID not found".into()))?;
        Ok(entry.audit_trail.iter().cloned().collect())
    }

    pub fn store_did_document(
        &self,
        op_did: &OperationalDID,
        did_document: Vec<u8>,
    ) -> Result<(), CustodyError> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get_mut(op_did) {
            entry.did_document = Some(did_document);
            Ok(())
        } else {
            Err(CustodyError::RegistryError("Operational DID not found".into()))
        }
    }

    pub fn get_did_document(
        &self,
        op_did: &OperationalDID,
    ) -> Result<Option<Vec<u8>>, CustodyError> {
        let entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(op_did) {
            Ok(entry.did_document.clone())
        } else {
            Err(CustodyError::RegistryError("Operational DID not found".into()))
            }
    }

    pub fn get_root_for_operational_did(&self, op_did: &OperationalDID) -> Option<RootDID> {
        self.entries.lock().unwrap().get(op_did).map(|entry| entry.root_did.clone())
    }

    pub fn get_vault_id_for_operational_did(&self, op_did: &OperationalDID) -> Option<String> {
        self.entries.lock().unwrap().get(op_did).map(|entry| entry.vault_id.clone())
    }

    pub fn get_all_vcs_for_operational_did(&self, op_did: &OperationalDID) -> Option<Vec<String>> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(op_did)?;

        let record = crate::vault::load_record(&entry.vault_id).ok()?;
        Some(record.vcs.iter().map(|vc| vc.vc_json.clone()).collect())
    }

    pub fn get_mpc_group(&self, op_did: &OperationalDID) -> Option<MPCGroupDescriptor> {
        self.entries.lock().unwrap().get(op_did).and_then(|entry| entry.mpc_group.clone())
    }

    pub fn set_mpc_group(&self, op_did: &OperationalDID, group: MPCGroupDescriptor) -> Result<(), CustodyError> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get_mut(op_did).ok_or_else(|| CustodyError::NotFound("DID not found".into()))?;
        entry.mpc_group = Some(group);
        Ok(())
    }

    pub fn set_vault_id(&self, op_did: &OperationalDID, vault_id: String) -> Result<(), CustodyError> {
        let mut entries = self.entries.write().unwrap();
        let entry = entries.get_mut(op_did).ok_or_else(|| CustodyError::NotFound("DID not found".into()))?;
        entry.vault_id = vault_id;
        Ok(())
    }
    
    pub fn update_did_document(&self, op_did: &OperationalDID, doc: Vec<u8>) -> Result<(), CustodyError> {
        let mut entries = self.entries.write().unwrap();
        let entry = entries.get_mut(op_did).ok_or_else(|| CustodyError::NotFound("DID not found".into()))?;
        entry.did_document = Some(doc);
        Ok(())
    }

    // might need to replace this with our actual logger. this was at the point where things were getting off
    pub fn audit_event(&self, op_did: &OperationalDID, event: String) {
        if let Some(entry) = self.entries.lock().unwrap.get_mut(op_did) {
            entry.audit_trail.push_back(AuditRecord {
                event_type: "Provision".to_string(),
                message: event,
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }
    }
}


// I think these are missing since the canvas was overwritten. will need to check at the end
// get_root_for_operational_did() → Resolve the internal root DID
// get_vault_for_operational_did() → Retrieve the associated vault
// get_vcs_for_operational_did() → Collect all verifiable credentials linked to the DID
// I also think we should have built gRPC server APIs for these so other engines can call them

/*
    // stores the MPC group layout, associates public key with DID
    let mpc_group = MPCGroupDescriptor {
    group_id,
    members: custody_nodes.iter().enumerate().map(|(i, node)| MPCMemberDescriptor {
        vault_reference: format!("vault-{}", uuid::Uuid::new_v4()),
        custody_node_id: node.clone(),
        shard_index: i as u8,
    }).collect(),
    threshold,
};

registry.insert(op_did.clone(), OperationalDIDEntry {
    root_did,
    vault: Vault::empty_placeholder(),
    mpc_group: Some(mpc_group),
    audit_trail: VecDeque::new(),
    did_document: None,
});

*/