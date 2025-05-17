

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use crate::vault::Vault;
use crate::types::{OperationalDID, RootDID, VerifiableCredential};
use crate::error::CustodyError;
use crate::audit::{AuditRecord, AuditEventType, AUDIT, now_rfc3339};

/// Represents the mapping between an operational DID and its associated data.
pub struct OperationalDIDEntry {
    pub root_did: RootDID,                    // Internal root DID reference (masked externally)
    pub custody_vault: Vault,                 // Vault holding shards + VCs
    pub audit_trail: VecDeque<AuditRecord>,  // Local in-memory audit trail for VC changes (rotation, revocation)
}

/// Central registry for managing operational DIDs and their vaults.
pub struct OperationalDIDRegistry {
    pub entries: Mutex<HashMap<OperationalDID, OperationalDIDEntry>>, // Thread-safe mapping
}

impl OperationalDIDRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new operational DID and vault
    /// need to look into this. should verify root did vault location if exist and assign opdid to that location
    pub fn register(
        &self,
        operational_did: OperationalDID,
        root_did: RootDID,
        vault: Vault
    ) -> Result<(), CustodyError> {
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(&operational_did) {
            return Err(CustodyError::AlreadyExists("Operational DID already registered".into()));
        }

        entries.insert(operational_did, OperationalDIDEntry {
            root_did,
            custody_vault: vault,
            audit_trail: VecDeque::new(),
        });
        Ok(())
    }

    /// Rotate the operational DID (link to a new operational handle)
    pub fn rotate_operational_did(&self,
        old_did: &OperationalDID,
        new_did: OperationalDID
    ) -> Result<(), CustodyError> {
        let mut entries = self.entries.lcol().unwrap();
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
}


// I think these are missing since the canvas was overwritten. will need to check at the end
// get_root_for_operational_did() → Resolve the internal root DID
// get_vault_for_operational_did() → Retrieve the associated vault
// get_vcs_for_operational_did() → Collect all verifiable credentials linked to the DID
// I also think we should have built gRPC server APIs for these so other engines can call them