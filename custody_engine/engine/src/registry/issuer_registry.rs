/// This module will:
///     Track issuer DIDs
///     Store their BBS+ key material
///     confirm which DIDs are allowed to sign credentials

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use bbs::PublicKey;
use crate::bbs::BbsKeyPair;

/// Information about a registered issuer DID
#[derive(Clone)]
pub struct  IssuerRecord {
    pub did: String,
    pub active: bool,
    pub is_issuer: bool,
    pub vault_ref: String,       // Points to where the private key lives
    pub public_key: PublicKey,   // Public, can be exposed
    // pub bbs_keypair: BbsKeyPair, // stored both keys. replaced with the above publicKey
}

/// Central isuer registry (thread-safe)
pub struct IssuerRegistry {
    issuers: Arc<RwLock<HashMap<String, IssuerRecord>>>,
}

impl IssuerRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        IssuerRegistry {
            issuers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new issuer DID with vault reference + public key
    pub fn register_issuer(&self, did: &str, vault_ref: &str, public_key: PublicKey) {
        let record = IssuerRecord {
            did: did.to_string(),
            is_issuer: true,
            vault_ref: vault_ref.to_string(),
            public_key // storing the public key only now
           // bbs_keypair: BbsKeyPair::generate(), // previously stored private and public keypair
        };

        self.issuers.write().unwrap().insert(did.to_string(), record);
    }

    /// Check if a DID is an authorized issuer
    pub fn is_authorized_issuer(&self, did: &str) -> bool {
        self.issuers.read().unwrap().get(did).map_or(false, |r| r.is_issuer)
    }

     /// Get public key for DID (for verification)
     pub fn get_public_key(&self, did: &str) -> Option<PublicKey> {
        self.issuers.read().unwrap().get(did).map(|r| r.public_key.clone())
    }

    /// Get vault reference for DID (for internal signing)
    pub fn get_vault_ref(&self, did: &str) -> Option<String> {
        self.issuers.read().unwrap().get(did).map(|r| r.vault_ref.clone())
    }

    pub fn get_issuer_record(&self, did: &str) -> Option<IssuerRecord> {
        self.issuers.read().unwrap().get(did).cloned()
    }

    pub fn update_issuer(
        &self,
        issuer_did: &str,
        new_public_key: Option<String>,
        new_vault_ref: Option<String>,
    ) -> Result<(), CustodyError> {
        let mut issuers = self.issuers.write().unwrap();
        let record = issuers.get_mut(issuer_did).ok_or_else(|| {
            CustodyError::NotFound("Issuer not found".to_string())
        })?;
    
        if let Some(pk) = new_public_key {
            record.public_key = pk;
        }
        if let Some(vault) = new_vault_ref {
            record.vault_ref = vault;
        }
    
        Ok(())
    }

    /// Physically deletes an issuer from the registry.
    pub fn remove_issuer(&self, issuer_did: &str) -> Result<(), CustodyError> {
        let mut issuers = self.issuers.write().unwrap();
        issuers.remove(issuer_did)
            .ok_or_else(|| CustodyError::NotFound("Issuer not found".to_string()))?;
        Ok(())
    }

    /// Soft-disables issuer without removing its record.
    pub fn deactivate_issuer(&self, issuer_did: &str) -> Result<(), CustodyError> {
        let mut issuers = self.issuers.write().unwrap();
        let record = issuers.get_mut(issuer_did)
            .ok_or_else(|| CustodyError::NotFound("Issuer not found".to_string()))?;
        record.active = false;
        Ok(())
    }

    /// Retrieve the BBS+ keypair for a given issuer DID original fn replaced with public key
   // pub fn get_issuer_keys(&self, did: &str) -> Option<BbsKeyPair> {
   //     self.issuers.read().unwrap().get(did).map(|r| r.bbs_keypair.clone())
   // }
}