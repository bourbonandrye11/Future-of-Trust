
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, Duration};

use crate::registry::{OperationalDIDRegistry, MPCGroupDescriptor};
use crate::vault;

/// Represents the state of an in-progress MPC signing round
pub struct SigningSession {
    pub operational_did: String,                   // DID being signed on behalf of
    pub message: Vec<u8>,                          // The message being signed (e.g., DID proof or VC ID)
    pub group_id: String,                          // The FROST group session ID from registry
    pub nonce_commitments: HashMap<String, Vec<u8>>, // peer_id → nonce commitment
    pub partial_signatures: HashMap<String, Vec<u8>>, // peer_id → signature share
    pub threshold: usize,                          // Quorum threshold
    pub start_time: SystemTime,                    // Timestamp the session began
}

impl SigningSession {
    /// Initializes a new session by loading group metadata from the registry
    pub fn new(registry: &OperationalDIDRegistry, op_did: &str, message: Vec<u8>) -> Result<Self, String> {
        let descriptor = registry.get_mpc_group(op_did)
            .ok_or("No MPC group descriptor found")?;

        let group_id = descriptor.group_id.clone();

        Ok(SigningSession {
            operational_did: op_did.to_string(),
            message,
            group_id,
            nonce_commitments: HashMap::new(),
            partial_signatures: HashMap::new(),
            threshold: descriptor.threshold as usize,
            start_time: SystemTime::now(),
        })
    }

    /// Adds a nonce commitment from a participant
    pub fn record_commitment(&mut self, peer_id: &str, commitment: Vec<u8>) {
        self.nonce_commitments.insert(peer_id.to_string(), commitment);
    }

    /// Adds a partial signature from a participant
    pub fn record_partial(&mut self, peer_id: &str, sig: Vec<u8>) {
        self.partial_signatures.insert(peer_id.to_string(), sig);
    }

    /// Checks if we have enough shares to finalize
    pub fn ready_to_aggregate(&self) -> bool {
        self.partial_signatures.len() >= self.threshold
    }

    /// Returns a set of participant peer IDs who have not yet submitted signatures
    pub fn missing_participants(&self, all_participants: &[String]) -> Vec<String> {
        all_participants
            .iter()
            .filter(|pid| !self.partial_signatures.contains_key(*pid))
            .cloned()
            .collect()
    }

    /// Checks if the session is stale
    pub fn is_expired(&self, timeout_secs: u64) -> bool {
        self.start_time.elapsed().map_or(false, |e| e > Duration::from_secs(timeout_secs))
    }
}
