// Section 1: Shared DKG Types

// File: src/dkg/types.rs

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Messages exchanged between custody nodes during FROST DKG
#[derive(Debug, Serialize, Deserialize)]
pub enum DKGMessage {
    Round1(Vec<u8>),
    Round2(Vec<u8>),
    Finalization(Vec<u8>),
}

/// Local DKG session state for a single custody node
#[derive(Debug)]
pub struct DKGLocalState {
    pub operational_did: String,                  // The DID this DKG is being run for
    pub threshold: u8,                            // Signing threshold (t)
    pub participant_ids: Vec<String>,             // List of custody node identifiers
    pub round1_received: HashMap<String, Vec<u8>>, // Round1 packages received
    pub round2_received: HashMap<String, Vec<u8>>, // Round2 packages received
    pub finalized: bool,                          // Whether this node finished
    pub keygen_machine: Option<frost_ed25519::dkg::KeyGenMachine>, // Local cryptographic state
}

/// Session managed by the node-local DKG engine
pub struct DKGSession {
    pub group_id: String,             // Unique session ID
    pub local: DKGLocalState,
}

/// Errors thrown during DKG lifecycle
#[derive(Debug)]
pub enum DKGError {
    SessionAlreadyExists,
    SessionNotFound,
    MessageMalformed,
    CryptoFailure(String),
    RegistryUpdateFailed,
    VaultStorageFailed,
}