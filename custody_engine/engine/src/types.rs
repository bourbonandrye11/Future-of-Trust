//! Shared data types for custody engine: Participant IDs, Shard IDs, and Custody Shards.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Unique identifier for a participant (device, server, mobile shard)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantID(pub u8);

/// Unique identifier for a custody shard (sealed key share)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShardId(pub u8);

/// A custody shard containing an encrypted secret share and its public key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CustodyShard {
    /// Unique ID for the shard
    pub id: ShardId,
    /// Public key corresponding to the secret share.
    pub pubkey: Vec<u8>,
    /// Serialized and sealed secret share.
    pub share: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionNonce(pub [u8; 32]);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VcRecord {
    pub vc_id: String,
    pub vc_json: String,
    pub is_revoked: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultRecord {
    pub root_did: String,                          // The root DID this vault is anchored to
    pub op_dids: Vec<String>,                     // One or more operational DIDs
    pub mpc_shard: Option<String>,                // Encrypted MPC shard
    pub group_metadata: Option<String>,           // MPC/FROST config or quorum metadata
    pub public_keys: Vec<String>,                 // Stored public keys for DID rotation or delegation
    pub vcs: Vec<VcRecord>,                       // Stored VC entries (root + attribute)
    pub bbs_private_key: Option<String>,          // Issuer key if this vault belongs to an issuer
    pub bbs_public_key: Option<String>,
    pub active_nonce: Option<Vec<u8>>, // Binary nonce blob (bincode serialized)
}