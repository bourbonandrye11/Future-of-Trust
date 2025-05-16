//! Shared data types for custody engine: Participant IDs, Shard IDs, and Custody Shards.

use serde::{Deserialize, Serialize};

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
