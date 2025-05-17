//! Vault abstraction for custody shard sealing and unsealing.
//! In production, this would integrate with TEE-based storage (SGX, TrustZone, SEV).

use crate::types::CustodyShard;
use crate::error::CustodyError;
use crate::vault::backend::{VaultBackend, MemoryVaultBackend, SimulatedTEEBackend};
use lazy_static::lazy_static;
use std::sync::{Arc, OnceLock};
//use serde;
//use bincode;

/// Represents which backend vault mode to use at runtime.
pub enum VaultMode {
    Memory,
    SimulatedTee,
    // Future: Sgx,
    // Future: Nitro,
}

/// Static instance of the active backend (shared globally).
static BACKEND: OnceLock<Arc<dyn VaultBackend>> = OnceLock::new(); // OnceLock creates a global singleton

/// Initialize the vault with the chosen mode.
pub fn init(mode: VaultMode) {
    let backend: Arc<dyn VaultBackend> = match mode {
        VaultMode::Memory => Arc::new(MemoryVaultBackend),
        VaultMode::SimulatedTee => Arc::new(SimulatedTEEBackend::new()),
    };

    BACKEND.set(backend).expect("Vault already initialized");
}

// I believe we don't use lazy_static since we are implementing a static backend that is switcable at startup.
//lazy_static::lazy_static! {
//    static ref BACKEND: Box<dyn VaultBackend> = Box::new(MemoryVaultBackend); // can swap here
//}

/// A vault handles secure storage operations for custody shards.
pub struct Vault;

impl Vault {
    /// Seal a custody shard into a sealed binary blob.
    pub fn seal(shard: &CustodyShard) -> Result<Vec<u8>, CustodyError> {
        BACKEND
            .get()
            .ok_or_else(|| CustodyError::CryptoError("Vault not initialized".into()))?
            .seal(shard)
    }
    /// Unseal a custody shard from a sealed binary blob.
    pub fn unseal(data: &[u8]) -> Result<CustodyShard, CustodyError> {
        BACKEND
            .get()
            .ok_or_else(|| CustodyError::CryptoError("Vault not initialized".into()))?
            .unseal(data)
    }
}

// Later we can toggle to: Box::new(SimulatedTEEBackend::new())
// or any other backend that implements the VaultBackend trait.
// with this we have  aruntime pluggable vault backend interface, a fully working AES-256-GCM sealing engine,
// a simulated TEE key that is never leaked or stored, a Tamper-resistent, authenticated shard stored. 
// this is 100% TEE-compatible vault code ready for SGX/Nitro/TrustZone backends. 