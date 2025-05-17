

use crate::types::CustodyShard;
use crate::error::CustodyError;
use crate::vault::backend::VaultBackend;

// ==============================
// 🔐 SGX Vault Backend (Stub)
// ==============================

/// Simulates sealing to Intel SGX enclave memory.
/// Replace with actual SGX SDK or Fortanix APIs.
pub struct SgxVaultBackend;

impl VaultBackend for SgxVaultBackend {
    fn seal(&self, shard: &CustodyShard) -> Result<Vec<u8>, CustodyError> {
        // 🔐 Replace with real SGX SDK: use sgx_seal_data + sgxfs
        Err(CustodyError::Unimplemented("SGX backend not yet implemented".into()))
    }

    fn unseal(&self, _data: &[u8]) -> Result<CustodyShard, CustodyError> {
        // 🔐 Replace with real SGX SDK: use sgx_unseal_data
        Err(CustodyError::Unimplemented("SGX backend not yet implemented".into()))
    }
}

// ===============================
// 🔐 Nitro Vault Backend (Stub)
// ===============================

/// Placeholder for AWS Nitro Enclave sealing.
/// Replace with enclave-side vsock IPC or JSON-RPC bridge.
pub struct NitroVaultBackend;

impl VaultBackend for NitroVaultBackend {
    fn seal(&self, shard: &CustodyShard) -> Result<Vec<u8>, CustodyError> {
        // 🔐 Replace with real enclave comms: vsock or socketpair
        Err(CustodyError::Unimplemented("Nitro backend not yet implemented".into()))
    }

    fn unseal(&self, _data: &[u8]) -> Result<CustodyShard, CustodyError> {
        // 🔐 Replace with real enclave comms
        Err(CustodyError::Unimplemented("Nitro backend not yet implemented".into()))
    }
}