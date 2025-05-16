//! Centralized custody engine error types.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CustodyError {
    /// MPC protocol-related error (e.g., signing failure).
    #[error("Vault error: {0}")]
    VaultError(String),
    /// MPC protocol-related error (e.g., signing failure).
    #[error("MPC error: {0}")]
    MPCError(String),
    /// Serialization or deserialization error.
    #[error("Serialization error: {0}")]
    SerdeError(String),
     /// Generic cryptographic operation failure.
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    /// Input validation or integrity error.
    #[error("Validation error: {0}")]
    ValidationError(String),
    /// Unknown or uncategorized error.
    #[error("Unknown error: {0}")]
    Unknown(String),
}
