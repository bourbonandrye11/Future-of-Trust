use thiserror::Error;

#[derive(Error, Debug)]
pub enum CustodyError {
    #[error("Vault error: {0}")]
    VaultError(String),
    #[error("MPC error: {0}")]
    MPCError(String),
    #[error("Serialization error" )]
    SerdeError(#[from] bincode::Error),
    #[error("Unknown error")]
    Unknown,
}
