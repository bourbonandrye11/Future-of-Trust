//! Custody Engine Core Library

pub mod bootstrap;
pub mod vault;
pub mod registry;
pub mod dkg;
pub mod mpc;
pub mod relay;
pub mod issuer;
pub mod orchestrator;

pub mod service {
    pub mod dkg_service;
    pub mod vault_service;
    pub mod mpc_service;
    pub mod issuer_service;
    pub mod relay_service;
}

// Export client stubs if needed by external engines
pub mod api {
    tonic::include_proto!("vault");
    tonic::include_proto!("dkg");
    tonic::include_proto!("mpc");
    tonic::include_proto!("issuer");
    tonic::include_proto!("registry"); // if defined
}




//pub mod crypto;
//pub mod vault;
//pub mod mpc;
//pub mod types;
//pub mod error;

use tracing_subscriber::FmtSubscriber;

/// Initialize custody engine Logging
/*pub fn init_logging() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global default subscriber");
}
*/