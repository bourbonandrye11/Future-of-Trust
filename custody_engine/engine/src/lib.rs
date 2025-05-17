//! Custody Engine Core Library

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