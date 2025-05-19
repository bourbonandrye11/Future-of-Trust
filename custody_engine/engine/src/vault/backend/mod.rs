
pub mod simulated;
//pub mod memory;
//pub mod sgx;
//pub mod nitro;
use crate::vault::types::VaultRecord;

pub trait VaultBackend: Send + Sync {
    fn store_record(&self, vault_id: &str, record: &VaultRecord) -> Result<(), String>;
    fn load_record(&self, vault_id: &str) -> Result<VaultRecord, String>;
}
