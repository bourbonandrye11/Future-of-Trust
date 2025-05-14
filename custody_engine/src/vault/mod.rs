use crate::types::CustodyShard;
use crate::error::CustodyError;

pub struct Vault;

impl Vault {
    pub fn seal(shard: &CustodyShard) -> Result<Vec<u8>, CustodyError> {

        bincode::serialize(shard).map_err(CustodyError::SerdeError)
    }

    pub fn unseal(data: &[u8]) -> Result<CustodyShard, CustodyError> {
        bincode::deserialize(data).map_err(CustodyError::SerdeError)
    }
}