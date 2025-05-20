
use tonic::{Request, Response, Status};
use issuer::custody_issuer_server::{CustodyIssuer, CustodyIssuerServer};
use issuer::{ProvisionIssuerVaultRequest, ProvisionIssuerVaultResponse};

use crate::vault::{store_record, VaultRecord};

#[derive(Clone)]
pub struct IssuerService {}

#[tonic::async_trait]
impl CustodyIssuer for IssuerService {
    async fn provision_issuer_vault(
        &self,
        request: Request<ProvisionIssuerVaultRequest>,
    ) -> Result<Response<ProvisionIssuerVaultResponse>, Status> {
        let issuer_did = request.into_inner().issuer_did;

        let vault_id = format!("vault-{}", blake3::hash(issuer_did.as_bytes()).to_hex());

        let record = VaultRecord {
            shard: None,
            bbs_private_key: None,
            public_keys: vec![],
            vcs: Default::default(),
            active_nonce: None,
        };

        store_record(&vault_id, &record)
            .map_err(|e| Status::internal(format!("Failed to store vault: {e}")))?;

        Ok(Response::new(ProvisionIssuerVaultResponse {
            vault_id,
        }))
    }
}
