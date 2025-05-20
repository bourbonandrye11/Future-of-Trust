
use tonic::{Request, Response, Status};
use crate::vault;
use crate::registry::OperationalDIDRegistry;

use vault::custody_vault_server::{CustodyVault, CustodyVaultServer};
use vault::{
    GenerateNonceRequest, GenerateNonceResponse,
    PartialSignRequest, PartialSignResponse,
};

pub mod custody {
    tonic::include_proto!("vault");
}

#[derive(Clone)]
pub struct VaultService {
    pub registry: OperationalDIDRegistry,
}

#[tonic::async_trait]
impl CustodyVault for VaultService {
    async fn generate_nonce(
        &self,
        request: Request<GenerateNonceRequest>,
    ) -> Result<Response<GenerateNonceResponse>, Status> {
        let op_did = request.into_inner().operational_did;

        let commitment = vault::generate_nonce(&self.registry, &op_did)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(GenerateNonceResponse {
            commitment,
        }))
    }

    async fn partial_sign(
        &self,
        request: Request<PartialSignRequest>,
    ) -> Result<Response<PartialSignResponse>, Status> {
        let req = request.into_inner();

        let commitments = req.commitments.into_iter()
            .map(|c| (c.peer_id, c.commitment))
            .collect::<Vec<_>>();

        let signature = vault::partial_sign(&self.registry, &req.operational_did, &req.message, &commitments)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(PartialSignResponse {
            signature,
        }))
    }
}
