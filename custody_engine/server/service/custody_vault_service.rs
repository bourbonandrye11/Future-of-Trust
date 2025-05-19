

use tonic::{Request, Response, Status};
use custody::custody_management_service_server::CustodyManagementService;
use custody::*;
use crate::registry::OperationalDIDRegistry;
use crate::types::{OperationalDID as InternalOperationalDID, RootDID as InternalRootDID, VerifiableCredential as InternalVC};
use crate::vault::Vault;
use crate::error::CustodyError;

pub mod custody {
    tonic::include_proto!("custody");
}

#[derive(Default)]
pub struct CustodyVaultServiceServer;

#[tonic::async_trait]
impl CustodyVaultService for CustodyVaultServiceServer {

/// Calls into the local vaults DKG engine
/// Prepares it for DKG message exchanges
async fn start_dkg_session(
    &self,
    request: Request<StartDKGSessionRequest>,
) -> Result<Response<StartDKGSessionResponse>, Status> {
    let req = request.into_inner();

    self.dkg_engine.start_session(
        req.group_id,
        req.operational_did,
        req.threshold as u8,
        req.participant_nodes,
    ).map_err(|e| Status::internal(format!("DKG session start failed: {}", e)))?;

    Ok(Response::new(StartDKGSessionResponse { success: true }))
}

/// Vault receives DKG messages from its peers
/// Processes them as part of the DKG protocol
async fn submit_dkg_message(
    &self,
    request: Request<SubmitDKGMessageRequest>,
) -> Result<Response<SubmitDKGMessageResponse>, Status> {
    let req = request.into_inner();

    self.dkg_engine.receive_message(
        req.group_id,
        req.sender_node_id,
        req.dkg_payload,
    ).map_err(|e| Status::internal(format!("DKG message handling failed: {}", e)))?;

    Ok(Response::new(SubmitDKGMessageResponse { success: true }))
    }

    /// vault finalizes its share
    /// returns the jointly agreed public key
    async fn complete_dkg_session(
        &self,
        request: Request<CompleteDKGSessionRequest>,
    ) -> Result<Response<CompleteDKGSessionResponse>, Status> {
        let req = request.into_inner();
    
        let public_key_commitment = self.dkg_engine.complete_session(req.group_id)
            .map_err(|e| Status::internal(format!("Completing DKG failed: {}", e)))?;
    
        Ok(Response::new(CompleteDKGSessionResponse {
            public_key_commitment,
        }))
    }
}
