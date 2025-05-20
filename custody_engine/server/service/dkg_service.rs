
use tonic::{Request, Response, Status};
use crate::dkg::engine::DKGEngine;
use crate::dkg::types::DKGError;

use std::sync::Arc;
use custodydkg::custody_dkg_server::{CustodyDkg, CustodyDkgServer};
use custodydkg::{
    StartDkgSessionRequest, StartDkgSessionResponse,
    BroadcastRound2Request, FinalizeDkgRequest, FinalizeDkgResponse,
};
use prost_types::Empty;

pub mod custody {
    tonic::include_proto!("custodydkg");
}

#[derive(Clone)]
pub struct CustodyDkgService {
    pub dkg_engine: Arc<DKGEngine>,
}

#[tonic::async_trait]
impl CustodyDkg for CustodyDkgService {
    async fn start_dkg_session(
        &self,
        request: Request<StartDkgSessionRequest>,
    ) -> Result<Response<StartDkgSessionResponse>, Status> {
        let req = request.into_inner();
        let group_id = self.dkg_engine
            .start_session(req.operational_did, req.threshold as u8, req.participant_nodes)
            .map_err(|e| Status::internal(format!("start_session failed: {:?}", e)))?;

        Ok(Response::new(StartDkgSessionResponse { group_id }))
    }

    async fn broadcast_round2(
        &self,
        request: Request<BroadcastRound2Request>,
    ) -> Result<Response<Empty>, Status> {
        let group_id = request.into_inner().group_id;

        self.dkg_engine
            .broadcast_round2(&group_id)
            .map_err(|e| Status::internal(format!("round2 failed: {:?}", e)))?;

        Ok(Response::new(Empty {}))
    }

    async fn finalize_dkg_session(
        &self,
        request: Request<FinalizeDkgRequest>,
    ) -> Result<Response<FinalizeDkgResponse>, Status> {
        let group_id = request.into_inner().group_id;

        let shard = self.dkg_engine
            .finalize(&group_id)
            .map_err(|e| Status::internal(format!("finalize failed: {:?}", e)))?;

        Ok(Response::new(FinalizeDkgResponse {
            shard_base64: base64::encode(shard),
        }))
    }
}
