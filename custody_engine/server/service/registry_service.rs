

use tonic::{Request, Response, Status};
use crate::proto::custody_registry::{
    custody_registry_server::CustodyRegistry,
    RegisterOpDidRequest, RegisterOpDidResponse,
    GetVaultForOpDidRequest, GetVaultForOpDidResponse,
    RegisterIssuerRequest, RegisterIssuerResponse,
    RemoveIssuerRequest, RemoveIssuerResponse,
    DeactivateIssuerRequest, DeactivateIssuerResponse,
    GetIssuerRequest, GetIssuerResponse,
};
use crate::registry::{OperationalDIDRegistry, IssuerRegistry}; // adjust paths


pub struct CustodyRegistryService {
    pub did_registry: OperationalDIDRegistry,
    pub issuer_registry: IssuerRegistry,
}

#[tonic::async_trait]
impl CustodyRegistry for CustodyRegistryService {
    async fn register_operational_did(
        &self,
        request: Request<RegisterOpDidRequest>,
    ) -> Result<Response<RegisterOpDidResponse>, Status> {
        let req = request.into_inner();
        self.did_registry.register_operational_did(
            req.operational_did,
            req.root_did,
            req.vault_id,
            req.did_document,
        ).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(RegisterOpDidResponse {}))
    }

    async fn get_vault_for_operational_did(
        &self,
        request: Request<GetVaultForOpDidRequest>,
    ) -> Result<Response<GetVaultForOpDidResponse>, Status> {
        let req = request.into_inner();
        let vault_id = self.did_registry
            .get_vault_id_for_operational_did(&req.operational_did)
            .ok_or(Status::not_found("DID not found"))?;
        Ok(Response::new(GetVaultForOpDidResponse { vault_id }))
    }

    async fn register_issuer(
        &self,
        request: Request<RegisterIssuerRequest>,
    ) -> Result<Response<RegisterIssuerResponse>, Status> {
        let req = request.into_inner();
        self.issuer_registry.register_issuer(
            req.issuer_did, req.vault_ref, req.public_key
        ).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(RegisterIssuerResponse {}))
    }

    async fn remove_issuer(
        &self,
        request: Request<RemoveIssuerRequest>,
    ) -> Result<Response<RemoveIssuerResponse>, Status> {
        let req = request.into_inner();
        self.issuer_registry.remove_issuer(&req.issuer_did)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(RemoveIssuerResponse {}))
    }

    async fn deactivate_issuer(
        &self,
        request: Request<DeactivateIssuerRequest>,
    ) -> Result<Response<DeactivateIssuerResponse>, Status> {
        let req = request.into_inner();
        self.issuer_registry.deactivate_issuer(&req.issuer_did)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DeactivateIssuerResponse {}))
    }

    async fn get_issuer(
        &self,
        request: Request<GetIssuerRequest>,
    ) -> Result<Response<GetIssuerResponse>, Status> {
        let req = request.into_inner();
        let issuer = self.issuer_registry.get_issuer_record(&req.issuer_did)
            .ok_or(Status::not_found("Issuer not found"))?;

        Ok(Response::new(GetIssuerResponse {
            vault_ref: issuer.vault_ref,
            public_key: issuer.public_key,
            active: issuer.active,
        }))
    }

    async fn get_did_document(
        &self,
        request: Request<GetDidDocumentRequest>,
    ) -> Result<Response<GetDidDocumentResponse>, Status> {
        let op_did = request.into_inner().operational_did;
        let doc = self.did_registry
            .get_did_document(&op_did)
            .ok_or(Status::not_found("DID not found"))?;
    
        Ok(Response::new(GetDidDocumentResponse {
            did_document: doc,
        }))
    }
    
    async fn store_did_document(
        &self,
        request: Request<StoreDidDocumentRequest>,
    ) -> Result<Response<StoreDidDocumentResponse>, Status> {
        let req = request.into_inner();
        self.did_registry
            .update_did_document(&req.operational_did, req.did_document)
            .map_err(|e| Status::internal(e.to_string()))?;
    
        Ok(Response::new(StoreDidDocumentResponse {}))
    }

    async fn rotate_operational_did(
        &self,
        request: Request<RotateOperationalDidRequest>,
    ) -> Result<Response<RotateOperationalDidResponse>, Status> {
        let req = request.into_inner();
        self.did_registry
            .rotate_operational_did(req.old_did, req.new_did)
            .map_err(|e| Status::internal(e.to_string()))?;
    
        Ok(Response::new(RotateOperationalDidResponse {}))
    }    
}
