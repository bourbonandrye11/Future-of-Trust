

use tonic::{Request, Response, Status};
use crate::proto::custody_vc::{
    custody_vc_server::CustodyVc, // Generated service trait
    SignCredentialRequest, SignCredentialResponse,
    StoreCredentialRequest, StoreCredentialResponse,
    GetCredentialRequest, GetCredentialResponse,
    RevokeCredentialRequest, RevokeCredentialResponse,
};

use crate::vault;
use crate::issuer_registry::IssuerRegistry;
use crate::bbs::{extract_vc_messages, sign_vc_messages};
use crate::bbs; 

use crate::vc_store::VcStore;
use crate::mpc::MpcSigningCoordinator; // hypothetical existing module
use crate::bbs::BbsPlusSigner;         // hypothetical BBS+ module

/// Struct holding service dependencies (vault, registry, VC store)
pub struct CustodyVcService {
    //pub vault: Vault,
    pub issuer_registry: IssuerRegistry,
    //pub vc_store: VcStore,
    //pub mpc_coordinator: MpcSigningCoordinator,
    //pub bbs_signer: BbsPlusSigner,
}

#[tonic::async_trait]
impl CustodyVc for CustodyVcService {
    /// Sign a VC with either MPC (root) or BBS+ (attribute)
    async fn sign_credential(
        &self,
        request: Request<SignCredentialRequest>,
    ) -> Result<Response<SignCredentialResponse>, Status> {
        let req = request.into_inner();

        // Determine vault_id from issuer DID (in your registry)
        let vault_id = req.issuer_did.clone(); // TODO: replace with registry lookup when wiring

        let vc_type = req.vc_type.as_str();
        let vc_json = req.vc_json;

        // Check issuer authorization - not part of new code but leaving for now
        if !self.issuer_registry.is_authorized_issuer(&req.issuer_did) {
            return Err(Status::permission_denied("DID is not an authorized issuer"));
        }

        // NEW match added to route Root and Attribute VCs. I moved everything from 
        // Extract BBS+ messages to signed_vc_json into the match arm. it was part of the 
        // original code if needed to extract later. 
        // Match based on VC type
        match vc_type {
            "root" => {
                // TODO: Replace with actual MPC signing coordinator
                println!("[sign_credential] Routing root VC through MPC signing stub");

                let fake_signature = "MPC_SIGNATURE_PLACEHOLDER";
                let mut vc: serde_json::Value = serde_json::from_str(&vc_json)
                    .map_err(|e| Status::invalid_argument(format!("Invalid JSON: {:?}", e)))?;

                vc["proof"] = serde_json::json!({
                    "type": "MPCSignature2023",
                    "created": chrono::Utc::now().to_rfc3339(),
                    "signature": fake_signature,
                });

                let signed_json = serde_json::to_string(&vc).unwrap();

                // Store in vault
                let vc_id = extract_vc_id(&signed_json).ok_or_else(|| Status::invalid_argument("Missing VC id"))?;
                vault::add_vc(&vault_id, &vc_id, &signed_json)
                    .map_err(|e| Status::internal(e))?;

                Ok(Response::new(SignCredentialResponse {
                    signed_vc_json: signed_json,
                }))
            }

            "attribute" => {
                println!("[sign_credential] Using vault-backed BBS+ signer");

                let signed_vc = bbs::sign_vc_with_vault(&req.issuer_did, &vc_json)
                    .map_err(|e| Status::internal(e))?;

                let vc_id = extract_vc_id(&signed_vc)
                    .ok_or(Status::invalid_argument("VC missing id"))?;

                vault::add_vc(&req.issuer_did, &vc_id, &signed_vc)
                    .map_err(|e| Status::internal(e))?;

                Ok(Response::new(SignCredentialResponse {
                    signed_vc_json: signed_vc,
                }))
            }

            _ => Err(Status::invalid_argument("Unknown vc_type")),
        }
    }

    /// Store an externally signed VC
    async fn store_credential(
        &self,
        request: Request<StoreCredentialRequest>,
    ) -> Result<Response<StoreCredentialResponse>, Status> {
        let req = request.into_inner();
        let vault_id = req.subject_did.clone(); // assume subject DID maps to vault ID

        let vc_id = extract_vc_id(&req.signed_vc_json)
            .ok_or_else(|| Status::invalid_argument("Missing VC id"))?;

        vault::add_vc(&vault_id, &vc_id, &req.signed_vc_json)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(StoreCredentialResponse { success: true }))
    }

    /// Fetch a VC (if not revoked)
    async fn get_credential(
        &self,
        request: Request<GetCredentialRequest>,
    ) -> Result<Response<GetCredentialResponse>, Status> {
        let req = request.into_inner();
        let vault_id = req.subject_did.clone();

        let vc_json = vault::get_vc(&vault_id, &req.vc_id)
            .map_err(|e| Status::not_found(e))?;

        Ok(Response::new(GetCredentialResponse { signed_vc_json: vc_json }))
    }

    /// Mark VC as revoked
    async fn revoke_credential(
        &self,
        request: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        let req = request.into_inner();
        let vault_id = req.issuer_did.clone(); // assume issuer owns this VC

        vault::revoke_vc(&vault_id, &req.vc_id)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(RevokeCredentialResponse { success: true }))
    }

    /// GET VC BY TYPE
    async fn get_vc_by_type(
        &self,
        request: Request<GetVcByTypeRequest>,
    ) -> Result<Response<GetVcByTypeResponse>, Status> {
        let req = request.into_inner();
        let vc_json = vault::get_vc_by_type(&req.vault_id, &req.vc_type)
            .map_err(|e| Status::not_found(e))?;
        Ok(Response::new(GetVcByTypeResponse { vc_json }))
    }

    /// DELETE VC
    async fn delete_vc(
        &self,
        request: Request<DeleteVcRequest>,
    ) -> Result<Response<DeleteVcResponse>, Status> {
        let req = request.into_inner();
        vault::delete_vc(&req.vault_id, &req.vc_id)
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(DeleteVcResponse { success: true }))
    }

    /// BBS+ PRIVATE
    async fn get_bbs_private_key(
        &self,
        request: Request<GetBbsKeyRequest>,
    ) -> Result<Response<GetBbsKeyResponse>, Status> {
        let key = vault::get_bbs_private_key(&request.into_inner().vault_id)
            .map_err(|e| Status::not_found(e))?;
        Ok(Response::new(GetBbsKeyResponse { key }))
    }

    async fn set_bbs_private_key(
        &self,
        request: Request<SetBbsKeyRequest>,
    ) -> Result<Response<SetBbsKeyResponse>, Status> {
        let req = request.into_inner();
        vault::set_bbs_private_key(&req.vault_id, &req.key)
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(SetBbsKeyResponse { success: true }))
    }

    /// BBS+ PUBLIC
    async fn get_bbs_public_key(
        &self,
        request: Request<GetBbsKeyRequest>,
    ) -> Result<Response<GetBbsKeyResponse>, Status> {
        let key = vault::get_bbs_public_key(&request.into_inner().vault_id)
            .map_err(|e| Status::not_found(e))?;
        Ok(Response::new(GetBbsKeyResponse { key }))
    }

    async fn set_bbs_public_key(
        &self,
        request: Request<SetBbsKeyRequest>,
    ) -> Result<Response<SetBbsKeyResponse>, Status> {
        let req = request.into_inner();
        vault::set_bbs_public_key(&req.vault_id, &req.key)
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(SetBbsKeyResponse { success: true }))
    }

    /// PUBLIC KEYS
    async fn get_public_keys(
        &self,
        request: Request<GetPublicKeysRequest>,
    ) -> Result<Response<GetPublicKeysResponse>, Status> {
        let keys = vault::get_public_keys(&request.into_inner().vault_id)
            .map_err(|e| Status::not_found(e))?;
        Ok(Response::new(GetPublicKeysResponse { keys }))
    }

    async fn add_public_key(
        &self,
        request: Request<AddPublicKeyRequest>,
    ) -> Result<Response<PublicKeyUpdateResponse>, Status> {
        let req = request.into_inner();
        vault::add_public_key(&req.vault_id, &req.key)
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(PublicKeyUpdateResponse { success: true }))
    }

    async fn remove_public_key(
        &self,
        request: Request<RemovePublicKeyRequest>,
    ) -> Result<Response<PublicKeyUpdateResponse>, Status> {
        let req = request.into_inner();
        vault::remove_public_key(&req.vault_id, &req.key)
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(PublicKeyUpdateResponse { success: true }))
    }

    async fn generate_issuer_keys(
        &self,
        request: Request<GenerateIssuerKeysRequest>,
    ) -> Result<Response<GenerateIssuerKeysResponse>, Status> {
        let issuer_did = request.into_inner().issuer_did;
    
        let (_sk, pk) = bbs::generate_and_store_issuer_keys(&issuer_did)
            .map_err(|e| Status::internal(e))?;
    
        Ok(Response::new(GenerateIssuerKeysResponse {
            public_key: pk,
        }))
    }
}

/// Extract `id` field from VC JSON
fn extract_vc_id(vc_json: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(vc_json).ok()?;
    json.get("id")?.as_str().map(|s| s.to_string())
}
