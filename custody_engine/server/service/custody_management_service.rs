

use tonic::{Request, Response, Status};
use custody::custody_management_service_server::CustodyManagementService;
use custody::*;
use crate::registry::OperationalDIDRegistry;
use crate::types::{OperationalDID as InternalOperationalDID, RootDID as InternalRootDID, VerifiableCredential as InternalVC};
use crate::vault::Vault;
use crate::error::CustodyError;

/// Core gRPC service implementation
pub struct CustodyManagementServer {
    pub registry: OperationalDIDRegistry,
}

#[tonic::async_trait]
impl CustodyManagementService for CustodyManagementServer {

    // ======================
    // 🔐 DID Management
    // ======================

    async fn provision_identity_material(
        &self,
        request: Request<ProvisionIdentityMaterialRequest>,
    ) -> Result<Response<ProvisionIdentityMaterialResponse>, Status> {
        let req = request.into_inner();
    
        let op_did = InternalOperationalDID(req.operational_did);
        let root_did = InternalRootDID(req.root_did);
    
        // Generate vault + FROST group + key shards
        // this method doesn't exist yet in main code
        let vault = Vault::new_with_frost_group()
            .map_err(|e| Status::internal(format!("Vault init failed: {}", e)))?;
    
        // Register DID + vault mapping
        self.registry.register(
            op_did.clone(),
            root_did.clone(),
            vault.clone(),
        ).map_err(|e| Status::internal(format!("Registry insert failed: {}", e)))?;
    
        // Get public key commitment for DID document
        // this method doesn't exist yet in main code
        let pubkey_commitment = vault.get_public_key_commitment()
            .map_err(|e| Status::internal(format!("Failed to get public key: {}", e)))?;
    
        // Optional: custody proof (stub for now)
        // this method doesn't exist yet in main code
        let custody_proof = vault.generate_custody_proof()
            .map_err(|e| Status::internal(format!("Failed to generate custody proof: {}", e)))?;
    
        Ok(Response::new(ProvisionIdentityMaterialResponse {
            public_key_commitment: pubkey_commitment,
            // this method doesn't exist yet in main code
            vault_reference: vault.get_reference(),
            custody_proof,
        }))
    }

    async fn store_did_document(
        &self,
        request: Request<StoreDIDDocumentRequest>,
    ) -> Result<Response<StoreDIDDocumentResponse>, Status> {
        let req = request.into_inner();

        let op_did = InternalOperationalDID(req.operational_did);
        let root_did = InternalRootDID(req.root_did);
        let did_doc = req.did_document;

        // Validate non-empty payload
        if did_doc.is_empty() {
            return Err(Status::invalid_argument("DID document cannot be empty"));
        }

        // Check if entry exists and store DID document
        self.registry.store_did_document(&op_did, did_doc.clone())
            .map_err(|e| Status::internal(format!("Failed to store DID document: {}", e)))?;

        // Add audit event
        self.registry.audit_event(
            &op_did,
            format!("Stored DID document for operational DID {}", op_did.0),
        );

        Ok(Response::new(StoreDIDDocumentResponse {
            success: true,
            message: format!("DID document stored successfully for {}", op_did.0),
        }))
    }

    /// Get DID document for operational DID function
    async fn get_did_document(
        &self,
        request: Request<GetDIDDocumentRequest>,
    ) -> Result<Response<GetDIDDocumentResponse>, Status> {
        let req = request.into_inner();

        let op_did = InternalOperationalDID(req.operational_did);

        match self.registry.get_did_document(&op_did) {
            Ok(Some(did_doc)) => Ok(Response::new(GetDIDDocumentResponse {
                did_document: did_doc,
                found: true,
            })),
            Ok(None) => Ok(Response::new(GetDIDDocumentResponse {
                did_document: vec![],
                found: false,
            })),
            Err(e) => Err(Status::internal(format!("Failed to retrieve DID document: {}", e))),
        }

        self.registry.audit_event(
            &op_did,
            "Stored/queried DID document".to_string(),
        );
    }

    /// need to see if root did exists, find its vault and register opdid in that vault with root. not new vault.
    // needs to be refactored to only update mappings, manage rotation/revocation and rely on vaults
    // with ProvisionIdentityMaterial
    async fn register_operational_did(
        &self,
        request: Request<RegisterOperationalDIDRequest>,
    ) -> Result<Response<RegisterOperationalDIDResponse>, Status> {
        let req = request.into_inner();
        let op_did = InternalOperationalDID(req.operational_did.unwrap().id);
        let root_did = InternalRootDID(req.root_did.unwrap().id);
        let vault = Vault::new(); // fresh vault for new DID

        self.registry.register(op_did, root_did, vault)
            .map_err(|e| Status::internal(format!("Failed to register DID: {}", e)))?;

        Ok(Response::new(RegisterOperationalDIDResponse {}))
    }

    // needs to be refactored to only update mappings, manage rotation/revocation and rely on vaults
    // with ProvisionIdentityMaterial
    async fn rotate_operational_did(
        &self,
        request: Request<RotateOperationalDIDRequest>,
    ) -> Result<Response<RotateOperationalDIDResponse>, Status> {
        let req = request.into_inner();
        let old_did = InternalOperationalDID(req.old_did.unwrap().id);
        let new_did = InternalOperationalDID(req.new_did.unwrap().id);

        self.registry.rotate_operational_did(&old_did, new_did)
            .map_err(|e| Status::internal(format!("Failed to rotate DID: {}", e)))?;

        Ok(Response::new(RotateOperationalDIDResponse {}))
    }

    async fn revoke_operational_did(
        &self,
        request: Request<RevokeOperationalDIDRequest>,
    ) -> Result<Response<RevokeOperationalDIDResponse>, Status> {
        let req = request.into_inner();
        let op_did = InternalOperationalDID(req.operational_did.unwrap().id);

        self.registry.revoke_operational_did(&op_did)
            .map_err(|e| Status::internal(format!("Failed to revoke DID: {}", e)))?;

        Ok(Response::new(RevokeOperationalDIDResponse {}))
    }

    async fn get_root_for_operational_did(
        &self,
        request: Request<GetRootForOperationalDIDRequest>,
    ) -> Result<Response<GetRootForOperationalDIDResponse>, Status> {
        let req = request.into_inner();
        let op_did = InternalOperationalDID(req.operational_did.unwrap().id);

        let root_did = self.registry.get_root_for_operational_did(&op_did)
            .map_err(|e| Status::internal(format!("Failed to get root DID: {}", e)))?;

        Ok(Response::new(GetRootForOperationalDIDResponse {
            root_did: Some(RootDID { id: root_did.0 }),
        }))
    }

    // ======================
    // need to look at integrating these later. this was skimmed over after VCManager.
    // it is for issuing, signing, revoking, retrieving VCs + issuer. funcs are also missing in core
    // ======================

    async fn sign_credential(
        &self,
        request: Request<SignCredentialRequest>,
    ) -> Result<Response<SignCredentialResponse>, Status> {
        let req = request.into_inner();
        let issuer_did = InternalOperationalDID(req.issuer_did);
    
        // Lookup custody vault
        let vault = self.registry.get_vault_for_operational_did(&issuer_did)
            .map_err(|e| Status::internal(format!("Vault lookup failed: {}", e)))?;
    
        // Ensure DID is authorized to issue (not a subject/root-only DID)
        if !vault.is_issuer() {
            return Err(Status::permission_denied("DID is not authorized as an issuer"));
        }
    
        // Get or derive BBS+ key
        let bbs_plus_key = vault.get_bbs_plus_key()
            .map_err(|e| Status::internal(format!("BBS+ key missing: {}", e)))?;
    
        // Sign VC payload (using MPC or single-party, depending on design)
        let signed_vc_json = bbs_plus_sign(&req.vc_json, &bbs_plus_key)
            .map_err(|e| Status::internal(format!("BBS+ signing failed: {}", e)))?;
    
        Ok(Response::new(SignCredentialResponse { signed_vc_json }))
    }

    async fn store_credential(
        &self,
        request: Request<StoreCredentialRequest>,
    ) -> Result<Response<StoreCredentialResponse>, Status> {
        let req = request.into_inner();
        let subject_did = InternalOperationalDID(req.subject_did);
    
        let vault = self.registry.get_vault_for_operational_did(&subject_did)
            .map_err(|e| Status::internal(format!("Vault lookup failed: {}", e)))?;
    
        vault.store_verifiable_credential(req.signed_vc_json.clone())
            .map_err(|e| Status::internal(format!("VC storage failed: {}", e)))?;
    
        Ok(Response::new(StoreCredentialResponse {
            success: true,
            message: "Credential stored successfully".into(),
        }))
    }

    // get and revoke follow similar pattern it says but weren't covered...
    // =====================================================================

    // ======================
    // 🔐 VC Management
    // ======================

    async fn add_or_rotate_vcs(
        &self,
        request: Request<AddOrRotateVCsRequest>,
    ) -> Result<Response<AddOrRotateVCsResponse>, Status> {
        let req = request.into_inner();
        let op_did = InternalOperationalDID(req.operational_did.unwrap().id);
        let vcs: Vec<InternalVC> = req.vcs.into_iter().map(|vc| InternalVC(vc.payload)).collect();

        let vault = self.registry.get_vault_for_operational_did(&op_did)
            .map_err(|e| Status::internal(format!("Failed to get vault: {}", e)))?;

        vault.add_or_rotate_vcs(vcs)
            .map_err(|e| Status::internal(format!("Failed to add/rotate VCs: {}", e)))?;

        Ok(Response::new(AddOrRotateVCsResponse {}))
    }

    async fn get_vcs_for_operational_did(
        &self,
        request: Request<GetVCsForOperationalDIDRequest>,
    ) -> Result<Response<GetVCsForOperationalDIDResponse>, Status> {
        let req = request.into_inner();
        let op_did = InternalOperationalDID(req.operational_did.unwrap().id);

        let vault = self.registry.get_vault_for_operational_did(&op_did)
            .map_err(|e| Status::internal(format!("Failed to get vault: {}", e)))?;

        let vcs = vault.get_verifiable_credentials()
            .map_err(|e| Status::internal(format!("Failed to retrieve VCs: {}", e)))?;

        let proto_vcs = vcs.into_iter().map(|vc| VerifiableCredential { payload: vc.0 }).collect();

        Ok(Response::new(GetVCsForOperationalDIDResponse { vcs: proto_vcs }))
    }

    async fn verify_vc_integrity(
        &self,
        request: Request<VerifyVCIntegrityRequest>,
    ) -> Result<Response<VerifyVCIntegrityResponse>, Status> {
        let req = request.into_inner();
        let op_did = InternalOperationalDID(req.operational_did.unwrap().id);
        let vc = InternalVC(req.vc.unwrap().payload);

        let vault = self.registry.get_vault_for_operational_did(&op_did)
            .map_err(|e| Status::internal(format!("Failed to get vault: {}", e)))?;

        let is_valid = vault.verify_vc_integrity(&vc)
            .map_err(|e| Status::internal(format!("Failed to verify VC: {}", e)))?;

        Ok(Response::new(VerifyVCIntegrityResponse { valid: is_valid }))
    }

    // ======================
    // 🕵️ Audit Trail
    // ======================

    async fn get_vc_audit_trail(
        &self,
        request: Request<GetVCAuditTrailRequest>,
    ) -> Result<Response<GetVCAuditTrailResponse>, Status> {
        let req = request.into_inner();
        let op_did = InternalOperationalDID(req.operational_did.unwrap().id);

        let records = self.registry.get_vc_audit_trail(&op_did)
            .map_err(|e| Status::internal(format!("Failed to retrieve audit trail: {}", e)))?;

        let proto_records = records.into_iter().map(|r| AuditRecord {
            event_type: r.event_type_label().to_string(),
            message: r.message,
            timestamp: r.timestamp,
        }).collect();

        Ok(Response::new(GetVCAuditTrailResponse { records: proto_records }))
    }

    /// Handler for responding to partial signature requests on this node + distributed signing
    /// each custody node runs this handler, recieves partial signing requests
    /// locally signs the message with its shard and returns the result
    async fn request_partial_signature(
        &self,
        request: Request<RequestPartialSignatureRequest>,
    ) -> Result<Response<RequestPartialSignatureResponse>, Status> {
        let req = request.into_inner();
    
        // Lookup vault holding the shard for this DID
        let op_did = InternalOperationalDID(req.operational_did);
        let vault = self.registry.get_vault_for_operational_did(&op_did)
            .map_err(|e| Status::internal(format!("Vault lookup failed: {}", e)))?;
    
        // Compute partial signature
        let partial_sig = vault.compute_partial_signature(&req.message)
            .map_err(|e| Status::internal(format!("Partial signing failed: {}", e)))?;
    
        Ok(Response::new(RequestPartialSignatureResponse {
            partial_signature: partial_sig,
        }))
    }
}