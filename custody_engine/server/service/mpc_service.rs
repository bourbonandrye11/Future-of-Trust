

use tonic::{Request, Response, Status};

use mpc::custody_mpc_server::{CustodyMpc, CustodyMpcServer};
use mpc::{SignMessageRequest, SignMessageResponse};

use crate::mpc::coordinator::MPCSigningCoordinator;
use mpc::{ProvisionVaultAndShardsRequest, ProvisionVaultAndShardsResponse};
use crate::vault::{store_record, VaultRecord};
use crate::registry::{OperationalDID, RootDID, MPCGroupDescriptor, MPCMemberDescriptor};

use uuid::Uuid;

pub mod custody {
    tonic::include_proto!("mpc");
}

#[derive(Clone)]
pub struct CustodyMpcService {
    pub coordinator: MPCSigningCoordinator,
}

async fn generate_new_vault_id() -> String {
    format!("vault-{}", Uuid::new_v4())
}

#[tonic::async_trait]
impl CustodyMpc for CustodyMpcService {
    async fn sign_message(
        &self,
        request: Request<SignMessageRequest>,
    ) -> Result<Response<SignMessageResponse>, Status> {
        let req = request.into_inner();

        let sig = self.coordinator
            .sign(&req.operational_did, req.message)
            .await
            .map_err(|e| Status::internal(format!("Sign failed: {e}")))?;

        Ok(Response::new(SignMessageResponse {
            signature: sig,
        }))
    }

    async fn provision_vault_and_shards(
        &self,
        request: Request<ProvisionVaultAndShardsRequest>,
    ) -> Result<Response<ProvisionVaultAndShardsResponse>, Status> {
        let req = request.into_inner();
        let op_did = OperationalDID(req.operational_did.clone());
        let root_did = RootDID(req.root_did.clone());

        // Step 1: create vault_id
        let vault_id = generate_new_vault_id().await;

        // Step 2: create empty VaultRecord
        let record = VaultRecord {
            shard: None,
            bbs_private_key: None,
            public_keys: vec![],
            vcs: Default::default(),
            active_nonce: None,
        };

        store_record(&vault_id, &record)
            .map_err(|e| Status::internal(format!("vault store failed: {e}")))?;

        // Step 3: trigger DKG
        let peers = discover::discover_peer_nodes("custody-nodes.default.svc.cluster.local")
            .await.map_err(|e| Status::internal(format!("peer discovery failed: {e}")))?;

        let threshold = 2; // TODO: replace with policy engine call
        let group_id = orchestrator::orchestrate_dkg(&req.operational_did, threshold, peers.clone())
            .await.map_err(|e| Status::internal(format!("DKG orchestration failed: {e}")))?;

        // Step 4: assemble MPC group descriptor
        let mpc_group = MPCGroupDescriptor {
            group_id: group_id.clone(),
            members: peers.iter().enumerate().map(|(i, node)| MPCMemberDescriptor {
                vault_reference: vault_id.clone(),
                custody_node_id: node.clone(),
                shard_index: i as u8,
            }).collect(),
            threshold,
            dkg_protocol: Some("frost-dkg-v1".to_string()),
            session_state: None,
        };

        self.coordinator.registry.register_operational_did(
            op_did.clone(),
            root_did.clone(),
            vault_id.clone(),
            vec![], // DID doc will be added later
        ).map_err(|e| Status::internal(format!("register DID failed: {e:?}")))?;

        self.coordinator.registry.set_mpc_group(&op_did, mpc_group.clone())
            .map_err(|e| Status::internal(format!("set MPC group failed: {e:?}")))?;

        let group_pubkey = aggregate_group_public_key(&mpc_group)
        .map_err(|e| Status::internal(e))?;
    
        Ok(Response::new(ProvisionVaultAndShardsResponse {
            vault_id,
            group_id,
            group_public_key: group_pubkey,
        }))
    }

    fn aggregate_group_public_key(group: &MPCGroupDescriptor) -> Result<Vec<u8>, String> {
        use frost_ed25519::keys::VerifyingKey;
        use frost_ed25519::keys::PublicKeyPackage;
        use frost_ed25519::Identifier;
        use std::collections::HashMap;
    
        let mut pubkeys = HashMap::new();
    
        for member in &group.members {
            let id = Identifier::try_from(member.custody_node_id.as_bytes())
                .map_err(|_| "Invalid Identifier")?;
    
            let pk_b64 = &member.public_share;
            let pk_bytes = base64::decode(pk_b64).map_err(|_| "Invalid base64 public key")?;
            let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|_| "Invalid verifying key")?;
    
            pubkeys.insert(id, verifying_key);
        }
    
        let package = PublicKeyPackage::try_from(pubkeys)
            .map_err(|e| format!("Group public key aggregation failed: {:?}", e))?;
    
        Ok(package.group_public().to_bytes().to_vec())
    }

    async fn rotate_shards(
        &self,
        request: Request<RotateShardsRequest>,
    ) -> Result<Response<RotateShardsResponse>, Status> {
        let op_did = request.into_inner().operational_did;
    
        // Step 1: Get current vault_id
        let vault_id = self.coordinator.registry
            .get_vault_id_for_operational_did(&op_did)
            .ok_or(Status::not_found("Vault ID not found"))?;
    
        // Step 2: Discover peers again (could also reuse existing group)
        let peers = discover::discover_peer_nodes("custody-nodes.default.svc.cluster.local")
            .await.map_err(|e| Status::internal(format!("Discovery failed: {e}")))?;
    
        let threshold = 2; // Load from policy engine if needed
    
        // Step 3: Run orchestrator to rotate shards
        let new_group_id = orchestrator::orchestrate_dkg(&op_did, threshold, peers.clone())
            .await.map_err(|e| Status::internal(format!("DKG failed: {e}")))?;
    
        // Step 4: Replace MPC group in registry
        let new_group = MPCGroupDescriptor {
            group_id: new_group_id.clone(),
            members: peers.iter().enumerate().map(|(i, node)| MPCMemberDescriptor {
                vault_reference: vault_id.clone(),
                custody_node_id: node.clone(),
                shard_index: i as u8,
            }).collect(),
            threshold,
            dkg_protocol: Some("frost-dkg-v1".to_string()),
            session_state: None,
        };
    
        self.coordinator.registry.set_mpc_group(&OperationalDID(op_did.clone()), new_group)
            .map_err(|e| Status::internal(format!("Failed to update MPC group: {e:?}")))?;

        // Step 5: Aggregate new public key
        let group_pubkey = aggregate_group_public_key(&new_group)
            .map_err(|e| Status::internal(e))?;

        // Step 6: Update vault with new public key
        vault::add_public_key(&vault_id, &group_pubkey)
            .map_err(|e| Status::internal(format!("Failed to store pubkey: {e}")))?;

        // Step 7: Update DID document with new pubkey
        let mut doc = registry.get_did_document(&OperationalDID(op_did.clone()))
            .ok_or(Status::not_found("DID document not found"))?;

        if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&doc) {
        if let Some(vm) = json["verificationMethod"].as_array_mut() {
            for method in vm.iter_mut() {
                if let Some(pk) = method.get_mut("publicKeyMultibase") {
                    *pk = serde_json::Value::String(multibase::encode(multibase::Base::Base58Btc, &group_pubkey));
                }
            }
        }

        let updated = serde_json::to_vec(&json).map_err(|_| Status::internal("Serialize failed"))?;
        registry.update_did_document(&OperationalDID(op_did.clone()), updated)?;
        }
    
        Ok(Response::new(RotateShardsResponse {
            new_group_id,
        }))
    }
}
