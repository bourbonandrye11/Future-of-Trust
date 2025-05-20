// File: src/dkg/engine.rs

use std::collections::HashMap;
use std::sync::Mutex;

use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::dkg::{self, Round1Package, Round2Package, KeyGenMachine};
use frost_core::ciphersuite::Ciphersuite;
use frost_ed25519::Ed25519;
use frost_core::group::Group;
use frost_core::Curve;

use rand_core::OsRng;
use serde_json;

use crate::dkg::types::*;
use crate::relay::RelayClient;
use crate::registry::{OperationalDIDRegistry, MPCGroupDescriptor, MPCMemberDescriptor};
use crate::vault;

/// Node-local distributed key generation engine
pub struct DKGEngine {
    pub sessions: Mutex<HashMap<String, DKGSession>>,
    pub did_registry: OperationalDIDRegistry,
    pub relay: RelayClient,
    pub node_id: String,
}

impl DKGEngine {
    /// Start a new session and return the session ID
    pub fn start_session(&self, op_did: String, threshold: u8, participant_ids: Vec<String>) -> Result<String, DKGError> {
        let mut sessions = self.sessions.lock().unwrap();

        let id = frost_core::Identifier::try_from(self.node_id.as_bytes()).unwrap();
        let mut machine = KeyGenMachine::<Ed25519>::new(&id, threshold, &participant_ids).map_err(|e| DKGError::CryptoFailure(format!("KeyGen init: {e:?}")))?;

        let (round1_pkg, _machine) = machine.round1().map_err(|e| DKGError::CryptoFailure(format!("Round1 failed: {e:?}")))?;
        let group_id = uuid::Uuid::new_v4().to_string();

        let local_state = DKGLocalState {
            operational_did: op_did.clone(),
            threshold,
            participant_ids: participant_ids.clone(),
            round1_received: HashMap::new(),
            round2_received: HashMap::new(),
            finalized: false,
            keygen_machine: Some(_machine),
        };

        sessions.insert(group_id.clone(), DKGSession {
            group_id: group_id.clone(),
            local: local_state,
        });

        // Broadcast Round1
        let msg = bincode::serialize(&DKGMessage::Round1(bincode::serialize(&round1_pkg).unwrap())).unwrap();
        for peer_id in participant_ids.iter().filter(|id| *id != &self.node_id) {
            self.relay.send_message(&group_id, peer_id, msg.clone())?;
        }

        Ok(group_id)
    }

    /// Handle incoming Round1 or Round2 message
    pub fn handle_message(&self, group_id: &str, from: &str, msg: Vec<u8>) -> Result<(), DKGError> {
        let dkg_msg: DKGMessage = bincode::deserialize(&msg).map_err(|_| DKGError::MessageMalformed)?;
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(group_id).ok_or(DKGError::SessionNotFound)?;

        match dkg_msg {
            DKGMessage::Round1(raw) => {
                session.local.round1_received.insert(from.to_string(), raw);
            }
            DKGMessage::Round2(raw) => {
                session.local.round2_received.insert(from.to_string(), raw);
            }
            _ => {}
        }

        Ok(())
    }

    /// After receiving all Round1s, broadcast our Round2
    pub fn broadcast_round2(&self, group_id: &str) -> Result<(), DKGError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(group_id).ok_or(DKGError::SessionNotFound)?;
        let machine = session.local.keygen_machine.take().ok_or(DKGError::CryptoFailure("Missing state".into()))?;

        let mut received = Vec::new();
        for (peer_id, raw) in &session.local.round1_received {
            let pkg: Round1Package = bincode::deserialize(raw).map_err(|_| DKGError::MessageMalformed)?;
            let id = frost_core::Identifier::try_from(peer_id.as_bytes()).unwrap();
            received.push((id, pkg));
        }

        let (round2_pkg, machine2) = machine.round2(&received).map_err(|e| DKGError::CryptoFailure(format!("Round2: {e:?}")))?;
        session.local.keygen_machine = Some(machine2);

        let msg = bincode::serialize(&DKGMessage::Round2(bincode::serialize(&round2_pkg).unwrap())).unwrap();
        for peer_id in session.local.participant_ids.iter().filter(|id| *id != &self.node_id) {
            self.relay.send_message(group_id, peer_id, msg.clone())?;
        }

        Ok(())
    }

    /// Finalize and store the share locally
    pub fn finalize(&self, group_id: &str) -> Result<Vec<u8>, DKGError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.remove(group_id).ok_or(DKGError::SessionNotFound)?;

        let machine = session.local.keygen_machine.ok_or(DKGError::CryptoFailure("No state".into()))?;
        let mut received = Vec::new();
        for (peer_id, raw) in session.local.round2_received {
            let pkg: Round2Package = bincode::deserialize(&raw).map_err(|_| DKGError::MessageMalformed)?;
            let id = frost_core::Identifier::try_from(peer_id.as_bytes()).unwrap();
            received.push((id, pkg));
        }

        let (key_package, pubkeys) = machine.finish(&received).map_err(|e| DKGError::CryptoFailure(format!("Finalize failed: {e:?}")))?;

        // added this in to query registry for vault_id since add_shard needs vault_id
        // optionally could add a helper in vault which I will place and comment out
        let vault_id = registry
            .get_vault_id_for_operational_did(&session.local.operational_did)
            .ok_or(DKGError::VaultNotFound)?;

        let shard = key_package.secret_share().serialize();
        vault::add_shard(&vault_id, &base64::encode(&shard))
            .map_err(|e| DKGError::VaultStorageFailed)?;

        // This is what we'd use if we utilized the helper. 
        // vault::add_shard_for_did(registry, &session.local.operational_did, &base64::encode(&shard))?;


       // this is the original vault call that used did if I end up switching to the helper
       // vault::add_shard(&session.local.operational_did, &base64::encode(&shard)).map_err(|e| DKGError::VaultStorageFailed)?;

        let mpc_group = MPCGroupDescriptor {
            group_id: group_id.to_string(),
            members: pubkeys.iter().map(|(id, pk)| MPCMemberDescriptor {
                node_id: String::from_utf8_lossy(id.serialize()).to_string(),
                public_share: base64::encode(pk.serialize()),
            }).collect(),
            threshold: session.local.threshold,
            dkg_protocol: Some("frost-ed25519-dkg-v1".into()),
            session_state: None,
        };

        self.did_registry.set_mpc_group(&session.local.operational_did, mpc_group).map_err(|_| DKGError::RegistryUpdateFailed)?;

        Ok(shard)
    }
}