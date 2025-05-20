
use std::collections::HashMap;
use std::time::Duration;
use base64;

use crate::mpc::signing_session::SigningSession;
use crate::registry::{OperationalDIDRegistry, MPCGroupDescriptor};
use crate::vault;
use crate::relay::RelayClient;

use frost_ed25519::prelude::*;
use frost_ed25519::keys::PublicKeyPackage;

use vault::custody_vault_client::CustodyVaultClient;
use vault::{
    GenerateNonceRequest, PartialSignRequest, PeerCommitment,
};

/// Drives the threshold signing flow across custody nodes
pub struct MPCSigningCoordinator {
    pub registry: Arc<OperationalDIDRegistry>,
    pub relay: Arc<RelayClient>,
    pub local_node_id: String,
}

impl MPCSigningCoordinator {
    /// Executes a full MPC signing round
    pub async fn sign(&self, op_did: &str, message: Vec<u8>) -> Result<Vec<u8>, String> {
        // STEP 1: Load signing group
        let group = self.registry.get_mpc_group(op_did)
            .ok_or("No MPC group for DID")?;
        let participants = group.members.iter().map(|m| m.node_id.clone()).collect::<Vec<_>>();

        // STEP 2: Initialize local session tracking
        let mut session = SigningSession::new(&self.registry, op_did, message.clone())?;

        // STEP 3: Ask vaults to generate + share nonces
        for peer in &participants {
            let nonce = self.call_generate_nonce(peer, op_did).await?;
            session.record_commitment(peer, nonce);
        }

        // STEP 4: Send message + commitments, collect signature shares
        for peer in &participants {
            let sig = self.call_partial_sign(peer, op_did, &message, &session).await?;
            session.record_partial(peer, sig);
        }

        if !session.ready_to_aggregate() {
            return Err("Not enough signature shares collected".into());
        }

        // STEP 5: Aggregate final signature
        let final_sig = self.aggregate_signature(&session, &group)?;
        Ok(final_sig)
    }

    /// Calls a vault to generate its nonce commitment
    async fn call_generate_nonce(&self, peer: &str, op_did: &str) -> Result<Vec<u8>, String> {
        let uri = format!("http://{peer}");
        let mut client = CustodyVaultClient::connect(uri)
            .await
            .map_err(|e| format!("Vault connect failed: {e:?}"))?;
    
        let resp = client.generate_nonce(GenerateNonceRequest {
            operational_did: op_did.to_string(),
        }).await.map_err(|e| format!("RPC failed: {e:?}"))?;
    
        Ok(resp.into_inner().commitment)
    }    

    /// Calls a vault to sign the message with its shard + nonce
    async fn call_partial_sign(
        &self,
        peer: &str,
        op_did: &str,
        message: &[u8],
        session: &SigningSession,
    ) -> Result<Vec<u8>, String> {
        let uri = format!("http://{peer}");
        let mut client = CustodyVaultClient::connect(uri)
            .await
            .map_err(|e| format!("Vault connect failed: {e:?}"))?;
    
        let commitments = session
            .nonce_commitments
            .iter()
            .map(|(peer_id, commitment)| PeerCommitment {
                peer_id: peer_id.clone(),
                commitment: commitment.clone(),
            })
            .collect::<Vec<_>>();
    
        let resp = client.partial_sign(PartialSignRequest {
            operational_did: op_did.to_string(),
            message: message.to_vec(),
            commitments,
        }).await.map_err(|e| format!("RPC failed: {e:?}"))?;
    
        Ok(resp.into_inner().signature)
    }    

    /// Aggregates valid partials into a full Schnorr signature
    fn aggregate_signature(&self, session: &SigningSession, group: &MPCGroupDescriptor) -> Result<Vec<u8>, String> {
        let threshold = group.threshold as usize;
        let mut shares = vec![];

        for (peer_id, sig_bytes) in &session.partial_signatures {
            let sig = Signature::from_bytes(sig_bytes).map_err(|_| "Invalid sig")?;
            let id = Identifier::try_from(peer_id.as_bytes()).map_err(|_| "Invalid ID")?;
            shares.push((id, sig));
        }

        if shares.len() < threshold {
            return Err("Too few shares".into());
        }

        let group_pubkey = self.recover_group_key(group)?;
        let agg = frost_ed25519::aggregate(&shares, &session.message, &group_pubkey)
            .map_err(|e| format!("Aggregation failed: {:?}", e))?;

        Ok(agg.to_bytes().to_vec())
    }

    /// Rebuilds group pubkey from MPCGroupDescriptor
    fn recover_group_key(&self, group: &MPCGroupDescriptor) -> Result<PublicKeyPackage, String> {
        let pubkeys = group.members.iter()
            .map(|m| {
                let id = Identifier::try_from(m.node_id.as_bytes()).map_err(|_| "bad ID")?;
                let pk_bytes = base64::decode(&m.public_share).map_err(|_| "bad base64")?;
                let pk = frost_ed25519::keys::VerifyingKey::from_bytes(&pk_bytes).map_err(|_| "bad key")?;
                Ok((id, pk))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        PublicKeyPackage::try_from(pubkeys).map_err(|e| format!("bad group pubkey: {e:?}"))
    }
}
