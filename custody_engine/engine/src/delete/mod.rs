//! MPC signing session management.
//! 
//! engine/src/mpc/mod.rs
//! 
//! this was the original file that is no longer needed
//! moving it to remove folder
//! 
//! This module coordinates threshold key generation, signing session setup,
//! nonce management, partial signature creation, and aggregation into final signatures.

use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::keys::{generate_with_dealer, Identifier};
use frost_ed25519::SignatureShare; //partial signature returned by each signer
use frost_ed25519::parameters::FrostEd25519;
use rand::rngs::OsRng;
use frost_core::round1::{SigningCommitments, SigningNonces}; // Holds participants random nonce secrets & participants nonce secrets
use frost_core::round2::SignatureResponse; // to combine partial signatures into final signature
use frost_core::Group;
use frost_ed25519::Ed25519Sha512; // hash function used in FROST
use frost_core::sign::{calculate_lagrange_coefficient};
use frost_core::Ciphersuite;
use frost_ed25519::Ciphersuite as FrostCiphersuite;
use frost_ed25519::SignatureShare as FrostSignatureShare;
use frost_core::sign::{combine_signature_shares};
use frost_core::FrostError;

use std::collections::HashMap;

use crate::types::CustodyShard;
use crate::error::CustodyError;
use crate::vault::Vault;
use crate::types::ParticipantId;

/// A signing session tracks all nonces, commitments, and partial signatures for a message.
pub struct SigningSession {
    /// The message to be signed.
    pub message: Vec<u8>,
    /// dynamically record number of participants signing.
    pub threshold: usize,
    /// The group public key for the signing session.
    pub group_public_key: Vec<u8>, // NEW
    /// Secret nonces generated by each participant.
    pub nonces: HashMap<ParticipantId, SigningNonces>,
    /// Public nonce commitments from each participant.
    pub commitments: HashMap<ParticipantId, SigningCommitments>,
    /// NEW: Collected signature shares from participants
    pub signature_shares: HashMap<ParticipantId, SignatureShare>,
    /// Tracks which participants have already submitted their share.
    pub submitted_participants: HashSet<ParticipantId>,
}

impl SigningSession {
    /// Create a new signing session for the given message.
    /// the signature_shares map lets each signing session accumulate signature shares over time.
    pub fn new(message: Vec<u8>, threshold: usize) -> Self {
        SigningSession {
            message,
            threshold,
            group_public_key, //SigningSession now securely binds to the correct public key.
            nonces: HashMap::new(),
            commitments: HashMap::new(),
            signature_shares: HashMap::new(),
            submitted_participants: HashSet::new(),
        }
    }

        /// Generate fresh nonces and public commitments for a participant.
    pub fn generate_nonce(&mut self, participant_id: ParticipantId) -> Result<(), CustodyError> {
        // pull a secure random number generator from the OS
        let mut rng = OsRng;

        // Create new signing nonces (secret randomness)
        let nonces = SigningNonces::generate(&mut rng);

        // Create public commitments from nonces
        let commitments = SigningCommitments::from(&nonces);

        // Save locally participants secret nonces and public commitments
        self.nonces.insert(participant_id, nonces);
        self.commitments.insert(participant_id, commitments);

        Ok(())
    }

        /// Aggregate all public commitments into a group commitment for signing.
    pub fn aggregate_commitments(&self) -> Result<<FrostEd25519 as frost_core::Curve>::Group, CustodyError> {
        //step 1: start with identity element zero point on elliptice curve (neutral element for addition)
        let mut group_commitment = <FrostEd25519 as frost_core::Curve>::Group::identity();

        //step 2: summ all commitments
        //loop through each participant's commitments
        for (_participant_id, commitment) in self.commitments.iter() {
            group_commitment = group_commitment + commitment.hiding(); // use the hiding nonce for privacy
        }
        //step 3: return the aggregated commitment
        Ok(group_commitment)
    }

    /// Create a partial signature share for the participant using their shard.
    pub fn create_partial_signature(
        &self,
        participant_id: ParticipantId,
        sealed_shard: &[u8],
    ) -> Result<FrostSignatureShare, CustodyError> {
        // Step 1: unseal and deserialize the CustodyShard into KeyPackage
        let key_package: KeyPackage<FrostEd25519> = unseal_and_load_key_package(sealed_shard)?;
        
        // Step 2: Retrieve participant's stored nonces
        let signing_nonces = self.nonces.get(&participant_id)
            .ok_or_else(|| CustodyError::MPCError("No nonces found for participant".to_string()))?;

        // step 3: aggregate group commitment
        let group_commitment = self.aggregate_commitments()?;

        // step 4: Derive the signing challenge
        let challenge = FrostCiphersuite::challenge(
            &group_commitment,
            &key_package.public.group_public,
            self.message.as_slice(),
        );

        //step 5: Generate the partial signature
        let signature_share = key_package.sign(
            signing_nonces,
            &group_commitment,
            self.message.as_slice(),
            challenge,
        ).map_err(|e| CustodyError::MPCError(format!("Partial signing failed: {:?}", e)))?;

        Ok(signature_share)
    }

        /// Combine partial signatures into a full valid Schnorr signature.
    pub fn aggregate_partial_signatures(
        &self,
        partials: Vec<FrostSignatureShare>,
    ) -> Result<frost_ed25519::Signature, CustodyError> {
        
        // step 1: aggregate the group commitment again (R)
        let group_commitment = self.aggregate_commitments()?;

        //step2: Calculate the final signatures (s)
        // Merge all partial signature shares into one valid full signature
        let signature = combine_signature_shares::<FrostEd25519>(
            &partials,
            &group_commitment,
            self.message.as_slice(),
        ).map_err(|e| CustodyError::MPCError(format!("Aggregation failed: {:?}", e)))?;

        Ok(signature)
    }
}

pub struct MpcSigner;

/// This struct is a placeholder for the actual implementation of the MPC signer.
/// It will coordinate the signing process using the FROST protocol.
impl MpcSigner {
    pub fn sign_message(_message: &[u8]) -> Result<Vec<u8>, CustodyError> {
        // this will coordinate partial signatures using FROST protocol
        Err(CustodyError::MPCError("Not implemented".to_string()))
    }
}

/*SigningSession 
    who's participating
    what random nonces they generated
    nonce commitments
    group aggregated commitment
    what message are we signing
    what signatures have been generated
    ------
    we can now create a sessio. each participant generates nonces. 
    we can aggregate a group commitment (R) needed for signing
    ---
    we can now generate partial signatures per particpant
    every shard holder can indepenedently produce their own secure signature share
    */


pub struct MPCSigningCoordinator;

/// Loops over all MPC members
/// requests partial signatures from each vault
/// aggregates them into a threshold signature using FROST
/// only vault internal logic can access shards; the coordinator just orchestrates.
impl MPCSigningCoordinator {
    // added this because newest version had it
    pub fn new() -> Self {
        MpcSigningCoordinator { }
    }

    /// Signs the root VC using MPC/FROST flow
    /// this was added at the end for handling Signing the Root VC. need to build out the remaining logic still.
    pub async fn sign_root_vc(&self, issuer_did: &str, vc_json: &str) -> Result<String, String> {
        println!("MPC signing for root VC with DID: {}", issuer_did);

        // [STEP 1] Deserialize VC JSON → canonical form
        // [STEP 2] Hash VC payload → message digest
        // [STEP 3] Trigger MPC threshold signing over the digest
        // [STEP 4] Collect partial signatures, aggregate into final signature
        // [STEP 5] Embed signature back into VC JSON structure

        // For now, we'll stub this return
        Ok(format!("{{\"signed_root_vc\": \"MPC_SIGNATURE_PLACEHOLDER\"}}"))
    }
    pub fn sign_with_group(
        &self,
        group: &MPCGroupDescriptor,
        message: &[u8],
    ) -> Result<Vec<u8>, MPCError> {
        // Step 1: Collect responses from all vault members
        let mut partial_signatures = Vec::new();

        for member in &group.members {
            let partial_sig = self.request_partial_signature(
                &member.vault_reference,
                &member.custody_node_id,
                message,
            )?;
            partial_signatures.push((member.shard_index, partial_sig));
        }

        // Step 2: Aggregate threshold signature (FROST)
        let aggregated_signature = frost_aggregate_signatures(&partial_signatures, group.threshold)?;

        Ok(aggregated_signature)
    }

    fn request_partial_signature(
        &self,
        vault_reference: &str,
        custody_node_id: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, MPCError> {
        // Here we simulate calling the local or remote vault to compute its partial signature
        // In real systems, this would be a gRPC or RPC call, or an in-process handler
        let partial_sig = vault_partial_sign(vault_reference, custody_node_id, message)?;
        Ok(partial_sig)
    }

    /// Didn't want to erase the one above yet. This one does the same thing but is for using gRPC
    /// to make these requests across nodes instead of assuming local vaults
    /// Orchestrates multi-node MPC signing by contacting all vaults.
pub fn sign_with_group_grpc(
    &self,
    group: &MPCGroupDescriptor,
    message: &[u8],
) -> Result<Vec<u8>, MPCError> {
    let mut partial_signatures = Vec::new();

    for member in &group.members {
        let mut client = CustodyVaultServiceClient::connect(format!(
            "https://{}",
            member.custody_node_id
        ))?;
        let response = client.request_partial_signature(RequestPartialSignatureRequest {
            operational_did: group.group_id.clone(),
            message: message.to_vec(),
        }).await?;

        let resp = response.into_inner();
        partial_signatures.push((member.shard_index, resp.partial_signature));
    }

    // Aggregate the threshold signature using FROST or similar scheme
    let aggregated_signature = frost_aggregate_signatures(&partial_signatures, group.threshold)?;
    Ok(aggregated_signature)
    }
}

