
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

pub struct SigningSession {
    pub message: Vec<u8>, // message to be signed
    pub nonces: HashMap<u8, SigningNonces>, // holds participants' random nonces
    pub commitments: HashMap<u8, SigningCommitments>, // holds participants' nonce commitments
}

impl SigningSession {
    pub fn new(message: Vec<u8>) -> Self {
        SigningSession {
            message,
            nonces: HashMap::new(),
            commitments: HashMap::new(),
        }
    }

    pub fn generate_nonce(&mut self, participant_id: u8) -> Result<(), CustodyError> {
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

    pub fn create_partial_signature(
        &self,
        participant_id: u8,
        sealed_shard: &[u8],
    ) -> Result<FrostSignatureShare, CustodyError> {
        // Step 1: unseal and deserialize the CustodyShard into KeyPackage
        let custody_shard = Vault::unseal(sealed_shard)?;
        let key_package: KeyPackage<FrostEd25519> =
            bincode::deserialize(&custody_shard.share)
                .map_err(|e| CustodyError::VaultError(format!("Shard deserialize failed: {:?}", e)))?;
        
        // Step 2: Retrieve participant's stored nonces
        let signing_nonces = self.nonces.get(&participant_id)
            .ok_or_else(|| CustodyError::MPCError("No nonces found for participant".to_string()))?;

        // step 3: aggregate group commitment
        let group_commitment = self.aggregate_commitments()?;

        // step 4: Derive the signing challenge
        let challenge = FristCiphersuite::challenge(
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

    pub fn aggregate_partial_signatures(
        &self,
        partials: Vec<FrostSignatureShare>,
    ) -> Result<frost_ed25519::Signature, CustodyError> {
        
        // step 1: aggreagte the group commitment again (R)
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

pub fn generate_key_shares(threshold: usize, participants: usize) -> Result<(Vec<Vec<u8>>, Vec<u8>), CustodyError> {
    // step 1: Initialize secure randomness source
    let mut rng = OsRng; 

    // step 2: Run FROST Dealer-based key generation
    let (key_packages, public_key_package) = 
        generate_with_dealer(threshold, participants, &mut rng)
        .map_err(|e| CustodyError::MPCError(format!("keygen failed: {:?}", e)))?;

    //step 3: Create sealed custody shards
    let mut sealed_shards = Vec::new();
    for (identifier, key_package) in key_packages { 
        let shard = CustodyShard { 
            id: identifier.serialize(),
            pubkey: key_package.public.share.to_bytes().to_vec(),
            share: bincode::serialize(&key_package)
                .map_err(|e| CustodyError::VaultError(format!("Serialization failed: {:?}", e)))?,
        };

        //step 4: seal the shard (for real TEE storage later) 
        let sealed = Vault::seal(&shard)?;
        sealed_shards.push(sealed);
        }

        //step 5: Serialize the group public key for later use
        let group_pubkey_bytes = public_key_package.group_public.to_bytes().to_vec();

        Ok((sealed_shards, group_pubkey_bytes))
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


