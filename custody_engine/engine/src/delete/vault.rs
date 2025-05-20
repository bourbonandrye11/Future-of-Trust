

// There are issues here. this isn't complete
// it doesn't take in participants or threshholds. 
// it doesn't separate out crypto from vault like we previously had. 
// it even says to replace with proper keygen so we definitely have questions here. 
// our original keygen is also still using generate_with_dealer

use crate::bbs::BbsKeyPair;

impl Vault {
    /// Creates a new vault + initializes FROST group + MPC shards
    pub fn new_with_frost_group() -> Result<Self, CustodyError> {
        // Step 1: Generate MPC key shards
        let key_shards = MPCShardGenerator::generate()
            .map_err(|e| CustodyError::VaultError(format!("MPC shard generation failed: {}", e)))?;

        // Step 2: Initialize FROST group state
        let frost_group = FROSTGroup::initialize()
            .map_err(|e| CustodyError::VaultError(format!("FROST init failed: {}", e)))?;

        // Step 3: Assemble the vault struct
        Ok(Self {
            key_shards,
            frost_group,
            verifiable_credentials: Mutex::new(vec![]),
            encryption_key: Zeroizing::new(rand::random()), // replace with proper keygen
        })
    }

    /// Get the public key commitment (for DID embedding)
    pub fn get_public_key_commitment(&self) -> Result<Vec<u8>, CustodyError> {
        self.frost_group.get_public_key_commitment()
            .map_err(|e| CustodyError::VaultError(format!("Public key retrieval failed: {}", e)))
    }

    /// (Optional) Generate a custody proof or attestation
    pub fn generate_custody_proof(&self) -> Result<Vec<u8>, CustodyError> {
        // Stub for now: return placeholder or mock proof
        Ok(vec![0u8; 32]) // replace with real proof system later
    }

    /// Return a vault reference handle (for internal tracking)
    pub fn get_reference(&self) -> String {
        format!("vault-{}", uuid::Uuid::new_v4())
    }

    /// Retrieve the BBS+ secret key for the given issuer DID
    /// WARNING: Only called internally by signing flows!
    pub fn get_bbs_secret_key_for_issuer(&self, issuer_did: &str) -> Option<SecretKey> {
        self.records.get(issuer_did).map(|record| record.bbs_keypair.secret_key.clone())
    }

    /// Retrieve the BBS+ public key for the given issuer DID
    pub fn get_bbs_public_key_for_issuer(&self, issuer_did: &str) -> Option<PublicKey> {
        self.records.get(issuer_did).map(|record| record.bbs_keypair.public_key.clone())
    }
}
