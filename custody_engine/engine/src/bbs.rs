

// Import dependencies
use bbs::{SecretKey, PublicKey, Signature, SignatureMessage, MessageGenerators};
use bbs::prelude::*; // BBS+ library
use serde_json::Value; // For working with VC JSON payloads
use base64;
use crate::vault; // For vault access

/// Struct representing a BBS+ keypair
pub struct BbsKeyPair {
    pub secret_key: SecretKey, // Sensitive, stored only in vault!
    pub public_key: PublicKey, // Public, can be exposed
}

impl BbsKeyPair {
    /// Generate a new BBS+ keypair using secure random entropy
    pub fn generate() -> Self {
        let sk = SecretKey::random();            // Create secure random 32-byte secret
        let pk = PublicKey::from(&sk);           // Derive public key from secret key
        BbsKeyPair { secret_key: sk, public_key: pk }
    }
}

/// Generate and store an issuer's keypair in the vault under their DID
pub fn generate_and_store_issuer_keys(issuer_did: &str) -> Result<(String, String), String> {
    let keypair = BbsKeyPair::generate();

    // Encode both keys as base64 strings
    let sk_encoded = base64::encode(keypair.secret_key.to_bytes_compressed_form());
    let pk_encoded = base64::encode(keypair.public_key.to_bytes_compressed_form());

    // Save keys into the vault under the issuer DID
    vault::set_bbs_private_key(issuer_did, &sk_encoded)?;
    vault::set_bbs_public_key(issuer_did, &pk_encoded)?;

    Ok((sk_encoded, pk_encoded))
}

/// Helper: extract canonical VC fields as BBS+ messages
/// This enables selective disclosure + future ZKP proofs
pub fn extract_vc_messages(vc_json: &str) -> Result<Vec<SignatureMessage>, String> {
    let vc_value: Value = serde_json::from_str(vc_json)
        .map_err(|e| format!("Failed to parse VC JSON: {:?}", e))?;

    let mut messages = Vec::new();

    // Example: extract "id"
    if let Some(id) = vc_value.get("id").and_then(|v| v.as_str()) {
        messages.push(SignatureMessage::hash(id.as_bytes()));
    }

    // Example: extract "issuer"
    if let Some(issuer) = vc_value.get("issuer").and_then(|v| v.as_str()) {
        messages.push(SignatureMessage::hash(issuer.as_bytes()));
    }

    // Example: extract all credentialSubject claims (flattened)
    if let Some(subject) = vc_value.get("credentialSubject").and_then(|v| v.as_object()) {
        for (key, value) in subject.iter() {
            let value_str = value.to_string(); // Convert value to string (could be string, number, bool, etc.)
            let message_string = format!("credentialSubject.{}={}", key, value_str);
            messages.push(SignatureMessage::hash(message_string.as_bytes()));
        }
    }

    Ok(messages)
}

/// Sign a VC using the issuer's vault-stored secret key (BBS+ signature)
pub fn sign_vc_with_vault(issuer_did: &str, vc_json: &str) -> Result<String, String> {
    let messages = extract_vc_messages(vc_json)?;

    // Retrieve base64-encoded secret key from vault
    let sk_b64 = vault::get_bbs_private_key(issuer_did)?;
    let sk_bytes = base64::decode(&sk_b64)
        .map_err(|e| format!("Base64 decode error: {:?}", e))?;

    let secret_key = SecretKey::from_bytes(&sk_bytes)
        .map_err(|e| format!("Invalid secret key format: {:?}", e))?;

    let public_key = PublicKey::from(&secret_key);
    let generators = MessageGenerators::from_public_key(&public_key, messages.len());

    let signature = Signature::new(&messages, &secret_key, &generators)
        .map_err(|e| format!("BBS+ signing failed: {:?}", e))?;

    // Embed signature into VC
    let mut vc_obj: Value = serde_json::from_str(vc_json)
        .map_err(|e| format!("Invalid VC JSON: {:?}", e))?;

    vc_obj["proof"] = serde_json::json!({
        "type": "BbsBlsSignature2020",
        "created": chrono::Utc::now().to_rfc3339(),
        "proofPurpose": "assertionMethod",
        "verificationMethod": issuer_did,
        "signature": base64::encode(signature.to_bytes_compressed_form())
    });

    serde_json::to_string(&vc_obj)
        .map_err(|e| format!("Failed to serialize signed VC: {:?}", e))
}

/// Verify a VC's BBS+ signature using a base64 public key and the original VC payload
pub fn verify_vc_signature(vc_json: &str, signature_b64: &str, public_key_b64: &str) -> bool {
    let messages = match extract_vc_messages(vc_json) {
        Ok(m) => m,
        Err(_) => return false,
    };

    let sig_bytes = match base64::decode(signature_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let signature = match Signature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let pk_bytes = match base64::decode(public_key_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let public_key = match PublicKey::from_bytes(&pk_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let generators = MessageGenerators::from_public_key(&public_key, messages.len());
    signature.verify(&messages, &public_key, &generators).is_ok()
}
