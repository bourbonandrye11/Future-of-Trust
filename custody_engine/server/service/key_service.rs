
use tonic::{Request, Response, Status};
use custody::key_service_server::KeyService;
use custody::{GenerateKeyRequest, GenerateKeyResponse};
use custody_engine::crypto::keys::generate_and_seal_key_shards;

pub mod custody {
    tonic::include_proto!("custody");
}

/// Concrete implementation of the KeyService gRPC interface
#[derive(Default)]
pub struct MyKeyService;

#[tonic::async_trait]
impl KeyService for MyKeyService {
    /// Generate a new threshold key set and return sealed shards + group public key.
    async fn generate_key_set(
        &self,
        request: Request<GenerateKeyRequest>, // Incoming gRPC request
    ) -> Result<Response<GenerateKeyResponse>, Status> {
        let req = request.into_inner(); // Unpack request from tonic wrapper
        let threshold = req.threshold as usize;
        let participants = req.participants as usize;

        // Call your custody engine's keygen logic
        let (sealed_shards, pubkey) = generate_and_seal_key_shards(threshold, participants)
            .map_err(|e| Status::internal(format!("Key generation failed: {:?}", e)))?;

        // Convert Rust Vec<Vec<u8>> → protobuf `repeated bytes`
        let response = GenerateKeyResponse {
            sealed_shards,
            group_public_key: pubkey,
        };

        Ok(Response::new(response)) // Send back the result
    }
}
