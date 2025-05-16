

use std::collections::HashMap;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use custody::signing_service_server::SigningService;
use custody::{CreateSessionRequest, CreateSessionResponse};
use custody::{SubmitSignatureShareRequest, SubmitSignatureShareResponse};
use custody::{AggregateSignatureRequest, AggregateSignatureResponse};
use frost_ed25519::SignatureShare;
use custody_engine::mpc::SigningSession;
use custody_engine::types::ParticipantId;
use custody_engine::crypto::signing::verify_signature;
use std::sync::Arc;

pub mod custody {
    tonic::include_proto!("custody");
}

/// Represents an in-memory store of active signing sessions
 #[derive(Debug, Default)]
 pub struct SigningSessionStore {
    pub sessions: Mutex<HashMap<String, SigningSession>>, // key: message hash
 }
 
 /// Concrete implementation of the SigningService gRPC interface
 #[derive(Default)]
 pub struct MySigningService {
    pub store: Arc<SigningSessionStore>,
 }

 #[tonic::async_trait]
 impl SigningService for MySigningService {
    /// Start a new signing session for a given message and participant.
    async fn create_session(
        &self,
        request: Request<CreateSessionRequest>, // Incoming gRPC request
    ) -> Result<Response<CreateSessionResponse>, Status> {
        let req = request.into_inner(); // unpack request

        let message_bytes = req.message.into_bytes();
        let participant_id = ParticipantId(req.participant_id as u8);

        // Derive session key (could use hash later)
        let session_key = hex::encode(&message_bytes);

        // Lock the session store to insert new session
        let mut sessions = self.store.sessions.lock().await;

        // Create a new signing session if not exists
        let session = sessions
            .entry(session_key.clone())
            .or_insert_with(|| SigningSession::new(message_bytes.clone()));

        // Generate nonce commitment for this participant
        session.generate_nonce(participant_id)
            .map_err(|e| Status::internal(format!("Failed to generate nonce: {:?}", e)))?;

        let commitment = session.commitments
            .get(&participant_id)
            .ok_or_else(|| Status::internal("Commitment missing after nonce generation"))?
            .hiding()
            .to_bytes()
            .to_vec();

        // Return the participants commitment
        let response = CreateSessionResponse {
            commitment,
        };
        Ok(Response::new(response)) // Send back the result
    }

    async fn submit_signature_share(
        &self,
        request: Request<SubmitSignatureShareRequest>,
    ) -> Result<Response<SubmitSignatureShareResponse>, Status> {
        let req = request.into_inner(); // unpack request
        let participant_id = ParticipantId(req.participant_id as u8);
        let signature_bytes = req.signature_share;

        let mut sessions = self.store.sessions.lock().await;

        // Derive session key based on message
        // this safely binds the submission to the session used during CreateSession
        let session_key = hex::encode(req.message.as_bytes());
            .ok_or_else(|| Status::not_found("No active session found"))?;
            .clone();

        // Locate the active signing session
        let session = sessions.get_mut(&session_key)
            .ok_or_else(|| Status::not_found("Session not found"))?;

        // Deserialize the signature share
        let share = SignatureShare::from_bytes(&signature_bytes)
            .map_err(|e| Status::invalid_argument(format!("Invalid signature format: {:?}", e)))?;

        // Store it in session memory
        session.signature_shares.insert(participant_id, share);

        // Return success message
        let response = SubmitSignatureShareResponse {
            status: "Signature share received".into(),
        };
        Ok(Response::new(response))
    }

    async fn aggregate_signature(
        &self,
        _request: Request<AggregateSignatureRequest>,
    ) -> Result<Response<AggregateSignatureResponse>, Status> {
        let sessions = self.store.sessions.lock().await;
        
        // WARNING: this is simplified and assumes a single active session.
        // In production, you'd pass in session ID or message hash from client.
        let (session_key, session) = sessions.iter().next()
            .ok_or_else(|| Status::not_found("No active session found"))?;

        // Gather all collected signature shares
        let shares: Vec<_> = session.signature_shares.values()
            .cloned()
            .collect();

        if shares.len() < 2 {
            return Err(Status::failed_precondition("Not enough shares to aggregate"));
        }

        // Aggregate the final signature
        let final_signature = session
            .aggregate_partial_signatures(shares)
            .map_err(|e| Status::internal(format!("Failed to aggregate signatures: {:?}", e)))?;

        // Optional: verify it internally using engine verifier
        let group_pubkey = session
            .commitments
            .values()
            .next()
            .ok_or_else(|| Status::internal("No commitments found"))?
            .commitment() // this gives R
            .to_bytes();

        // NOTE: this is a placeholder. Replace with actual group pubkey from real keygen.
        let dummy_pubkey = [0u8; 32]; // Replace with actual group public key

        let verification = verify_signature(
            &dummy_pubkey,
            &session.message,
            &final_signature.to_bytes(),
        );

        if verification.is_err() {
            return Err(Status::internal("Signature verification failed after aggregation"));
        }

        // Send back final signature bytes
        let response = AggregateSignatureResponse {
            ful_signature: final_signature.to_bytes().to_vec(),
        };
        Ok(Response::new(response))
    }
}