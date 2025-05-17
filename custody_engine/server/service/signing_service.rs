

use std::collections::HashMap;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use custody::signing_service_server::SigningService;
use custody::{CreateSessionRequest, CreateSessionResponse};
use custody::{SubmitSignatureShareRequest, SubmitSignatureShareResponse};
use custody::{AggregateSignatureRequest, AggregateSignatureResponse};
use custody_engine::audit::{AUDIT, AuditRecord, AuditEventType, now_rfc3339};
use frost_ed25519::SignatureShare;
use custody_engine::mpc::SigningSession;
use custody_engine::types::ParticipantId;
use custody_engine::crypto::signing::verify_signature;
use std::sync::Arc;
use uuid::Uuid;
use blake3;

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

        if req.threshold == 0 {
            return Err(Status::invalid_argument("Threshold must be at least 1"));
        }
        if req.group_public_key.len() != 32 {
            return Err(Status::invalid_argument("Invalid group public key size"));
        }

        let threshold = req.threshold as usize;
        let group_pubkey = req.group_public_key;

        let message_bytes = req.message.into_bytes();
        let participant_id = ParticipantId(req.participant_id as u8);

        // switching to blake3 instead of uuid so commenting this out for now.
        //let session_id = Uuid::new_v4().to_string();
        // computes a 32-byte (256-bit) cryptographic digest of input. Guarantees deterministic sessionID -> same message = same session. fixed length and prevents edge cases.
        let session_id = blake3::hash(&message_bytes).to_hex().to_string();


        // Derive session key (could use hash later)
        let session_key = hex::encode(&message_bytes);

        // Lock the session store to insert new session
        let mut sessions = self.store.sessions.lock().await;

        // Clients now pass back the exact group public key and threshold from keygen when starting a session.
        let session = SigningSession::new(message_bytes.clone(), threshold, group_pubkey);
        sessions.insert(session_id.clone(), session);

        AUDIT.log(AuditRecord {
            event_type: AuditEventType::Keygen,
            session_id: session_id.clone(),
            participant_id: None,
            message: format!("Created signing session for message of {} bytes", message_bytes.len()),
            timestamp: now_rfc3339(),
        });        

        // Create a new signing session if not exists | commented out because added section above.
        // unsure how the above section handles not creating a new session if one exists
       // let session = sessions
        //    .entry(session_key.clone())
          //  .or_insert_with(|| SigningSession::new(message_bytes.clone()));

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
            session_id,
            commitment,
        };
        Ok(Response::new(response)) // Send back the result

        info!("Created signing session with ID {} (threshold {})", session_id, threshold);

    }

    async fn submit_signature_share(
        &self,
        request: Request<SubmitSignatureShareRequest>,
    ) -> Result<Response<SubmitSignatureShareResponse>, Status> {
        let req = request.into_inner(); // unpack request
        let participant_id = ParticipantId(req.participant_id as u8);

        // Also validate that the participant ID matches an expected participant in the session (future enhancement).
        if req.signature_share.len() != 32 {
            return Err(Status::invalid_argument("Signature share must be 32 bytes"));
        }
        
        let signature_bytes = req.signature_share;

        let session_id = req.session_id; // with session_id do we still need participant_id?

        let mut sessions = self.store.sessions.lock().await;

        // Derive session key based on message
        // this safely binds the submission to the session used during CreateSession
        // with the added session_id I presume we are no longer using session_key. will comment out for now.
        // let session_key = hex::encode(req.message.as_bytes());
        //     .ok_or_else(|| Status::not_found("No active session found"))?;
        //     .clone();

        // Locate the active signing session
        let session = sessions.get_mut(&session_id)
            .ok_or_else(|| Status::not_found("Session ID not found"))?;

        // Deserialize the signature share
        let share = SignatureShare::from_bytes(&signature_bytes)
            .map_err(|e| Status::invalid_argument(format!("Invalid signature format: {:?}", e)))?;

        // Make sure participant isn't signing twice
        if session.submitted_participants.contains(&participant_id) {
            return Err(Status::already_exists(format!(
                "Participant {} already submitted a signature share",
                participant_id.0
            )));

            AUDIT.log(AuditRecord {
                event_type: AuditEventType::Error,
                session_id: session_id.clone(),
                participant_id: Some(participant_id.0),
                message: "Duplicate signature share rejected".into(),
                timestamp: now_rfc3339(),
            });            
        }
        
        // Store it in session memory
        session.signature_shares.insert(participant_id, share);

        // updates submitted_participants to block repeat submissions before aggregation.
        session.submitted_participants.insert(participant_id);

        AUDIT.log(AuditRecord {
            event_type: AuditEventType::Signing,
            session_id: session_id.clone(),
            participant_id: Some(participant_id.0),
            message: "Received partial signature".into(),
            timestamp: now_rfc3339(),
        });        

        info!(
            "Received signature share from participant {} for session {}",
            participant_id.0,
            session_id
        );        

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
        let session_id = req.session_id;
        let mut sessions = self.store.sessions.lock().await;
        
        // WARNING: this is simplified and assumes a single active session.
        // In production, you'd pass in session ID or message hash from client.
        // presumably we are using session_id to locate the session. commenting out.
        //let (session_key, session) = sessions.iter().next()
         //   .ok_or_else(|| Status::not_found("No active session found"))?;
         let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| Status::not_found("Session ID not found"))?;

        // Gather all collected signature shares
        let shares: Vec<_> = session.signature_shares.values()
            .cloned()
            .collect();

        if shares.len() < session.threshold {
            return Err(Status::failed_precondition(format!(
                "Not enough shares: got {}, need {}",
                shares.len(),
                session.threshold
            )));
        }

        // signature verification failure as an explicit error:
        // (data_loss fits better semantically for cryptographic inconsistency.)
        if verification.is_err() {
            return Err(Status::data_loss("Signature verification failed after aggregation"));
        }
        
        
        // Aggregate the final signature
        let final_signature = session
            .aggregate_partial_signatures(shares)
            .map_err(|e| Status::internal(format!("Failed to aggregate signatures: {:?}", e)))?;

        // Optional: verify it internally using engine verifier
        // since we added the group public key do we need to change this and not use .next?
        let group_pubkey = session
            .commitments
            .values()
            .next()
            .ok_or_else(|| Status::internal("No commitments found"))?
            .commitment() // this gives R
            .to_bytes();

            // You now verify every signature against the actual public key used to construct the MPC group.
            let verification = verify_signature(
                &session.group_public_key,
                &session.message,
                &final_signature.to_bytes(),
            );
            

        if verification.is_err() {
            return Err(Status::internal("Signature verification failed after aggregation"));
        }

        AUDIT.log(AuditRecord {
            event_type: AuditEventType::Aggregation,
            session_id: session_id.clone(),
            participant_id: None,
            message: format!("Aggregated signature from {} participants", session.threshold),
            timestamp: now_rfc3339(),
        });        

        // Send back final signature bytes
        let response = AggregateSignatureResponse {
            ful_signature: final_signature.to_bytes().to_vec(),
        };

        info!(
            "Aggregated final signature for session {} (message {} bytes)",
            session_id,
            session.message.len()
        );
        
        Ok(Response::new(response))
    }
}