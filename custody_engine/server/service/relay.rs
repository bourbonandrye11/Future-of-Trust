
// File: src/relay.rs

use tonic::{Request, Response, Status};
use tonic::transport::Server;
use crate::dkg::types::*;
use crate::dkg::engine::DKGEngine;
use std::sync::Arc;

use custodyrelay::custody_relay_server::{CustodyRelay, CustodyRelayServer};
use custodyrelay::{RelayMessage, Empty};
use crate::custodyrelay::custody_relay_server::{CustodyRelay, CustodyRelayServer};

/// Relay service for custody node-to-node communication
#[derive(Clone)]
pub struct RelayService {
    pub dkg_engine: Arc<DKGEngine>,
    pub local_node_id: String,
}

#[tonic::async_trait]
impl CustodyRelay for RelayService {
    async fn send_message(
        &self,
        request: Request<RelayMessage>,
    ) -> Result<Response<Empty>, Status> {
        let msg = request.into_inner();

        // Pass raw message payload to the DKG engine handler
        self.dkg_engine
            .handle_message(&msg.group_id, &msg.from_node, msg.payload)
            .map_err(|e| Status::internal(format!("DKG handling failed: {:?}", e)))?;

        Ok(Response::new(Empty {}))
    }
}

/// RelayClient used to send outbound messages
#[derive(Clone)]
pub struct RelayClient {
    pub local_node_id: String,
}

impl RelayClient {
    pub fn new(local_node_id: &str) -> Self {
        RelayClient {
            local_node_id: local_node_id.to_string(),
        }
    }

    /// Send a message to a remote peer
    pub fn send_message(
        &self,
        group_id: &str,
        to_node: &str,
        payload: Vec<u8>,
    ) -> Result<(), DKGError> {
        let uri = format!("http://{}:50051", to_node);
        let channel = std::thread::spawn(move || {
            tokio::runtime::Runtime::new().unwrap().block_on(async move {
                let mut client = custodyrelay::custody_relay_client::CustodyRelayClient::connect(uri)
                    .await
                    .map_err(|e| DKGError::CryptoFailure(format!("Connect failed: {e:?}")))?;

                let msg = RelayMessage {
                    group_id: group_id.to_string(),
                    from_node: self.local_node_id.clone(),
                    payload,
                };

                client.send_message(Request::new(msg)).await
                    .map_err(|e| DKGError::CryptoFailure(format!("Send failed: {e:?}")))?;

                Ok(())
            })
        }).join().unwrap();

        channel
    }
}