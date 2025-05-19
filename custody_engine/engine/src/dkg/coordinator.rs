


/// the coordinator instructs all nodes to participate
/// manages multi-round DKG message exchanges
/// finalizes the groups shared public key
pub async fn orchestrate_dkg(
    &self,
    op_did: &OperationalDID,
    threshold: u8,
    custody_nodes: Vec<String>,
) -> Result<Vec<u8>, MPCError> {
    let group_id = uuid::Uuid::new_v4().to_string();

    // Step 1: Tell all nodes to start the DKG session
    for node in &custody_nodes {
        let mut client = CustodyVaultServiceClient::connect(format!("https://{}", node)).await?;
        client.start_dkg_session(StartDKGSessionRequest {
            group_id: group_id.clone(),
            operational_did: op_did.0.clone(),
            threshold: threshold as u32,
            participant_nodes: custody_nodes.clone(),
        }).await?;
    }
    

    // Step 3: Tell all nodes to complete the session
    let mut public_key_commitment = None;
    for node in &custody_nodes {
        let mut client = CustodyVaultServiceClient::connect(format!("https://{}", node)).await?;
        let response = client.complete_dkg_session(CompleteDKGSessionRequest {
            group_id: group_id.clone(),
        }).await?;

        // Collect one copy of the public key commitment
        if public_key_commitment.is_none() {
            public_key_commitment = Some(response.into_inner().public_key_commitment);
        }
    }

    Ok(public_key_commitment.unwrap())
}

    // give as a fn but step 1 and 3 aren't functions need to revisit this as well...
    // Step 2: Handle DKG message passing (omitted for brevity — can be pub/sub or relay)
    /// wraps the peer-to-peer message delivery into a clean function
    /// one vault calls another vaults gRPC API to pass a message
    pub async fn send_dkg_message(
        &self,
        target_node: &str,
        group_id: &str,
        sender_node_id: &str,
        dkg_payload: Vec<u8>,
    ) -> Result<(), MPCError> {
        let mut client = CustodyVaultServiceClient::connect(format!("https://{}", target_node)).await?;
        client.submit_dkg_message(SubmitDKGMessageRequest {
            group_id: group_id.to_string(),
            sender_node_id: sender_node_id.to_string(),
            dkg_payload,
        }).await?;
        Ok(())
    }
