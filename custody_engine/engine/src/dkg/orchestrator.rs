use tonic::transport::Channel;
use custodydkg::custody_dkg_client::CustodyDkgClient;
use custodydkg::{StartDkgSessionRequest, BroadcastRound2Request, FinalizeDkgRequest};

use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

pub async fn orchestrate_dkg(op_did: &str, threshold: u32, nodes: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let first = nodes[0].clone();

    // STEP 1: Start session by calling one node
    let mut client = CustodyDkgClient::connect(format!("http://{}", first)).await?;
    let start_resp = client.start_dkg_session(StartDkgSessionRequest {
        operational_did: op_did.to_string(),
        threshold,
        participant_nodes: nodes.clone(),
    }).await?.into_inner();

    let group_id = start_resp.group_id;
    println!("✅ Started DKG with group ID: {group_id}");

    // Optional: wait to let Round1 messages propagate
    sleep(Duration::from_secs(1)).await;

    // STEP 2: Broadcast Round2 on all nodes
    for node in &nodes {
        let mut client = CustodyDkgClient::connect(format!("http://{}", node)).await?;
        println!("📡 Broadcasting Round2 to {node}");
        client.broadcast_round2(BroadcastRound2Request {
            group_id: group_id.clone(),
        }).await?;
    }

    // Optional: wait to let Round2 messages propagate
    sleep(Duration::from_secs(1)).await;

    // STEP 3: Finalize and collect result
    for node in &nodes {
        let mut client = CustodyDkgClient::connect(format!("http://{}", node)).await?;
        let resp = client.finalize_dkg_session(FinalizeDkgRequest {
            group_id: group_id.clone(),
        }).await?;

        println!("🔐 Finalized {node} shard = {}", resp.into_inner().shard_base64);
    }

    println!("🎉 All nodes completed FROST DKG.");
    Ok(())
}

/// Then we can call this from anywhere in our system
/// could trigger: after identity creation, after governance vote, on schedule
/*
    let op_did = "did:example:123";
    let peers = discover_peer_nodes("custody-nodes.default.svc.cluster.local").await?;

    orchestrator::orchestrate_dkg(op_did, 2, peers).await?;

*/