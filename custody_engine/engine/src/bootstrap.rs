
// File: src/bootstrap.rs

use std::net::SocketAddr;
use std::env;
use std::error::Error;
use hostname;
use trust_dns_resolver::{TokioAsyncResolver, config::*};

/// Bootstraps the local node context dynamically from environment + DNS
pub struct NodeBootstrap {
    pub local_node_id: String,
    pub relay_bind: SocketAddr,
    pub peer_nodes: Vec<String>,
}

/// Initializes the node's identity, peer list, and bind address
pub async fn init_bootstrap(service_dns_name: &str) -> Result<NodeBootstrap, Box<dyn Error>> {
    // Node ID = pod hostname (via Kubernetes DNS or /etc/hostname)
    let local_node_id = hostname::get()?.to_string_lossy().to_string();

    // Relay gRPC bind address
    let relay_bind = "0.0.0.0:50051".parse::<SocketAddr>()?;

    // Use DNS SRV or A-record lookup for the headless service
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;
    let lookup_result = resolver.lookup_ip(service_dns_name).await?;

    let mut peers = vec![];
    for ip in lookup_result.iter() {
        // Skip own IP if needed (optional)
        let formatted = format!("{}:50051", ip);
        peers.push(formatted);
    }

    Ok(NodeBootstrap {
        local_node_id,
        relay_bind,
        peer_nodes: peers,
    })
}