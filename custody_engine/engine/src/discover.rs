
use trust_dns_resolver::{TokioAsyncResolver, config::*};

pub async fn discover_peer_nodes(service_dns_name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.lookup_ip(service_dns_name).await?;

    let mut nodes = vec![];
    for ip in response.iter() {
        nodes.push(format!("{ip}:50051"));
    }

    Ok(nodes)
}

/*
    usage: 
    mod discover;

    let peers = discover::discover_peer_nodes("custody-nodes.default.svc.cluster.local").await?;

*/