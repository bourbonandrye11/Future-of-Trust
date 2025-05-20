#[tokio::test]
async fn test_rotate_shards() {
    use mpc::custody_mpc_client::CustodyMpcClient;
    use mpc::RotateShardsRequest;

    let mut client = CustodyMpcClient::connect("http://[::1]:50051").await.expect("connect failed");

    let response = client.rotate_shards(RotateShardsRequest {
        operational_did: "did:op:test".into(),
    }).await.expect("rpc failed");

    assert!(response.get_ref().new_group_id.starts_with("group"));
}
