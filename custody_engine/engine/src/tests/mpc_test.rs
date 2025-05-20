#[tokio::test]
async fn test_mpc_sign_message() {
    use mpc::custody_mpc_client::CustodyMpcClient;
    use mpc::SignMessageRequest;

    let mut client = CustodyMpcClient::connect("http://[::1]:50051").await.expect("connect failed");

    let response = client.sign_message(SignMessageRequest {
        operational_did: "did:op:test".into(),
        message: b"hello world".to_vec(),
    }).await.expect("rpc failed");

    assert!(response.get_ref().signature.len() > 0);
}
