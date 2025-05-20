#[tokio::test]
async fn test_vault_record_creation_and_retrieval() {
    let vault_id = "test-vault-123";
    let record = VaultRecord {
        shard: Some("shard123".into()),
        bbs_private_key: None,
        public_keys: vec!["pk1".into()],
        vcs: Default::default(),
        active_nonce: None,
    };

    store_record(vault_id, &record).expect("store failed");
    let loaded = load_record(vault_id).expect("load failed");

    assert_eq!(loaded.shard.unwrap(), "shard123");
    assert_eq!(loaded.public_keys.len(), 1);
}
