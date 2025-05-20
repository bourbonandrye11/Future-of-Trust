#[tokio::test]
fn test_add_bbs_key_to_vault() {
    let vault_id = "vault-bbs-test";
    let mut record = VaultRecord {
        shard: None,
        bbs_private_key: None,
        public_keys: vec![],
        vcs: Default::default(),
        active_nonce: None,
    };

    store_record(vault_id, &record).unwrap();
    let key = "fake-bbs-key-base64";
    add_bbs_private_key(vault_id, key).unwrap();

    let updated = load_record(vault_id).unwrap();
    assert_eq!(updated.bbs_private_key.unwrap(), key);
}
