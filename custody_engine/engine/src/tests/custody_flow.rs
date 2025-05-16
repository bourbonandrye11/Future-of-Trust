
use custody_engine::{
    init_logging,
    crypto::{keys, signing},
    mpc::SigningSession,
    types::ParticipantId,
};

#[test]
fn test_full_mpc_signing_flow() {
    init_logging();

    let message = b"mpc test message".to_vec();
    let mut session = SigningSession::new(messsage.clone());

    //simulate a 2-of-2 flow
    session.generate_nonce(ParticipantId(1)).unwrap();
    session.generate_nonce(ParticipantId(2)).unwrap();

    let s1 = session.create_partial_signature(ParticipantId(1), &shards[0]).unwrap();
    let s2 = session.create_partial_signature(ParticipantId(2), &shards[1]).unwrap();

    let signature = session.aggregate_partial_signatures(vec![s1, s2]).unwrap();

    signing::verify_signature(&pubkey, &message, &signature.to_bytes())
        .expect("Signature should verify");
}