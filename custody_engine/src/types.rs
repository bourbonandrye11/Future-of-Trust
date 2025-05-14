use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CustodyShard {
    pub id: u8,
    pub pubkey: Vec<u8>,
    pub share: Vec<u8>, //Encrypted share
}

#[derive(Debug, Clone)]
pub struct SessionNonce(pub [u8; 32]);
