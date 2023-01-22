use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub ciphertext: Vec<u8>,
    pub enc_key: Vec<u8>,
}