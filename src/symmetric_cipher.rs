use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, encrypt};

const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;

pub struct SymmetricCipher {
    cipher: Cipher,
    key: [u8; KEY_LENGTH],
}

impl SymmetricCipher {
    pub fn new() -> Self {
        let cipher = Cipher::aes_256_cbc();
        assert_eq!(cipher.key_len(), KEY_LENGTH);
        assert_eq!(cipher.iv_len().unwrap(), IV_LENGTH);

        // Generate key
        let mut key = [0u8; KEY_LENGTH];
        rand_bytes(key.as_mut_slice()).unwrap();
        assert_ne!(key, [0u8; KEY_LENGTH]);

        SymmetricCipher {
            cipher,
            key,
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        // Zero IV allowed as keys are single use
        let iv = [0u8; IV_LENGTH];

        let ciphertext = encrypt(
            self.cipher,
            self.key.as_slice(),
            Some(iv.as_slice()),
            plaintext
        )?;

        Ok(ciphertext)
    }

    pub fn get_key(&self) -> [u8; KEY_LENGTH] {
        self.key
    }
}