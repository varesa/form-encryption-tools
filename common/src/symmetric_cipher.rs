use openssl::rand::rand_bytes;
use openssl::symm::{decrypt, encrypt, Cipher};

const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;

pub struct SymmetricCipher {
    cipher: Cipher,
    key: [u8; KEY_LENGTH],
    iv: [u8; IV_LENGTH],
}

impl SymmetricCipher {
    pub fn new(key: Option<&[u8]>) -> Self {
        let cipher = Cipher::aes_256_cbc();
        assert_eq!(cipher.key_len(), KEY_LENGTH);
        assert_eq!(cipher.iv_len().unwrap(), IV_LENGTH);

        // Generate key
        let key: [u8; KEY_LENGTH] = if let Some(key) = key {
            key.try_into()
                .expect("Failed to store key to proper sized array")
        } else {
            let mut key = [0u8; KEY_LENGTH];
            rand_bytes(key.as_mut_slice()).unwrap();
            key
        };
        assert_ne!(key, [0u8; KEY_LENGTH]);

        // Null IV for single-use keys
        let iv = [0u8; IV_LENGTH];

        SymmetricCipher { cipher, key, iv }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let ciphertext = encrypt(
            self.cipher,
            self.key.as_slice(),
            Some(self.iv.as_slice()),
            plaintext,
        )?;
        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let plaintext = decrypt(
            self.cipher,
            self.key.as_slice(),
            Some(self.iv.as_slice()),
            ciphertext,
        )?;
        Ok(plaintext)
    }

    pub fn get_key(&self) -> [u8; KEY_LENGTH] {
        self.key
    }
}

impl Default for SymmetricCipher {
    fn default() -> Self {
        Self::new(None)
    }
}
