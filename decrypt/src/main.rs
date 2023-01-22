use std::fs::File;
use openssl::rsa::Padding;
use openssl::symm::{Cipher, decrypt};
use common::bundle::Bundle;
use crate::keys::RsaPrivateKeyfile;

mod keys;

fn main() {
    println!("Started");

    let file = File::open("/home/esav.fi/esa/workspace/queue-decrypt/encrypted-596f0006-8daf-11ed-86ec-fa163e3c1968.zip").unwrap();
    let bundle: Bundle = bincode::deserialize_from(&file).unwrap();

    let private_key = RsaPrivateKeyfile::from_url("https://share.esav.fi/esa/5b977852-e823-4e90-904d-094f9f1c63b0/private.json").unwrap().into_rsa_key().unwrap();

    let mut buf = vec![0; private_key.size() as usize];
    private_key.private_decrypt(bundle.enc_key.as_slice(), buf.as_mut_slice(), Padding::PKCS1).unwrap();

    let sym_enc_key = &buf[0..32];

    let cipher = Cipher::aes_256_cbc();
    let iv = [0u8; 16];
    let _plaintext = decrypt(cipher, sym_enc_key, Some(iv.as_slice()), &bundle.ciphertext).unwrap();
}
