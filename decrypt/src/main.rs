use std::fs::File;
use std::io::Write;
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
    let plaintext = decrypt(cipher, &sym_enc_key, Some(iv.as_slice()), &bundle.ciphertext).unwrap();

    File::create("/home/esav.fi/esa/workspace/queue-decrypt/wrapped_key").unwrap().write(&bundle.enc_key).unwrap();
    File::create("/home/esav.fi/esa/workspace/queue-decrypt/unwrapped_key").unwrap().write(&sym_enc_key).unwrap();
    File::create("/home/esav.fi/esa/workspace/queue-decrypt/ciphertext").unwrap().write(&bundle.ciphertext).unwrap();
    File::create("/home/esav.fi/esa/workspace/queue-decrypt/plaintext").unwrap().write(&plaintext).unwrap();

    /*
    let private_pem = private_key.private_key_to_pem().unwrap();
    File::create("/home/esav.fi/esa/workspace/queue-decrypt/private.pem").unwrap().write(&private_pem).unwrap();
    let public_pem = private_key.public_key_to_pem().unwrap();
    File::create("/home/esav.fi/esa/workspace/queue-decrypt/public.pem").unwrap().write(&public_pem).unwrap();
    */


    //File::create("/home/esav.fi/esa/workspace/queue-decrypt/wrapped_key").unwrap().write(&bundle.enc_key).unwrap();
}
