use common::rsa_keys::{encode, RsaPubkey};
use openssl::rsa::Rsa;
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = args.get(1).expect("File name not provided");
    dbg!(filename);

    let keydata = fs::read(filename).expect("Unable to read key file");
    let key = Rsa::public_key_from_pem(&keydata).expect("Unable to understand key");

    let n = encode(key.n());
    let e = encode(key.e());

    println!(
        "{}",
        serde_json::to_string(&RsaPubkey::from_parts("RSA".to_string(), n, e,))
            .expect("Failed to encode key as JSON")
    )
}
