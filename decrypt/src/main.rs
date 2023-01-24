use anyhow::Error;
use clap::Parser;
use common::bundle::Bundle;
use common::rsa_keys::{KeyFromUrl, RsaPrivateKey};
use common::sources;
use common::sources::Data;
use common::symmetric_cipher::SymmetricCipher;
use log::info;
use openssl::rsa::{Padding, Rsa};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    source: String,

    #[arg(long)]
    output: PathBuf,

    #[arg(long)]
    private_key: PathBuf,
}

fn main() -> Result<(), Error> {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    info!("Started");

    let cli = Cli::parse();

    let private_key_pem = fs::read(cli.private_key)?;
    let private_key = Rsa::private_key_from_pem(&private_key_pem)?;

    let mut source = sources::from_string(&cli.source)?;
    loop {
        let data = source.next()?;
        dbg!(&data);
        source.confirm(data.id)?;
    }
}

fn handle_file(data: &Data) {
    let bundle: Bundle = bincode::deserialize(&data.contents).unwrap();

    let private_key = RsaPrivateKey::from_url(
        "https://share.esav.fi/esa/5b977852-e823-4e90-904d-094f9f1c63b0/private.json",
    )
    .unwrap()
    .into_rsa_key()
    .unwrap();

    let mut buf = vec![0; private_key.size() as usize];
    private_key
        .private_decrypt(
            bundle.enc_key.as_slice(),
            buf.as_mut_slice(),
            Padding::PKCS1,
        )
        .unwrap();

    let sym_enc_key = &buf[0..32];

    let cipher = SymmetricCipher::new(Some(sym_enc_key));
    let _plaintext = cipher.decrypt(&bundle.ciphertext);
}
