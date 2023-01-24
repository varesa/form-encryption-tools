use anyhow::Context;
use clap::Parser;
use log::info;
use openssl::rsa::Padding;
use std::fs;
use std::path::PathBuf;

use common::bundle::Bundle;
use common::rsa_keys::{KeyFromUrl, RsaPubkey};
use common::sources;
use common::sources::Data;
use common::symmetric_cipher::SymmetricCipher;

use crate::config::{Config, ConfigFile, Target};

mod config;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    config: PathBuf,

    //#[arg(long)]
    //cache: PathBuf,
    #[arg(long)]
    input: PathBuf,

    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<(), anyhow::Error> {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let cli = Cli::parse();

    let config_string = fs::read_to_string(&cli.config)
        .context(format!("Error reading the config file: {:?}", &cli.config))?;
    let config_file: ConfigFile = toml::from_str(&config_string)?;
    let config = Config {
        targets: config_file.targets,
        output: cli.output,
    };

    let mut source = sources::from_string(cli.input.to_str().unwrap())?;
    loop {
        let data = source.next()?;
        handle_data(&data, &config)?;
        source.confirm(data.id)?;
    }
}

fn handle_data(data: &Data, config: &Config) -> Result<(), anyhow::Error> {
    info!("Handling {:?}", &data.id);
    for target in &config.targets {
        info!(".. with target {}", &target.name);
        let bundle = encrypt_for(&data.contents, target).context("Error encrypting")?;
        bundle
            .write_to_path(&config.output, &target.name, &data.id)
            .context("Error writing output file")?;
    }

    info!("Done with {:?}", &data.id);
    Ok(())
}

fn encrypt_for(plaintext: &[u8], target: &Target) -> Result<Bundle, anyhow::Error> {
    let sym_cipher = SymmetricCipher::new(None);
    let ciphertext = sym_cipher.encrypt(plaintext)?;

    let rsa_key = RsaPubkey::from_url(&target.key_url)
        .context("Getting public key from URL")?
        .into_rsa_key()
        .context("Converting keyfile to a key")?;
    dbg!(&rsa_key.size());
    let mut wrapped_key = vec![0; rsa_key.size() as usize];
    rsa_key.public_encrypt(
        sym_cipher.get_key().as_slice(),
        wrapped_key.as_mut_slice(),
        Padding::PKCS1,
    )?;

    Ok(Bundle {
        ciphertext,
        enc_key: wrapped_key,
    })
}
