use anyhow::Context;
use clap::Parser;
use log::info;
use notify::event::AccessKind;
use notify::EventKind;
use openssl::rsa::Padding;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use common::bundle::Bundle;
use common::symmetric_cipher::SymmetricCipher;
use common::watch::watch_files;

use crate::config::{Config, ConfigFile, Target};
use crate::keys::RsaKeyfile;

mod config;
mod keys;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    config: PathBuf,

    #[arg(long)]
    cache: PathBuf,

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

    let (_watcher, events) = watch_files(&cli.input)?;
    for event in events {
        let event = event?;
        if let EventKind::Access(AccessKind::Close(_)) = &event.kind {
            for path in event.paths {
                handle_file(path, &config)?;
            }
        }
    }
    Err(anyhow::format_err!("Exited the main loop"))
}

fn handle_file(file: PathBuf, config: &Config) -> Result<(), anyhow::Error> {
    info!("Handling file: {}", file.display());
    let filename = file
        .file_name()
        .ok_or_else(|| anyhow::Error::msg("Unable to get input filename"))?;

    let mut plaintext_content = Vec::new();
    BufReader::new(
        File::open(&file).context(format!("Error opening input file: {:?}", &filename))?,
    )
    .read_to_end(&mut plaintext_content)
    .context(format!("Error reading input file: {:?}", &filename))?;

    for target in &config.targets {
        info!(".. with target {}", &target.name);
        let bundle = encrypt_for(&plaintext_content, target).context("Error encrypting")?;
        bundle
            .write_to_path(&config.output, &target.name, filename)
            .context("Error writing output file")?;
    }

    info!("Done with {}", file.display());
    Ok(())
}

fn encrypt_for(plaintext: &[u8], target: &Target) -> Result<Bundle, anyhow::Error> {
    let sym_cipher = SymmetricCipher::new(None);
    let ciphertext = sym_cipher.encrypt(plaintext)?;

    let rsa_key = RsaKeyfile::from_url(&target.key_url)
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
