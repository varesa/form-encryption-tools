use anyhow::Context;
use clap::Parser;
use log::info;
use notify::event::AccessKind;
use notify::{EventKind, Watcher};
use openssl::rsa::Padding;
use serde_derive::Serialize;
use std::fs::File;
use std::io::ErrorKind::NotFound;
use std::path::PathBuf;
use std::{fs, sync};

use crate::config::{Config, ConfigFile};
use crate::keys::RsaKeyfile;
use crate::symmetric_cipher::SymmetricCipher;

mod config;
mod keys;
mod symmetric_cipher;

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

    let (tx, rx) = sync::mpsc::channel();

    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(&cli.input, notify::RecursiveMode::NonRecursive)?;

    for event in rx.iter() {
        let event = event?;
        if let EventKind::Access(AccessKind::Close(_)) = &event.kind {
            for path in event.paths {
                handle_file(path, &config)?;
            }
        }
    }
    Err(anyhow::format_err!("Exited the main loop"))
}

#[derive(Debug, Serialize)]
struct Bundle {
    ciphertext: Vec<u8>,
    enc_key: Vec<u8>,
}

fn handle_file(file: PathBuf, config: &Config) -> Result<(), anyhow::Error> {
    info!("Handling file: {}", file.display());
    let plaintext_content = std::fs::read_to_string(&file)?;

    let sym_cipher = SymmetricCipher::new();
    let ciphertext = sym_cipher.encrypt(plaintext_content.as_bytes())?;
    let sym_key = sym_cipher.get_key();

    for target in &config.targets {
        info!(".. with target {}", &target.name);
        let rsa_key = RsaKeyfile::from_url(&target.key_url)?.into_rsa_key()?;

        let mut enc_sym_key = vec![0; rsa_key.size() as usize];
        rsa_key.public_encrypt(
            sym_key.as_slice(),
            enc_sym_key.as_mut_slice(),
            Padding::PKCS1,
        )?;

        let bundle = Bundle {
            ciphertext: ciphertext.clone(),
            enc_key: enc_sym_key,
        };

        let out_path = PathBuf::from(&config.output).join(&target.name).join(
            file.file_name()
                .ok_or(anyhow::Error::msg("Unable to get input filename"))?,
        );
        info!(".. output to: {}", &out_path.display());

        let target_dir = out_path
            .parent()
            .ok_or(anyhow::Error::msg("Error getting output path parent"))?;

        match std::fs::metadata(target_dir) {
            Err(e) => {
                assert_eq!(e.kind(), NotFound);
                info!("Parent {} does not exist, creating", target_dir.display());
                std::fs::create_dir(target_dir)?;
            }
            Ok(f) => {
                assert!(f.is_dir());
            }
        };

        info!(".. writing");
        let file = File::create(out_path)?;
        bincode::serialize_into(file, &bundle)?;
    }
    Ok(())
}
