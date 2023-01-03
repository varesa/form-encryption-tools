use anyhow::Context;
use clap::Parser;
use log::info;
use notify::event::AccessKind;
use notify::{Event, EventKind, Watcher};
use openssl::rsa::Padding;
use std::path::{Path, PathBuf};
use std::fs;
use std::sync::mpsc::{channel, Receiver};

use crate::config::{Config, ConfigFile, Target};
use crate::keys::RsaKeyfile;
use crate::symmetric_cipher::SymmetricCipher;
use crate::bundle::Bundle;

mod config;
mod keys;
mod symmetric_cipher;
mod bundle;

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

fn watch_files(path: &Path) -> Result<Receiver<notify::Result<Event>>, anyhow::Error> {
    let (tx, rx) = channel();

    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(path, notify::RecursiveMode::NonRecursive)?;
    Ok(rx)
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

    for event in watch_files(&cli.input)?.iter() {
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
    let plaintext_content = std::fs::read_to_string(&file)?;

    for target in &config.targets {
        info!(".. with target {}", &target.name);
        let bundle = encrypt_for(&plaintext_content, target)?;
        bundle.write_to_path(&config.output, &target.name, filename)?;
    }
    Ok(())
}

fn encrypt_for(plaintext: &str, target: &Target) -> Result<Bundle, anyhow::Error> {
    let sym_cipher = SymmetricCipher::new();
    let ciphertext = sym_cipher.encrypt(plaintext.as_bytes())?;

    let rsa_key = RsaKeyfile::from_url(&target.key_url)?.into_rsa_key()?;
    let mut sym_enc_key = vec![0; rsa_key.size() as usize];
    rsa_key.public_encrypt(
        sym_cipher.get_key().as_slice(),
        sym_enc_key.as_mut_slice(),
        Padding::PKCS1,
    )?;

    Ok(Bundle {
        ciphertext,
        enc_key: sym_enc_key,
    })
}
