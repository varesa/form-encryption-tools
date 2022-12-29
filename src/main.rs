use std::{fs, sync};
use std::path::PathBuf;
use anyhow::Context;
use clap::Parser;
use notify::{EventKind, Watcher};
use log::info;
use notify::event::AccessKind;

use crate::config::Config;
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
    let config_string = fs::read_to_string(&cli.config).context(format!("Error reading the config file: {:?}", &cli.config))?;
    let config: Config = toml::from_str(&config_string)?;

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

fn handle_file(file: PathBuf, config: &Config) -> Result<(), anyhow::Error> {
    info!("Handling file: {}", file.display());
    let plaintext_content = std::fs::read_to_string(file)?;

    let sym_cipher = SymmetricCipher::new();
    let _ciphertext = sym_cipher.encrypt(plaintext_content.as_bytes())?;
    let _sym_key = sym_cipher.get_key();


    for target in &config.targets {
        info!(".. with target {}", target.name);
        let rsa_key = RsaKeyfile::from_url(&target.key_url)?.into_rsa_key()?;
        dbg!(rsa_key);
    }
    Ok(())
}