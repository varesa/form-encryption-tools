use anyhow::Context;
use clap::Parser;
use log::info;
use notify::event::AccessKind;
use notify::{Event, EventKind, RecommendedWatcher, Watcher};
use openssl::rsa::Padding;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};

use crate::bundle::Bundle;
use crate::config::{Config, ConfigFile, Target};
use crate::keys::RsaKeyfile;
use crate::symmetric_cipher::SymmetricCipher;

mod bundle;
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

fn watch_files(
    path: &Path,
) -> Result<(RecommendedWatcher, Receiver<notify::Result<Event>>), anyhow::Error> {
    let (tx, rx) = channel();

    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(path, notify::RecursiveMode::NonRecursive)?;
    Ok((watcher, rx))
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
        let bundle =
            encrypt_for(&plaintext_content, target).context(format!("Error encrypting"))?;
        bundle
            .write_to_path(&config.output, &target.name, filename)
            .context(format!("Error writing output file"))?;
    }

    info!("Done with {}", file.display());
    Ok(())
}

fn encrypt_for(plaintext: &[u8], target: &Target) -> Result<Bundle, anyhow::Error> {
    let sym_cipher = SymmetricCipher::new();
    let ciphertext = sym_cipher.encrypt(plaintext)?;

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
