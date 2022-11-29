use std::fs;
use std::path::PathBuf;
use anyhow::Context;
use clap::Parser;

use crate::config::Config;

mod config;

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
    let cli = Cli::parse();
    let config_string = fs::read_to_string(&cli.config).context(format!("Error reading the config file: {:?}", &cli.config))?;
    let config: Config = toml::from_str(&config_string)?;

    Ok(())
}
