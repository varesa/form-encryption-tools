use std::path::PathBuf;
use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Target {
    pub name: String,
    pub key_url: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    pub targets: Vec<Target>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub targets: Vec<Target>,
    pub output: PathBuf,
}