use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Target {
    pub name: String,
    pub key_url: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub targets: Vec<Target>,
}