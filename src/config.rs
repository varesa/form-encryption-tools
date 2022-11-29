use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Target {
    name: String,
    key_url: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    targets: Vec<Target>,
}