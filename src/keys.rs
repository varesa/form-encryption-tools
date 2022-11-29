use serde_derive::Deserialize;
use std::io::Read;
use log::info;
use openssl::pkey;
use openssl::rsa::Rsa;

#[derive(Debug, Deserialize)]
pub struct RsaKeyfile {
    kty: String,
    n: String,
    e: String,
}

impl RsaKeyfile {
    pub fn from_raw_string(data: &str) -> Result<RsaKeyfile, anyhow::Error> {
        serde_json::from_str(data).map_err(|err| err.into())
    }

    pub fn from_url(url: &str) -> Result<RsaKeyfile, anyhow::Error> {
        info!("Fetching {}", url);
        let mut keyfile_string = String::new();
        reqwest::blocking::get(url)?.read_to_string(&mut keyfile_string)?;

        Self::from_raw_string(&keyfile_string)
    }

    pub fn into_rsa_key(self) -> Result<Rsa<pkey::Public>, anyhow::Error> {
        if &self.kty != "RSA" {
            return Err(anyhow::format_err!("Invalid keytype: {}, expected RSA", &self.kty));
        }

        let n_slice = data_encoding::BASE64URL_NOPAD.decode(self.n.as_bytes())?;
        let e_slice = data_encoding::BASE64URL_NOPAD.decode(self.e.as_bytes())?;
        let rsa_key = openssl::rsa::Rsa::from_public_components(
            openssl::bn::BigNum::from_slice(&n_slice)?,
            openssl::bn::BigNum::from_slice(&e_slice)?,
        )?;
        Ok(rsa_key)
    }
}