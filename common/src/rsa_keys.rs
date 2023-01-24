use anyhow::Context;
use data_encoding::BASE64URL_NOPAD;
use log::info;
use openssl::bn::{BigNum, BigNumRef};
use openssl::pkey;
use openssl::rsa::Rsa;
use serde_derive::{Deserialize, Serialize};
use std::io::Read;

pub fn encode(x: &BigNumRef) -> String {
    let raw = x.to_vec();
    BASE64URL_NOPAD.encode(&raw)
}

pub fn decode(x: &str) -> Result<BigNum, anyhow::Error> {
    let raw = BASE64URL_NOPAD.decode(x.as_bytes())?;
    let bn = BigNum::from_slice(&raw)?;
    Ok(bn)
}

pub trait KeyFromString<T> {
    fn from_raw_string(data: &str) -> Result<T, anyhow::Error>;
}

pub trait KeyFromUrl<T> {
    fn from_url(url: &str) -> Result<T, anyhow::Error>;
}

impl<T> KeyFromUrl<T> for T
where
    T: KeyFromString<T>,
{
    fn from_url(url: &str) -> Result<T, anyhow::Error> {
        info!("Fetching {}", url);
        let mut keyfile_string = String::new();
        reqwest::blocking::get(url)?.read_to_string(&mut keyfile_string)?;

        Self::from_raw_string(&keyfile_string)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RsaPubkey {
    kty: String,
    n: String,
    e: String,
}

impl RsaPubkey {
    pub fn from_parts(kty: String, n: String, e: String) -> Self {
        Self { kty, n, e }
    }

    pub fn into_rsa_key(self) -> Result<Rsa<pkey::Public>, anyhow::Error> {
        if &self.kty != "RSA" {
            return Err(anyhow::format_err!(
                "Invalid keytype: {}, expected RSA",
                &self.kty
            ));
        }
        let rsa_key = openssl::rsa::Rsa::from_public_components(decode(&self.n)?, decode(&self.e)?)
            .context("Building RSA key from components")?;
        Ok(rsa_key)
    }
}

impl KeyFromString<RsaPubkey> for RsaPubkey {
    fn from_raw_string(data: &str) -> Result<RsaPubkey, anyhow::Error> {
        serde_json::from_str(data).map_err(|err| err.into())
    }
}

#[derive(Debug, Deserialize)]
pub struct RsaPrivateKey {
    kty: String,
    n: String,
    e: String,
    d: String,
    p: String,
    q: String,
    dmp1: String,
    dmq1: String,
    iqmp: String,
}

impl RsaPrivateKey {
    pub fn into_rsa_key(self) -> Result<Rsa<pkey::Private>, anyhow::Error> {
        if &self.kty != "RSA" {
            return Err(anyhow::format_err!(
                "Invalid keytype: {}, expected RSA",
                &self.kty
            ));
        }

        let rsa_key = openssl::rsa::Rsa::from_private_components(
            decode(&self.n)?,
            decode(&self.e)?,
            decode(&self.d)?,
            decode(&self.p)?,
            decode(&self.q)?,
            decode(&self.dmp1)?,
            decode(&self.dmq1)?,
            decode(&self.iqmp)?,
        )
        .context("Building RSA key from components")
        .unwrap();
        Ok(rsa_key)
    }
}

impl KeyFromString<RsaPrivateKey> for RsaPrivateKey {
    fn from_raw_string(data: &str) -> Result<RsaPrivateKey, anyhow::Error> {
        serde_json::from_str(data).map_err(|err| err.into())
    }
}
