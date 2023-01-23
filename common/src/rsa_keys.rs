use anyhow::Context;
use log::info;
use openssl::pkey;
use openssl::rsa::Rsa;
use serde_derive::Deserialize;
use std::io::Read;

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

#[derive(Debug, Deserialize)]
pub struct RsaPubkey {
    kty: String,
    n: String,
    e: String,
}

impl RsaPubkey {
    pub fn into_rsa_key(self) -> Result<Rsa<pkey::Public>, anyhow::Error> {
        if &self.kty != "RSA" {
            return Err(anyhow::format_err!(
                "Invalid keytype: {}, expected RSA",
                &self.kty
            ));
        }

        let n_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.n.as_bytes())
            .context("Decoding n")?;
        let e_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.e.as_bytes())
            .context("Decoding e")?;
        let rsa_key = openssl::rsa::Rsa::from_public_components(
            openssl::bn::BigNum::from_slice(&n_slice)?,
            openssl::bn::BigNum::from_slice(&e_slice)?,
        )
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

        let n_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.n.as_bytes())
            .context("Decoding n")
            .unwrap();
        let e_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.e.as_bytes())
            .context("Decoding e")
            .unwrap();
        let d_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.d.as_bytes())
            .context("Decoding d")
            .unwrap();
        let p_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.p.as_bytes())
            .context("Decoding p")
            .unwrap();
        let q_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.q.as_bytes())
            .context("Decoding q")
            .unwrap();
        let dmp1_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.dmp1.as_bytes())
            .context("Decoding dmp")
            .unwrap();
        let dmq1_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.dmq1.as_bytes())
            .context("Decoding dmq")
            .unwrap();
        let iqmp_slice = data_encoding::BASE64URL_NOPAD
            .decode(self.iqmp.as_bytes())
            .context("Decoding iqmp")
            .unwrap();
        let rsa_key = openssl::rsa::Rsa::from_private_components(
            openssl::bn::BigNum::from_slice(&n_slice).unwrap(),
            openssl::bn::BigNum::from_slice(&e_slice).unwrap(),
            openssl::bn::BigNum::from_slice(&d_slice).unwrap(),
            openssl::bn::BigNum::from_slice(&p_slice).unwrap(),
            openssl::bn::BigNum::from_slice(&q_slice).unwrap(),
            openssl::bn::BigNum::from_slice(&dmp1_slice).unwrap(),
            openssl::bn::BigNum::from_slice(&dmq1_slice).unwrap(),
            openssl::bn::BigNum::from_slice(&iqmp_slice).unwrap(),
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
