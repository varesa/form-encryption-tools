use anyhow::Error;
use clap::Parser;
use common::{bundle::Bundle, sources, sources::Data, symmetric_cipher::SymmetricCipher};
use lettre::{
    message::{Attachment, Body, Message, MultiPart, SinglePart},
    SmtpTransport, Transport,
};
use log::info;
use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};
use serde_json::Value;
use std::{fs, io::Cursor, path::PathBuf};
use zip::ZipArchive;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    source: String,

    #[arg(long)]
    private_key: PathBuf,

    #[arg(long)]
    smtp_server: String,

    #[arg(long)]
    smtp_address: String,
}

fn main() -> Result<(), Error> {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    info!("Started");

    let cli = Cli::parse();

    info!("Loading private key");
    let private_key_pem = fs::read(&cli.private_key)?;
    let private_key = Rsa::private_key_from_pem(&private_key_pem)?;

    info!("Opening SMTP connection");
    let mailer = SmtpTransport::builder_dangerous(&cli.smtp_server).build();

    let mut source = sources::from_string(&cli.source)?;
    loop {
        let data = source.next()?;
        handle_file(&data, &private_key, &mailer, &cli.smtp_address)?;
        source.confirm(data.id)?;
    }
}

fn handle_file(
    data: &Data,
    private_key: &Rsa<Private>,
    mailer: &SmtpTransport,
    smtp_address: &str,
) -> Result<(), Error> {
    let bundle: Bundle = bincode::deserialize(&data.contents).unwrap();

    let mut buf = vec![0; private_key.size() as usize];
    private_key
        .private_decrypt(
            bundle.enc_key.as_slice(),
            buf.as_mut_slice(),
            Padding::PKCS1,
        )
        .unwrap();

    let sym_enc_key = &buf[0..32];

    let cipher = SymmetricCipher::new(Some(sym_enc_key));
    let plaintext = cipher.decrypt(&bundle.ciphertext)?;
    send_email(&plaintext, mailer, smtp_address)?;
    Ok(())
}

fn send_email(zip: &[u8], mailer: &SmtpTransport, smtp_address: &str) -> Result<(), Error> {
    let mut zip_archive = ZipArchive::new(Cursor::new(zip))?;
    let text = if let Ok(f) = zip_archive.by_name("formdata.json") {
        let data: Value = serde_json::from_reader(f)?;
        serde_json::to_string_pretty(&data)?
    } else {
        "ZipFile did not contain formdata.json".to_string()
    };

    info!("Constructing email message");
    let message = Message::builder()
        .from(
            "Hakulomake <noreply@localhost.localdomain>"
                .parse()
                .unwrap(),
        )
        .to(smtp_address.parse()?)
        .subject("Hakulomake")
        .multipart(
            MultiPart::mixed()
                .singlepart(SinglePart::plain(text))
                .singlepart(
                    Attachment::new("lomake.zip".to_string())
                        .body(Body::new(zip.to_vec()), "application/zip".parse()?),
                ),
        )
        .unwrap();

    info!("Sending email");
    mailer.send(&message)?;
    Ok(())
}
