use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use clap::Parser;
use notify::event::AccessKind;
use notify::{EventKind, Watcher, Event, RecommendedWatcher};
use std::fs::{File, remove_file};
use reqwest::blocking::multipart::{Part, Form};
use common::bundle::Bundle;
use anyhow::Context;

mod test_server;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    input: PathBuf,

    #[arg(long)]
    target: String,
}

fn file_to_form(path: &PathBuf) -> Result<Form, anyhow::Error> {
    let file = File::open(path).context(format!("Error opening input file: {:?}", &path))?;
    let bundle: Bundle = bincode::deserialize_from(&file).context("Error deserializing")?;
    let form = Form::new()
        .part(
            "files[]",
            Part::bytes(bundle.ciphertext)
                .file_name("form.zip")
                .mime_str("application/zip").context("Failed to set MIME type")?
        )
        .text("key", hex::encode(bundle.enc_key));
    Ok(form)
}

fn watch_files(
    path: &Path,
) -> Result<(RecommendedWatcher, Receiver<notify::Result<Event>>), anyhow::Error> {
    let (tx, rx) = channel();

    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(path, notify::RecursiveMode::NonRecursive)?;
    Ok((watcher, rx))
}

fn main()  -> Result<(), anyhow::Error> {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let cli = Cli::parse();

    let (_watcher, events) = watch_files(&cli.input)?;
    for event in events {
        let event = event?;
        if let EventKind::Access(AccessKind::Close(_)) = &event.kind {
            for path in event.paths {
                let form = file_to_form(&path).context("Failed to construct form")?;
                let response = reqwest::blocking::Client::new().post(&cli.target).multipart(form).send().context("HTTP request failed")?;

                if !response.status().is_success() {
                    log::error!("HTTP request failed: {:?}", response);
                    if let Ok(text) = response.text() {
                        log::error!("HTTP reponse text: {}", text);
                    }
                } else {
                    log::info!("{} sent succesfully", path.display());
                    remove_file(path).context("File deletion failed")?;
                }
            }
        }
    }

    Err(anyhow::format_err!("Exited the main loop"))
}
