use crate::sources::{Data, Source};
use anyhow::Context;
use anyhow::Error;
use notify::event::AccessKind;
use notify::{EventKind, Watcher};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::thread;

pub struct FileSource {
    rx: Receiver<PathBuf>,
}

impl FileSource {
    pub fn new(path: &str) -> Self {
        let path = path.to_owned();
        let (file_tx, file_rx) = channel();
        thread::spawn(move || {
            let (event_tx, event_rx) = channel();
            let mut watcher =
                notify::recommended_watcher(event_tx).expect("Failed to create watcher");
            watcher
                .watch(path.as_ref(), notify::RecursiveMode::NonRecursive)
                .expect("Failed to watch directory");

            for event in event_rx {
                let event = event.expect("Failed to get event");
                if let EventKind::Access(AccessKind::Close(_)) = &event.kind {
                    for path in event.paths {
                        file_tx.send(path).expect("Failed to send filename");
                    }
                }
            }
        });

        Self { rx: file_rx }
    }
}

impl Source for FileSource {
    fn next(&self) -> Result<Data, Error> {
        let fname = self.rx.recv().context("Failed to receive filename")?;
        let contents = fs::read(&fname).context("Failed to read file")?;

        let data = Data {
            contents,
            id: fname
                .file_name()
                .ok_or_else(|| anyhow::Error::msg("Unable to get input filename"))?
                .to_os_string(),
        };
        Ok(data)
    }

    fn confirm(&self, id: OsString) -> Result<(), Error> {
        let fname = id;
        fs::remove_file(fname).context("Failed to remove file")
    }
}
