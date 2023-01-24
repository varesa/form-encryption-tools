use crate::sources::{Data, Source};
use anyhow::Context;
use anyhow::Error;
use notify::event::AccessKind;
use notify::{EventKind, Watcher};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;

pub struct FileSource {
    rx: Receiver<PathBuf>,
    thread: Option<JoinHandle<Result<(), Box<Error>>>>,
}

fn watcher_thread(path: String, file_tx: Sender<PathBuf>) -> Result<(), Box<anyhow::Error>> {
    let (event_tx, event_rx) = channel();
    let mut watcher = notify::recommended_watcher(event_tx).expect("Failed to create watcher");
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
    Err(Box::new(anyhow::Error::msg("Exited the watcher loop")))
}

impl FileSource {
    pub fn new(path: &str) -> Self {
        let path = path.to_owned();
        let (tx, rx) = channel();
        let thread = Some(thread::spawn(move || watcher_thread(path, tx)));
        Self { thread, rx }
    }
}

impl Source for FileSource {
    fn next(&mut self) -> Result<Data, Error> {
        // Check that thread is alive
        if self
            .thread
            .as_ref()
            .expect("Thread has already died")
            .is_finished()
        {
            let x = self.thread.take().unwrap().join();
            return Err(match x {
                Err(e) => anyhow::Error::msg(format!("Thread panicked: {:?}", e)),
                Ok(r) => match r {
                    Ok(_) => anyhow::Error::msg("Thread unexpectedly exited without error"),
                    Err(e) => *e,
                },
            });
        }

        // Read a filename from queue
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
