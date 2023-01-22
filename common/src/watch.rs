use notify::{Event, RecommendedWatcher, Watcher};
use std::sync::mpsc::{channel, Receiver};
use std::path::Path;

pub fn watch_files(
    path: &Path,
) -> Result<(RecommendedWatcher, Receiver<notify::Result<Event>>), anyhow::Error> {
    let (tx, rx) = channel();

    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(path, notify::RecursiveMode::NonRecursive)?;
    Ok((watcher, rx))
}