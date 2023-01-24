use crate::sources::file::FileSource;
use crate::sources::ssh::SshSource;
use std::ffi::OsString;

mod file;
mod ssh;

pub struct Data {
    pub contents: Vec<u8>,
    pub id: OsString,
}

pub trait Source {
    fn next(&self) -> Result<Data, anyhow::Error>;
    fn confirm(&self, id: OsString) -> Result<(), anyhow::Error>;
}

pub fn from_string(s: &str) -> Box<dyn Source> {
    if s.starts_with('/') {
        Box::new(FileSource::new(s))
    } else if s.contains(':') {
        Box::new(SshSource::new(s))
    } else {
        panic!("Invalid source specification");
    }
}
