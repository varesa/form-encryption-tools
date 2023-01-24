use crate::sources::{Data, Source};
use anyhow::Error;
use std::ffi::OsString;

pub struct SshSource {}

impl SshSource {
    pub fn new(_url: &str) -> Self {
        Self {}
    }
}

impl Source for SshSource {
    fn next(&self) -> Result<Data, Error> {
        todo!()
    }

    fn confirm(&self, _id: OsString) -> Result<(), Error> {
        todo!()
    }
}
