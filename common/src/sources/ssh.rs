use crate::sources::{Data, Source};
use anyhow::Error;
use log::info;
use ssh2::{Session, Sftp};
use std::ffi::OsString;
use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;
use std::{env, thread};

fn split2(s: &str, pattern: char) -> Result<(String, String), Error> {
    let mut v: Vec<&str> = s.split(pattern).collect();
    if v.len() != 2 {
        return Err(Error::msg("Unexpected split"));
    }
    let second = v.pop().unwrap().to_string();
    let first = v.pop().unwrap().to_string();
    Ok((first, second))
}

struct RemoteParameters {
    username: Option<String>,
    hostname: String,
    path: String,
}

fn parse_connection_string(connection: &str) -> Result<RemoteParameters, Error> {
    let (connection_string, path) = split2(connection, ':')?;

    let username;
    let hostname;

    if connection_string.contains('@') {
        let (un, hn) = split2(&connection_string, '@')?;
        username = Some(un);
        hostname = hn;
    } else {
        username = None;
        hostname = connection_string;
    }

    Ok(RemoteParameters {
        username,
        hostname,
        path,
    })
}

pub struct SshSource {
    sftp: Sftp,
    directory: PathBuf,
}

impl SshSource {
    pub fn new(url: &str) -> Result<Self, Error> {
        let remote_parameters = parse_connection_string(url)?;

        let username = if let Some(username) = remote_parameters.username {
            username
        } else {
            env::var("USER").expect("Unable to get current $USER")
        };

        let private_key = PathBuf::new()
            .join(env::var("HOME").expect("Unable to read $HOME"))
            .join(".ssh/id_ed25519");

        info!("Connnecting SSH");
        let tcp = TcpStream::connect(format!("{}:22", remote_parameters.hostname)).unwrap();
        let mut sess = Session::new().unwrap();
        sess.set_tcp_stream(tcp);
        sess.handshake()?;
        info!("SSH connected");
        sess.userauth_pubkey_file(&username, None, &private_key, None)?;
        if !sess.authenticated() {
            return Err(Error::msg("Authentication failed"));
        }
        info!("SSH authenticated");

        let sftp = sess.sftp()?;
        info!("SFTP session open");

        Ok(Self {
            sftp,
            directory: PathBuf::from(remote_parameters.path),
        })
    }
}

impl Source for SshSource {
    fn next(&mut self) -> Result<Data, Error> {
        let path = loop {
            let mut files = self.sftp.readdir(&self.directory)?;
            if files.len() > 0 {
                break files.pop().unwrap().0;
            } else {
                thread::sleep(Duration::from_secs(5));
            }
        };

        let mut file = self.sftp.open(&path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        Ok(Data {
            id: path.into_os_string(),
            contents,
        })
    }

    fn confirm(&self, id: OsString) -> Result<(), Error> {
        self.sftp.unlink(&PathBuf::from(&id))?;
        Ok(())
    }
}
