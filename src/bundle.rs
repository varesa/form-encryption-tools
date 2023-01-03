use std::ffi::OsStr;
use std::fs::File;
use std::io::ErrorKind::NotFound;
use std::path::PathBuf;
use log::info;
use serde_derive::Serialize;

#[derive(Debug, Serialize)]
pub struct Bundle {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) enc_key: Vec<u8>,
}

impl Bundle {
    pub fn write_to_path(
        &self,
        output_path: &PathBuf,
        target: &str,
        filename: &OsStr,
    ) -> Result<(), anyhow::Error> {
        let target_dir = PathBuf::from(output_path).join(target);

        match std::fs::metadata(&target_dir) {
            Err(e) => {
                assert_eq!(e.kind(), NotFound);
                info!(
                ".. parent {} does not exist, creating",
                target_dir.display()
            );
                std::fs::create_dir(&target_dir)?;
            }
            Ok(f) => {
                assert!(f.is_dir());
            }
        };

        let file_path = PathBuf::from(&target_dir).join(filename);
        //
        info!(".. output to: {}", &file_path.display());

        info!(".. writing");
        let file = File::create(file_path)?;
        bincode::serialize_into(file, self)?;

        Ok(())
    }
}
