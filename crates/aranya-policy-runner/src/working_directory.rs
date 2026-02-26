use std::{
    env::temp_dir,
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, anyhow};
use aranya_crypto::{
    BaseId, Csprng, DeviceId,
    dangerous::spideroak_crypto::{import::Import, keys::SecretKey},
    keystore::fs_keystore,
};
use aranya_runtime::{
    GraphId,
    linear::{LinearStorageProvider, libc::FileManager},
};
use rand::random;

/// WorkingDirectory manages derived paths from a base working directory
/// and keeps track of whether the path is temporary. It also provides
/// file I/O functions to save and load data within the working
/// directory.
#[derive(Debug, Clone)]
pub struct WorkingDirectory {
    // The base working directory
    base: PathBuf,
    // True if the base working directory is temporary
    pub is_temporary: bool,
}

impl WorkingDirectory {
    /// Create a non-temporary `WorkingDirectory` from a path.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            base: path.as_ref().to_path_buf(),
            is_temporary: false,
        }
    }

    /// Create a temporary `WorkingDirectory` from a randomly generated
    /// path under the system temporary directory.
    pub fn new_temporary() -> Self {
        let dir_id = BaseId::from_bytes(random());
        Self {
            base: temp_dir().join(format!("policy-runner-{dir_id}")),
            is_temporary: true,
        }
    }

    /// Get the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base
    }

    /// Delete the working directory and all of its contents.
    pub fn delete(&self) -> Result<(), io::Error> {
        fs::remove_dir_all(&self.base)
    }

    /// The path to the keystore directory
    fn keystore_dir(&self) -> PathBuf {
        self.base.join("keystore")
    }

    /// The path to the crypto engine's secret root key
    fn secret_key(&self) -> PathBuf {
        self.keystore_dir().join("secret_key")
    }

    /// The path to the graph storage directory
    fn graph_dir(&self) -> PathBuf {
        self.base.join("graph")
    }

    /// The path to the stored Graph ID file
    fn graph_id(&self) -> PathBuf {
        self.base.join("graph_id")
    }

    /// The path to the serialized Device ID file
    fn device_id(&self) -> PathBuf {
        self.base.join("device_id")
    }

    /// Utility function to create all necessary directories
    pub fn make_dirs(&self) -> anyhow::Result<()> {
        for d in [&self.keystore_dir(), &self.graph_dir()] {
            fs::create_dir_all(d)?;
        }
        Ok(())
    }

    /// Loads the Device ID from disk or generates a new one
    pub fn load_device_id(&self, rng: &impl Csprng) -> anyhow::Result<DeviceId> {
        let id_path = self.device_id();

        match fs::read(&id_path) {
            Ok(buf) => {
                tracing::debug!("loaded Device ID from '{}'", id_path.display());
                let bytes = buf
                    .try_into()
                    .map_err(|_| anyhow!("Stored Device ID is not exactly 32 bytes"))?;
                let device_id = DeviceId::from_bytes(bytes);
                Ok(device_id)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                tracing::debug!("generating device ID");
                let mut rng_device_id = [0u8; 32];
                rng.fill_bytes(&mut rng_device_id);
                let device_id = DeviceId::from_bytes(rng_device_id);
                fs::write(&id_path, rng_device_id)?;
                tracing::debug!("Device ID saved to '{}'", id_path.display());
                Ok(device_id)
            }
            Err(err) => Err(err).context("unable to read Device ID"),
        }
    }

    /// Loads the keystore from disk
    pub fn load_keystore(&self) -> Result<fs_keystore::Store, fs_keystore::Error> {
        fs_keystore::Store::open(self.keystore_dir())
    }

    /// Loads the crypto engine secret key from a file or generates and
    /// writes a new one.
    pub fn load_secret_key<K: SecretKey, R: Csprng>(&self, rng: &R) -> anyhow::Result<K> {
        let key_path = self.secret_key();
        match fs::read(&key_path) {
            Ok(buf) => {
                tracing::debug!(
                    "crypto engine secret key loaded from '{}'",
                    key_path.display()
                );
                let key =
                    Import::import(buf.as_slice()).context("unable to import key from file")?;
                Ok(key)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                tracing::debug!("generating crypto engine secret key");
                let key = K::random(rng);
                let bytes = key
                    .try_export_secret()
                    .context("unable to export new key")?;
                fs::write(&key_path, bytes.as_bytes())?;
                tracing::debug!("crypto engine secret key saved to '{}'", key_path.display());
                Ok(key)
            }
            Err(err) => Err(err).context("unable to read key"),
        }
    }

    /// Loads the file-based storage provider using its configured directory
    pub fn get_storage_provider(&self) -> anyhow::Result<LinearStorageProvider<FileManager>> {
        let storage_path = self.graph_dir();
        let fm = FileManager::new(&storage_path)?;
        Ok(LinearStorageProvider::new(fm))
    }

    /// Loads the graph ID from the filesystem, if it exists. If it doesn't
    /// exist, returns `Ok(None)`.
    pub fn get_graph_id(&self) -> anyhow::Result<Option<GraphId>> {
        let id_path = self.graph_id();

        match fs::read(&id_path) {
            Ok(buf) => {
                tracing::debug!("loaded Graph ID from '{}'", id_path.display());
                let bytes = buf
                    .try_into()
                    .map_err(|_| anyhow!("Stored Graph ID is not exactly 32 bytes"))?;
                Ok(Some(GraphId::from_bytes(bytes)))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).context("unable to read Device ID"),
        }
    }

    /// Save the graph ID to the filesystem.
    pub fn save_graph_id(&self, graph_id: GraphId) -> anyhow::Result<()> {
        let id_path = self.graph_id();
        fs::write(&id_path, graph_id)?;
        tracing::debug!("Graph ID saved to '{}'", id_path.display());
        Ok(())
    }
}
