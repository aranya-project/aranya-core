#![cfg(test)]

use std::fs;

use tracing::info;

use super::*;
use crate::{
    storage::linear::LinearStorageProvider,
    testing::dsl::{test_suite, StorageBackend},
};

struct LinearBackend {
    tempdir: tempfile::TempDir,
}

impl StorageBackend for LinearBackend {
    type StorageProvider = LinearStorageProvider<FileManager>;

    fn provider(&mut self, client_id: u64) -> Self::StorageProvider {
        let dir = self.tempdir.path().join(client_id.to_string());
        fs::create_dir(&dir).unwrap();
        let manager = FileManager::new(&dir).unwrap();
        LinearStorageProvider::new(manager)
    }
}

test_suite!(|| {
    let tempdir = tempfile::tempdir().unwrap();
    info!(path = ?tempdir.path(), "using tempdir");
    LinearBackend { tempdir }
});
