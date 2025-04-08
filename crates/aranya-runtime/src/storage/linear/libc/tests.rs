#![cfg(test)]

use std::fs;

use tracing::info;

use super::*;
use crate::{
    storage::linear::LinearStorageProvider,
    testing::dsl::{test_suite, StorageBackend},
    Address, Command, CommandId, GraphId, Perspective as _, PolicyId, Prior, Priority,
    StorageProvider as _,
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

struct Init(CommandId);

impl Command for Init {
    fn priority(&self) -> Priority {
        Priority::Init
    }

    fn id(&self) -> CommandId {
        self.0
    }

    fn parent(&self) -> Prior<Address> {
        Prior::None
    }

    fn policy(&self) -> Option<&[u8]> {
        None
    }

    fn bytes(&self) -> &[u8] {
        &[0]
    }
}

#[test]
fn test_multiple_graph_ids() {
    let tempdir = tempfile::tempdir().unwrap();
    info!(path = ?tempdir.path(), "using tempdir");
    let mut backend = LinearBackend { tempdir };
    let mut provider = backend.provider(0);

    let init_cmd1 = Init([1u8; 64].into());
    let mut fp1 = provider.new_perspective(PolicyId::new(0));
    let _ = fp1.add_command(&init_cmd1);
    let _ = provider.new_storage(fp1).unwrap();

    let init_cmd2 = Init([2u8; 64].into());
    let mut fp2 = provider.new_perspective(PolicyId::new(1));
    let _ = fp2.add_command(&init_cmd2);
    let _ = provider.new_storage(fp2).unwrap();

    let graph_ids = provider.list_graph_ids().unwrap().collect::<Vec<_>>();
    assert_eq!(
        graph_ids,
        vec![GraphId::from([2u8; 64]), GraphId::from([1u8; 64])]
    );
}

test_suite!(|| {
    let tempdir = tempfile::tempdir().unwrap();
    info!(path = ?tempdir.path(), "using tempdir");
    LinearBackend { tempdir }
});
