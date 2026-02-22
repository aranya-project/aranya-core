#![cfg(test)]

use std::fs;
use tracing::info;

use super::*;
use crate::{
    storage::linear::LinearStorageProvider,
    testing::dsl::{StorageBackend, test_suite},
};

struct LinearBackend {
    tempdir: tempfile::TempDir,
    setup_clients_cap: Option<u64>,
}

impl LinearBackend {
    fn new(tempdir: tempfile::TempDir) -> Self {
        Self {
            tempdir,
            setup_clients_cap: None,
        }
    }

    fn setup_clients_cap(&mut self, requested: u64) -> u64 {
        if let Some(cap) = self.setup_clients_cap {
            return cap;
        }
        let cap = self.probe_setup_clients_cap(requested);
        self.setup_clients_cap = Some(cap);
        cap
    }

    /// Probes how many per-client `FileManager`s this process can
    /// sustain and returns a conservative client cap for
    /// `SetupClientsAndGraph`.
    ///
    /// The probe intentionally opens and holds one `FileManager`
    /// (and therefore one directory file descriptor) per synthetic
    /// client until failure or until `requested` is reached. This
    /// gives a backend- and environment-specific bound that accounts
    /// for current process state, unlike a fixed constant.
    ///
    /// If opening fails after at least one manager is open, we derive
    /// a cap from the number successfully opened, reserve headroom for
    /// unrelated descriptors, and apply a safety factor because each
    /// client can use more than one descriptor during the test.
    ///
    /// # Panics
    ///
    /// Panics if creating the probe directories fails or if the first
    /// `FileManager` cannot be opened.
    fn probe_setup_clients_cap(&self, requested: u64) -> u64 {
        // This probe estimates a safe upper bound for the
        // `SetupClientsAndGraph` "clients" fanout in this process.
        //
        // Why probe instead of using a fixed number?
        // - CI and local environments vary widely in RLIMIT_NOFILE.
        // - Other tests/process state may already hold descriptors.
        // - We need a backend-specific, runtime-derived limit.
        //
        // Keep headroom for stderr/stdout, test harness internals,
        // dynamic libs, and any unrelated open FDs.
        const RESERVED_FDS: u64 = 32;

        // Build probe directories under the same temp root used by
        // this backend so open patterns match the real workload.
        let root = self.tempdir.path().join("__fd_probe");
        fs::create_dir_all(&root).unwrap();

        // Intentionally retain all opened FileManagers in this vec:
        // each manager owns an open directory FD. If we dropped them
        // immediately, we'd never approach the process FD ceiling.
        let mut managers = Vec::new();
        let mut opened = 0u64;

        for i in 0..requested {
            let dir = root.join(i.to_string());
            fs::create_dir_all(&dir).unwrap();
            match FileManager::new(&dir) {
                Ok(manager) => {
                    managers.push(manager);
                    opened += 1;
                }
                Err(err) => {
                    if opened == 0 {
                        // Failing on the first open means the
                        // environment is fundamentally broken for this
                        // backend test (not just "too many clients").
                        panic!("unable to probe file-manager capacity: {err:?}");
                    }

                    // Convert the number of currently-open manager FDs
                    // into a conservative client cap.
                    //
                    // Heuristic:
                    // - subtract RESERVED_FDS for process headroom
                    // - divide by 2 because each client often implies
                    //   more than one simultaneously-open descriptor
                    //   during this scenario
                    // - clamp to at least 1 so the vector can still run
                    let cap = opened.saturating_sub(RESERVED_FDS) / 2;
                    let cap = cap.max(1);
                    info!(
                        requested,
                        opened,
                        cap,
                        ?err,
                        "detected open-file limit; clamping `many_clients` fanout"
                    );
                    return cap;
                }
            }
        }
        // If we can open `requested` managers without error, no clamp
        // is needed for this environment.
        requested
    }
}

impl StorageBackend for LinearBackend {
    type StorageProvider = LinearStorageProvider<FileManager>;

    fn provider(&mut self, client_id: u64) -> Self::StorageProvider {
        let dir = self.tempdir.path().join(client_id.to_string());
        fs::create_dir(&dir).unwrap();
        let manager = FileManager::new(&dir).unwrap();
        LinearStorageProvider::new(manager)
    }

    fn setup_clients_and_graph_clients(&mut self, requested: u64) -> u64 {
        requested.min(self.setup_clients_cap(requested))
    }
}

test_suite!(|| {
    let tempdir = tempfile::tempdir().unwrap();
    info!(path = ?tempdir.path(), "using tempdir");
    LinearBackend::new(tempdir)
});
