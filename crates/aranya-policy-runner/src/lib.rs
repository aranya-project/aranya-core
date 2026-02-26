#![doc = include_str!("../README.md")]
//! ## Programmatic usage
//!
//! The internals can also be used programmatically. For more information, see the [`PolicyRunner`]
//! documentation.
mod io;
mod policy;
mod rng;
pub mod runfile;
mod sink;
mod working_directory;

use std::{
    borrow::Cow,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use aranya_crypto::{Csprng, default::DefaultEngine};
use aranya_policy_vm::Identifier;
use aranya_runtime::{
    ActionPlacement, Policy as _, PolicyId, Sink as _, Storage as _, StorageProvider as _, TraversalBuffer, VmAction
};
use policy::{create_vmpolicy, load_and_compile_policy};
use rng::SwitchableRng;
use runfile::PolicyRunnable;
pub use runfile::RunFile;
use sink::EchoSink;
use working_directory::WorkingDirectory;
pub use io::testing_ffi;

/// The core Policy Runner object
///
/// By default, a temporary working directory is used and it will be deleted after execution.
/// Set a specific, persistent working directory with
/// [`with_working_directory()`](Self::with_working_directory).
///
/// This will not do anything useful until you load run files with
/// [`with_runfile_paths()`](Self::with_runfile_paths) or
/// [`with_runfiles()`](Self::with_runfiles).
///
/// Several options can be set which affect execution. They are all off by default and can be set
/// via `with_*` option modifiers.
///
/// | Option | Meaning |
/// |--------|---------|
/// | `with_working_directory(Option<PathBuf>)` | Set a working directory (`Some`) or use a temporary directory (`None`) |
/// | `with_deterministic_rng(bool)` | Use a deterministic RNG implementation. |
/// | `with_marker(bool)` | Print a marker between run files that shows which run file is producing the effects. |
/// | `with_validator(bool)` | Run the compiler validator before execution. |
#[derive(Debug, Clone)]
#[must_use]
pub struct PolicyRunner {
    working_directory: WorkingDirectory,
    run_files: Vec<RunFile>,
    policy: String,
    deterministic_rng: bool,
    marker: bool,
    validator: bool,
}

impl PolicyRunner {
    /// Create a new policy runner with a policy file at the given path.
    pub fn new_from_path(policy_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::new_from_reader(fs::File::open(policy_path)?)
    }

    /// Create a new policy runner with a policy from the given string. For usage
    pub fn new_from_reader<R: std::io::Read>(policy: R) -> anyhow::Result<Self> {
        let working_directory = WorkingDirectory::new_temporary();
        let policy: String = std::io::read_to_string(policy)?;
        Ok(Self {
            working_directory,
            run_files: Vec::new(),
            policy,
            deterministic_rng: false,
            marker: false,
            validator: false,
        })
    }

    /// Explicitly set the working directory. If `path` is `Some`, the
    /// path is used as the working direcotry. If `path` is `None`, a
    /// temporary working directory is used.
    pub fn with_working_directory(mut self, path: Option<PathBuf>) -> Self {
        self.working_directory = path
            .map(WorkingDirectory::new)
            .unwrap_or_else(WorkingDirectory::new_temporary);
        self
    }

    /// Load run files from their paths. This is not additive. The list of run files is replaced
    /// by the `Vec` given to this method.
    pub fn with_runfile_paths(mut self, run_paths: Vec<PathBuf>) -> anyhow::Result<Self> {
        self.run_files = run_paths
            .iter()
            .map(RunFile::from_file)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self)
    }

    /// Load run files from pre-created objects.
    pub fn with_runfiles(mut self, run_files: Vec<RunFile>) -> anyhow::Result<Self> {
        self.run_files = run_files;
        Ok(self)
    }

    /// Configure whether to use a deterministic RNG. This causes all
    /// randomly-generated keys and IDs to be the same on every run.
    /// This does _not_ affect the randomly generated temporary
    /// directory path.
    pub fn with_deterministic_rng(mut self, deterministic_rng: bool) -> Self {
        self.deterministic_rng = deterministic_rng;
        self
    }

    /// Configure whether to print markers between each run file as they execute.
    pub fn with_marker(mut self, marker: bool) -> Self {
        self.marker = marker;
        self
    }

    /// Configure whether to run the compiler validator before execution.
    pub fn with_validator(mut self, validator: bool) -> Self {
        self.validator = validator;
        self
    }

    /// Loads the crypto engine using the secret key
    fn load_crypto_engine<R: Csprng>(&self, rng: R) -> anyhow::Result<DefaultEngine<R>> {
        let secret_key = self.working_directory.load_secret_key(&rng)?;
        Ok(DefaultEngine::new(&secret_key, rng))
    }

    // This function mainly serves as a boundary for the main run file and
    // policy execution logic, so that its errors can be handled
    // independently of things like logging or setting up and tearing down
    // the working directory.
    fn inner_logic(&self) -> anyhow::Result<()> {
        // Load or generate policy prerequisites: Keystore, RNG, Device ID, and Crypto Engine
        let mut keystore = self.working_directory.load_keystore()?;
        let rng = if self.deterministic_rng {
            SwitchableRng::new_deterministic()
        } else {
            SwitchableRng::new_default()
        };
        let device_id = self.working_directory.load_device_id(&rng)?;
        let mut crypto_engine = self.load_crypto_engine(rng)?;

        // Iterate over all run files, execute their preambles, and collect
        // those values into `runfile_globals`.
        // This two-stage iter/collect looks a little weird, but the first
        // stage handles the `Result`s created by the map closure and the
        // second one flattens the `Vec`s created by
        // `get_preamble_values()`.
        let runfile_globals = self
            .run_files
            .iter()
            .map(|rf| rf.get_preamble_values(&mut crypto_engine, &mut keystore))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        // Compile the policy with additional globals provided by the run files
        let (machine, run_schedules) = load_and_compile_policy(
            &self.policy,
            runfile_globals,
            &self.run_files,
            self.validator,
        )?;
        let vm_policy = create_vmpolicy(machine, crypto_engine, keystore, device_id)?;

        let mut provider = self.working_directory.get_storage_provider()?;
        let mut sink = EchoSink::default();

        let (mut perspective, storage) = match self.working_directory.get_graph_id()? {
            Some(graph_id) => {
                let storage = provider.get_storage(graph_id)?;
                let head = storage.get_head()?;
                (storage.get_linear_perspective(head)?, Some(storage))
            }
            None => {
                tracing::debug!("creating new graph");
                (provider.new_perspective(PolicyId::new(0)), None)
            }
        };

        for schedule in run_schedules {
            if self.marker {
                println!("--- {}", schedule.file_path.display());
            }
            for i in schedule.thunk_range {
                let action_ident = Identifier::try_from(format!("policy_runner_thunk_{i}"))
                    .context("thunk {i} should be defined")?;

                let action = VmAction {
                    name: action_ident,
                    args: Cow::Borrowed(&[]),
                };
                sink.begin();
                vm_policy
                    .call_action(
                        action,
                        &mut perspective,
                        &mut sink,
                        ActionPlacement::OnGraph,
                    )
                    .inspect_err(|_| sink.rollback())?;
                sink.commit();
            }
        }

        if let Some(storage) = storage {
            // Storage already exists, commit
            let segment = storage.write(perspective)?;
            storage.commit(segment, &mut TraversalBuffer::new())?;
        } else {
            // Storage did not already exist, create a new one and save our Graph ID
            let (new_graph_id, _) = provider.new_storage(perspective)?;
            self.working_directory.save_graph_id(new_graph_id)?;
        }
        Ok(())
    }

    /// Run the configured policy runner. Returns the working directory configuration.
    ///
    /// Note: This consumes `self` not because it really needs to - all internal state is
    /// unchanged during execution. It serves as a brake against concurrent runs
    /// manipulating the same underlying filesystem state.
    pub fn run(self) -> anyhow::Result<WorkingDirectory> {
        if self.working_directory.is_temporary {
            tracing::info!(
                "Using temporary directory `{}`",
                self.working_directory.base_dir().display()
            );
        }
        self.working_directory
            .make_dirs()
            .context("Could not create working directory")?;

        self.inner_logic()
            .inspect_err(|e| eprintln!("Execution failed: {e}"))
            .ok();

        if self.working_directory.is_temporary {
            // Clean up temporary working directory
            tracing::debug!(
                "Removing temporary working directory {}",
                self.working_directory.base_dir().display()
            );
            self.working_directory.delete()?;
        }
        Ok(self.working_directory)
    }
}
