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
    io::Write,
    ops::Range,
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use aranya_crypto::{Csprng, Engine, KeyStore, default::DefaultEngine};
use aranya_policy_compiler::{Compiler, validate::validate};
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{Identifier, Machine, Value};
use aranya_runtime::{
    ActionPlacement, Policy as _, PolicyId, Sink as _, Storage as _, StorageProvider as _, VmAction,
};
pub use io::testing_ffi;
use policy::create_vmpolicy;
use rng::SwitchableRng;
use runfile::PolicyRunnable;
pub use runfile::RunFile;
use sink::WriterSink;
use working_directory::WorkingDirectory;

use crate::{policy::FFI_MODULES, runfile::RunFileError};

#[derive(Debug)]
enum OutputDestination {
    Stdout,
    File(fs::File),
}

impl Clone for OutputDestination {
    fn clone(&self) -> Self {
        match self {
            Self::Stdout => Self::Stdout,
            Self::File(f) => {
                // As far as I can tell, this can only fail if the OS refuses to duplicate the
                // underlying FD (e.g. you've hit the ulimit). So assuming this will succeed seems
                // more or less on the same level as assuming a memory allocation will succeed.
                Self::File(f.try_clone().expect("cannot clone file"))
            }
        }
    }
}

/// A `RunSchedule` keeps track of which action thunks are associated
/// with which file, so they can be run in sequence.
struct RunSchedule<'a> {
    pub file_path: &'a Path,
    pub preamble_values: Vec<Value>,
    pub thunk_range: Range<usize>,
}

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
    output_destination: OutputDestination,
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
            output_destination: OutputDestination::Stdout,
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

    /// Load run files from pre-created objects.
    pub fn with_runfiles(mut self, run_files: Vec<RunFile>) -> anyhow::Result<Self> {
        self.run_files = run_files;
        Ok(self)
    }

    /// Load run files from their paths. This is not additive. The list of run files is replaced
    /// by the `Vec` given to this method.
    pub fn with_runfile_paths(self, run_paths: Vec<PathBuf>) -> anyhow::Result<Self> {
        self.with_runfiles(
            run_paths
                .iter()
                .map(RunFile::from_file)
                .collect::<Result<Vec<_>, _>>()?,
        )
    }

    /// Set the output destination to a file specified by path.
    pub fn with_output_path(mut self, path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let file = fs::File::create(path.as_ref())?;
        self.output_destination = OutputDestination::File(file);
        Ok(self)
    }

    /// Set the output destination to a file specified directly.
    pub fn with_output_file(mut self, file: fs::File) -> Self {
        self.output_destination = OutputDestination::File(file);
        self
    }

    /// Set the output destination to stdout.
    pub fn with_output_stdout(mut self) -> Self {
        self.output_destination = OutputDestination::Stdout;
        self
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
        tracing::debug!("Loading DefaultEngine crypto engine");
        Ok(DefaultEngine::new(&secret_key, rng))
    }

    /// Utility function for loading the policy and injecting the run file
    /// action thunks and global values into it. Returns a `Vec` of
    /// [`RunSchedule`]s.
    fn load_and_compile_policy<'a, CE, KS>(
        &self,
        run_files: &'a [RunFile], // explicit argument so as to not borrow self
        crypto_engine: &mut CE,
        keystore: &mut KS,
    ) -> anyhow::Result<(Machine, Vec<RunSchedule<'a>>)>
    where
        CE: Engine,
        KS: KeyStore,
    {
        let mut policy_doc = self.policy.to_string();
        // Append generated policy thunks to the policy doc
        policy_doc.push_str("\n```policy\n");
        let mut thunk_counter = 0usize;
        tracing::debug!("Generating Policy Thunks");
        let thunk_schedule: Result<Vec<_>, RunFileError> = run_files
            .iter()
            .map(|run_file| {
                let preamble_vars = run_file.get_preamble_values(crypto_engine, keystore)?;
                // Prepare the action argument signatures
                let action_args: String = preamble_vars
                    .iter()
                    .map(|(i, v)| format!("{i} {}, ", v.type_name().to_lowercase()))
                    .collect();
                let thunk_start = thunk_counter;
                for policy_runnable in &run_file.do_things {
                    // Each thunk calls another action or publishes a command,
                    let action_body = match policy_runnable {
                        PolicyRunnable::Action(call) => format!("action {call}"),
                        PolicyRunnable::Command(cmd) => format!("publish {cmd}"),
                    };
                    policy_doc.push_str(&format!(
                        r#"
        action policy_runner_thunk_{thunk_counter}({action_args}) {{
            {action_body}
        }}"#
                    ));
                    // and they are sequentially numbered.
                    thunk_counter = thunk_counter
                        .checked_add(1)
                        .expect("should not overflow thunk counter");
                }
                // Each "schedule" captures a range of thunks for a given run file.
                Ok(RunSchedule {
                    file_path: &run_file.file_path,
                    preamble_values: preamble_vars.into_iter().map(|(_, v)| v).collect(),
                    thunk_range: thunk_start..thunk_counter,
                })
            })
            .collect();
        let thunk_schedule = thunk_schedule?;
        policy_doc.push_str("\n```\n");

        tracing::debug!("Compiling Policy");
        let ast = parse_policy_document(&policy_doc)
            .inspect_err(|e| println!("{e}"))
            .context("unable to parse policy document")?;
        let module = Compiler::new(&ast)
            .ffi_modules(&FFI_MODULES)
            .compile()
            .context("should be able to compile policy")?;
        tracing::debug!("Policy compiled successfully");
        if self.validator {
            tracing::debug!("Running validator");
            if validate(&module) {
                return Err(anyhow::anyhow!("Could not validate module"));
            }
            tracing::debug!("Policy validated");
        }
        tracing::debug!("Creating VM");
        let machine = Machine::from_module(module).context("should be able to create VM")?;

        Ok((machine, thunk_schedule))
    }

    // This function mainly serves as a boundary for the main run file and
    // policy execution logic, so that its errors can be handled
    // independently of things like logging or setting up and tearing down
    // the working directory.
    fn inner_logic(&mut self) -> anyhow::Result<()> {
        // Load or generate policy prerequisites: Keystore, RNG, Device ID, and Crypto Engine
        let mut keystore = self.working_directory.load_keystore()?;
        tracing::debug!("Keystore loaded");
        let rng = if self.deterministic_rng {
            tracing::debug!("Using deterministic RNG");
            SwitchableRng::new_deterministic()
        } else {
            tracing::debug!("Using default RNG");
            SwitchableRng::new_default()
        };
        let device_id = self.working_directory.load_device_id(&rng)?;
        let mut crypto_engine = self.load_crypto_engine(rng)?;
        tracing::debug!("Crypto Engine loaded");

        // Compile the policy with additional globals provided by the run files
        let (machine, run_schedules) =
            self.load_and_compile_policy(&self.run_files, &mut crypto_engine, &mut keystore)?;
        tracing::debug!("Policy VM loaded");
        let vm_policy = create_vmpolicy(machine, crypto_engine, keystore, device_id)?;
        tracing::debug!("Policy Runtime created");

        let mut provider = self.working_directory.get_storage_provider()?;
        tracing::debug!("Storage provider loaded");
        let out_stream: &mut dyn Write = match &mut self.output_destination {
            OutputDestination::Stdout => &mut std::io::stdout(),
            OutputDestination::File(w) => w,
        };
        let mut sink = WriterSink::new(out_stream);

        // To Claude and everyone else who didn't live through the 90s - this is a reference to
        // the game SimCity 2000 (as well as many later Maxis games). They would use this phrase
        // in their loading screens. It was a nonsense phrase that they threw in just for fun.
        tracing::debug!("Reticulating splines");

        let (mut perspective, storage) = match self.working_directory.get_graph_id()? {
            Some(graph_id) => {
                let storage = provider.get_storage(graph_id)?;
                let head = storage.get_head()?;
                tracing::debug!("Using existing graph");
                (storage.get_linear_perspective(head)?, Some(storage))
            }
            None => {
                tracing::debug!("creating new graph");
                (provider.new_perspective(PolicyId::new(0)), None)
            }
        };

        for schedule in run_schedules {
            if self.marker {
                sink.mark(schedule.file_path)?;
            }
            tracing::debug!("Running {}", schedule.file_path.display());
            for i in schedule.thunk_range {
                let action_ident = Identifier::try_from(format!("policy_runner_thunk_{i}"))
                    .with_context(|| format!("thunk {i} should be defined"))?;

                let action = VmAction {
                    name: action_ident,
                    args: Cow::Borrowed(&schedule.preamble_values),
                };
                sink.begin();
                tracing::debug!("Calling run schedule item {i}");
                vm_policy
                    .call_action(
                        action,
                        &mut perspective,
                        &mut sink,
                        ActionPlacement::OnGraph,
                    )
                    .inspect_err(|e| {
                        tracing::error!("VM Policy Error: {e}");
                        sink.rollback();
                    })?;
                sink.commit();
            }
        }

        if let Some(storage) = storage {
            // Storage already exists, commit
            let segment = storage.write(perspective)?;
            storage.commit(segment)?;
        } else {
            // Storage did not already exist, create a new one and save our Graph ID
            let (new_graph_id, _) = provider.new_storage(perspective)?;
            self.working_directory.save_graph_id(new_graph_id)?;
        }
        tracing::debug!("Committed storage");
        Ok(())
    }

    /// Run the configured policy runner. Returns the working directory configuration.
    ///
    /// Note: This consumes `self` not because it really needs to - all internal state is
    /// unchanged during execution. It serves as a brake against concurrent runs
    /// manipulating the same underlying filesystem state (although since it's cloneable, you could
    /// still do so if you tried).
    pub fn run(mut self) -> anyhow::Result<WorkingDirectory> {
        if self.working_directory.is_temporary {
            tracing::info!(
                "Using temporary directory `{}`",
                self.working_directory.base_dir().display()
            );
        }
        self.working_directory
            .make_dirs()
            .context("Could not set up working directory")?;

        let inner_err = self
            .inner_logic()
            .inspect_err(|e| tracing::error!("Execution failed: {e}"))
            .err();

        if self.working_directory.is_temporary {
            // Clean up temporary working directory
            tracing::debug!(
                "Removing temporary working directory {}",
                self.working_directory.base_dir().display()
            );
            self.working_directory.delete()?;
        }

        if let Some(err) = inner_err {
            Err(err)
        } else {
            Ok(self.working_directory)
        }
    }
}
