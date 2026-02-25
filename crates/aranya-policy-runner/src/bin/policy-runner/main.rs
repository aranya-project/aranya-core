use std::{
    borrow::Cow,
    env::temp_dir,
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, anyhow};
use aranya_crypto::{
    BaseId, Csprng, DeviceId,
    dangerous::spideroak_crypto::{csprng::rand::random, import::Import, keys::SecretKey},
    default::DefaultEngine,
    keystore::fs_keystore,
};
use aranya_policy_runner::{
    EchoSink, RunFile, SwitchableRng, create_vmpolicy, load_and_compile_policy,
};
use aranya_policy_vm::Identifier;
use aranya_runtime::{
    ActionPlacement, GraphId, Policy as _, PolicyId, Sink as _, Storage as _, StorageProvider as _,
    VmAction,
    linear::{LinearStorageProvider, libc::FileManager},
};
use clap::Parser;

/// The Aranya Policy Runner runs sequences of actions on policy files
#[derive(Parser, Debug)]
struct Args {
    /// The working directory for all data stored. If unspecified, a temporary directory is used.
    #[arg(long, short)]
    working_directory: Option<PathBuf>,
    /// If no working directory is specified, keep the temporary working
    /// directory
    #[arg(long)]
    keep_temporary_working_directory: bool,
    /// Use a deterministic RNG
    #[arg(long)]
    deterministic_rng: bool,
    /// Add a marker to the output when execution moves to a new run file
    #[arg(long)]
    marker: bool,
    /// Suppress trace output and other diagnostics
    #[arg(long, short)]
    quiet: bool,
    /// Run the validator on the policy compilation
    #[arg(long)]
    validator: bool,
    /// The policy file
    policy: PathBuf,
    /// The run files
    runs: Vec<PathBuf>,
}

/// WorkingDirectory manages derived paths from a base working directory
/// and keeps track of whether the path is temporary.
struct WorkingDirectory {
    // The base working directory
    pub base: PathBuf,
    // True if the base working directory is temporary
    pub is_temporary: bool,
}

impl WorkingDirectory {
    /// Create a non-temporary `WorkingDirectory` from a path.
    fn new(path: impl AsRef<Path>) -> Self {
        Self {
            base: path.as_ref().to_path_buf(),
            is_temporary: false,
        }
    }

    /// Create a temporary `WorkingDirectory` from a randomly generated
    /// path under the system temporary directory.
    fn new_temporary() -> Self {
        let dir_id = BaseId::from_bytes(random());
        Self {
            base: temp_dir().join(format!("policy-runner-{dir_id}")),
            is_temporary: true,
        }
    }

    /// Delete the working directory and all of its contents.
    fn delete(&self) -> Result<(), io::Error> {
        fs::remove_dir_all(&self.base)
    }

    /// The path to the keystore directory
    fn keystore_dir(&self) -> PathBuf {
        self.base.join("keystore")
    }

    /// The path to the keystore's secret root key
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
    fn make_dirs(&self) -> anyhow::Result<()> {
        for d in [&self.keystore_dir(), &self.graph_dir()] {
            fs::create_dir_all(d)?;
        }
        Ok(())
    }
}

/// Loads the crypto engine secret key from a file or generates and
/// writes a new one.
fn load_secret_key<K: SecretKey, R: Csprng>(
    working_directory: &WorkingDirectory,
    rng: &R,
) -> anyhow::Result<K> {
    let key_path = working_directory.secret_key();

    match fs::read(&key_path) {
        Ok(buf) => {
            tracing::debug!(
                "crypto engine secret key loaded from '{}'",
                key_path.display()
            );
            let key = Import::import(buf.as_slice()).context("unable to import key from file")?;
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

/// Loads the crypto engine using the secret key
fn load_crypto_engine<R: Csprng>(
    working_directory: &WorkingDirectory,
    rng: R,
) -> anyhow::Result<DefaultEngine<R>> {
    let secret_key = load_secret_key(working_directory, &rng)?;
    Ok(DefaultEngine::new(&secret_key, rng))
}

/// Loads the Device ID from disk or generates a new one
fn load_device_id(
    working_directory: &WorkingDirectory,
    rng: &impl Csprng,
) -> anyhow::Result<DeviceId> {
    let id_path = working_directory.device_id();

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

/// Loads the file-based storage provider using its configured directory
fn get_storage_provider(
    working_directory: &WorkingDirectory,
) -> anyhow::Result<LinearStorageProvider<FileManager>> {
    let storage_path = working_directory.graph_dir();
    let fm = FileManager::new(&storage_path)?;
    Ok(LinearStorageProvider::new(fm))
}

/// Loads the graph ID from the filesystem, if it exists. If it doesn't
/// exist, returns `Ok(None)`.
fn get_graph_id(working_directory: &WorkingDirectory) -> anyhow::Result<Option<GraphId>> {
    let id_path = working_directory.graph_id();

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

fn save_graph_id(working_directory: &WorkingDirectory, graph_id: GraphId) -> anyhow::Result<()> {
    let id_path = working_directory.graph_id();
    fs::write(&id_path, graph_id)?;
    tracing::debug!("Graph ID saved to '{}'", id_path.display());
    Ok(())
}

// This function mainly serves as a boundary for the main run file and
// policy execution logic, so that its errors can be handled
// independently of things like logging or setting up and tearing down
// the working directory.
fn inner_logic(
    working_directory: &WorkingDirectory,
    run_paths: &[PathBuf],
    policy: &Path,
    deterministic_rng: bool,
    marker: bool,
    validator: bool,
) -> anyhow::Result<()> {
    // Parse run files
    let run_files = run_paths
        .iter()
        .map(RunFile::from_file)
        .collect::<Result<Vec<_>, _>>()?;

    // Load or generate policy prerequisites: Keystore, Device ID, and Crypto Engine
    let mut keystore = fs_keystore::Store::open(working_directory.keystore_dir())?;
    let rng = if deterministic_rng {
        SwitchableRng::new_deterministic()
    } else {
        SwitchableRng::new_default()
    };
    let device_id = load_device_id(working_directory, &rng)?;
    let mut crypto_engine = load_crypto_engine(working_directory, rng)?;

    // Iterate over all run files, execute their preambles, and collect
    // those values into `runfile_globals`.
    // This two-stage iter/collect looks a little weird, but the first
    // stage handles the `Result`s created by the map closure and the
    // second one flattens the `Vec`s created by
    // `get_preamble_values()`.
    let runfile_globals = run_files
        .iter()
        .map(|rf| rf.get_preamble_values(&mut crypto_engine, &mut keystore))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    // Compile the policy with additional globals provided by the run files
    let (machine, run_schedules) =
        load_and_compile_policy(policy, runfile_globals, run_files, validator)?;
    let vm_policy = create_vmpolicy(machine, crypto_engine, keystore, device_id)?;

    let mut provider = get_storage_provider(working_directory)?;
    let mut sink = EchoSink::default();

    let (mut perspective, storage) = match get_graph_id(working_directory)? {
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
        if marker {
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
        storage.commit(segment)?;
    } else {
        // Storage did not already exist, create a new one and save our Graph ID
        let (new_graph_id, _) = provider.new_storage(perspective)?;
        save_graph_id(working_directory, new_graph_id)?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.runs.is_empty() {
        return Err(anyhow!("Please specify one or more run files"));
    }

    if !args.quiet {
        tracing_subscriber::fmt::init();
    }

    // Set up the working directory
    let working_directory = args
        .working_directory
        .as_ref()
        .map(WorkingDirectory::new)
        .unwrap_or_else(WorkingDirectory::new_temporary);
    if working_directory.is_temporary {
        tracing::info!(
            "Using temporary directory `{}`",
            working_directory.base.display()
        );
    }
    working_directory
        .make_dirs()
        .context("Could not create working directory")?;

    // Intentionally not using `?` here to print the error and continue on to temp dir cleanup
    inner_logic(
        &working_directory,
        &args.runs,
        &args.policy,
        args.deterministic_rng,
        args.marker,
        args.validator,
    )
    .inspect_err(|e| eprintln!("Execution failed: {e}"))
    .ok();

    if working_directory.is_temporary {
        if args.keep_temporary_working_directory {
            tracing::info!(
                "Keeping temporary working directory `{}`",
                working_directory.base.display()
            );
        } else {
            // Clean up temporary working directory
            tracing::debug!(
                "Removing temporary working directory {}",
                working_directory.base.display()
            );
            working_directory.delete()?;
        }
    }

    Ok(())
}
