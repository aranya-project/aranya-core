use std::{
    borrow::Cow,
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Context as _, anyhow};
use aranya_crypto::{
    DeviceId, Rng,
    dangerous::spideroak_crypto::{csprng::rand::random, import::Import, keys::SecretKey},
    default::DefaultEngine,
    keystore::fs_keystore,
};
use aranya_policy_vm::Identifier;
use aranya_runtime::{
    ActionPlacement, GraphId, Policy as _, PolicyId, Sink as _, Storage as _, StorageProvider as _,
    VmAction, VmPolicy,
    linear::{LinearStorageProvider, libc::FileManager},
};
use clap::Parser;

use aranya_policy_runner::{
    EchoSink, RunSchedule, create_vmpolicy, get_runfile_preamble_values, load_policy, parse_runfile,
};

#[derive(Parser, Debug)]
struct Args {
    /// The working directory for all data stored
    #[arg(long, short)]
    working_directory: Option<String>,
    /// Use a deterministic RNG with the given seed (NOT YET IMPLEMENTED)
    #[arg(long, short)]
    deterministic_rng: Option<String>,
    /// Add a marker to the output when execution moves to a new run file
    #[arg(long)]
    marker: bool,
    /// Suppress trace output and other diagnostics
    #[arg(long, short)]
    quiet: bool,
    /// Run the validator on the policy compilation (NOT YET IMPLEMENTED)
    #[arg(long)]
    validator: bool,
    /// The policy file to load
    policy: String,
    /// The run files to load
    runs: Vec<String>,
}

/// WorkingDirectory manages derived paths from a base working directory.
struct WorkingDirectory(PathBuf);

impl WorkingDirectory {
    fn new(path: &str) -> Self {
        Self(Path::new(path).to_path_buf())
    }

    /// The path to the keystore
    fn keystore(&self) -> PathBuf {
        self.0.join("keystore")
    }

    /// The path to the keystore's secret root key
    fn secret_key(&self) -> PathBuf {
        self.keystore().join("secret_key")
    }

    /// The path to graph storage
    fn graph(&self) -> PathBuf {
        self.0.join("graph")
    }

    /// The path to the stored Graph ID
    fn graph_id(&self) -> PathBuf {
        self.0.join("graph_id")
    }

    /// The path to the serialized Device ID
    fn device_id(&self) -> PathBuf {
        self.0.join("device_id")
    }

    /// Utility function to create all necessary directories
    fn make_dirs(&self) -> Result<(), io::Error> {
        for d in [self.0.as_path(), &self.keystore(), &self.graph()] {
            fs::create_dir_all(d)?;
        }
        Ok(())
    }
}

/// Loads a key from a file or generates and writes a new one.
fn load_secret_key<K: SecretKey>(working_directory: &WorkingDirectory) -> anyhow::Result<K> {
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
            let key = K::random(&mut Rng);
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

// Loads the crypto engine using the secret key
fn load_crypto_engine(working_directory: &WorkingDirectory) -> anyhow::Result<DefaultEngine> {
    let secret_key = load_secret_key(working_directory)?;
    Ok(DefaultEngine::new(&secret_key, Rng))
}

// Loads the Device ID from disk or generates a new one
fn load_device_id(working_directory: &WorkingDirectory) -> anyhow::Result<DeviceId> {
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
            let rng_device_id = random();
            let device_id = DeviceId::from_bytes(rng_device_id);
            fs::write(&id_path, rng_device_id)?;
            tracing::debug!("Device ID saved to '{}'", id_path.display());
            Ok(device_id)
        }
        Err(err) => Err(err).context("unable to read Device ID"),
    }
}

fn get_storage_provider(
    working_directory: &WorkingDirectory,
) -> anyhow::Result<LinearStorageProvider<FileManager>> {
    let storage_path = working_directory.graph();
    let fm = FileManager::new(&storage_path)?;
    Ok(LinearStorageProvider::new(fm))
}

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

fn execute_schedule(
    vmpolicy: VmPolicy<DefaultEngine>,
    working_directory: &WorkingDirectory,
    run_schedules: Vec<RunSchedule>,
    marker: bool,
) -> anyhow::Result<()> {
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
        for i in schedule.thunk_ids {
            let action_ident = Identifier::try_from(format!("policy_runner_thunk_{i}"))
                .context("thunk {i} should be defined")?;

            let action = VmAction {
                name: action_ident,
                args: Cow::Borrowed(&[]),
            };
            sink.begin();
            vmpolicy
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
        let segment = storage.write(perspective)?;
        storage.commit(segment)?;
    } else {
        let (new_graph_id, _) = provider.new_storage(perspective)?;
        save_graph_id(working_directory, new_graph_id)?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if !args.quiet {
        tracing_subscriber::fmt::init();
    }

    let working_directory = WorkingDirectory::new(args.working_directory.as_deref().unwrap_or("."));
    working_directory.make_dirs()?;
    let keystore = fs_keystore::Store::open(working_directory.keystore())?;
    let device_id = load_device_id(&working_directory)?;

    let eng = Mutex::new(load_crypto_engine(&working_directory)?);
    let runfiles: Vec<_> = args
        .runs
        .into_iter()
        .map(|rf| parse_runfile(rf).expect("could not parse run file"))
        .collect();

    let mut globals = Vec::new();
    for rf in &runfiles {
        let values = get_runfile_preamble_values(rf, &eng, keystore.try_clone()?)?;
        for (name, value) in values {
            tracing::debug!("defined {name} = {value}");
            globals.push((name, value));
        }
    }

    let (machine, run_schedule) = load_policy(&args.policy, globals, runfiles)?;

    let crypto_engine = load_crypto_engine(&working_directory)?;
    let vm_policy = create_vmpolicy(machine, crypto_engine, keystore, device_id)?;

    execute_schedule(vm_policy, &working_directory, run_schedule, args.marker)?;

    Ok(())
}
