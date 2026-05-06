//! End-to-end aranya-core example using ifgen-typed actions and effects.
//!
//! This crate exercises the public surface of `aranya-core`. The runtime
//! types come from `aranya-core` directly; typed actions and effects come
//! from `aranya-core::ifgen` via build-time codegen against `policy.md`.
//! The FFI/compiler/VM crates are needed for one-time policy compilation
//! and FFI module wiring.

use std::fs;

use anyhow::{Context as _, Result};
use aranya_core::{
    ClientState, Command as _, GraphId, RuntimeBuffers, Sink, TraversalBuffer, TraversalBuffers,
    crypto::{DefaultCipherSuite, DefaultEngine, Rng},
    ifgen::Actionable as _,
    keystore::{
        DeviceId, EncryptionKey, Identified, IdentityKey, KeyStoreExt as _, MemStore, SigningKey,
    },
    policy::{FfiCallable, VmEffect, VmPolicy, VmPolicyStore},
    storage::{FileManager, LibcSpill, LinearStorageProvider},
    sync::{MAX_SYNC_MESSAGE_SIZE, PeerCache, SyncRequester, SyncResponder, SyncType},
};
use aranya_crypto_ffi::Ffi as CryptoFfi;
use aranya_device_ffi::FfiDevice as DeviceFfi;
use aranya_envelope_ffi::Ffi as EnvelopeFfi;
use aranya_idam_ffi::Ffi as IdamFfi;
use aranya_perspective_ffi::FfiPerspective as PerspectiveFfi;
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{Machine, ffi::FfiModule as _};

#[allow(dead_code)]
mod policy;

use policy::{Effect, PublicKeys, add_device, increment_counter, init, set_counter};

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

type CS = DefaultCipherSuite;
type CE = DefaultEngine<Rng, CS>;

struct PrintSink {
    effects: Vec<VmEffect>,
}

impl PrintSink {
    fn new() -> Self {
        Self {
            effects: Vec::new(),
        }
    }

    fn drain_and_print(&mut self, label: &str) {
        for eff in self.effects.drain(..) {
            match Effect::try_from(eff) {
                Ok(parsed) => println!("  [{label}] Effect: {parsed:?}"),
                Err(err) => println!("  [{label}] Effect parse failed: {err}"),
            }
        }
    }
}

impl Sink<VmEffect> for PrintSink {
    fn begin(&mut self) {}

    fn consume(&mut self, effect: VmEffect) {
        self.effects.push(effect);
    }

    fn rollback(&mut self) {}

    fn commit(&mut self) {}
}

// ---------------------------------------------------------------------------
// Device Setup
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct Device {
    engine: CE,
    store: MemStore,
    device_id: DeviceId,
    sign_id: <SigningKey<CS> as Identified>::Id,
    enc_id: <EncryptionKey<CS> as Identified>::Id,
    public_keys: PublicKeys,
}

fn create_device() -> Result<Device> {
    let (eng, _) = DefaultEngine::<_, DefaultCipherSuite>::from_entropy(Rng);
    let mut store = MemStore::new();

    // Generate keys
    let device_id = store
        .insert_key(&eng, IdentityKey::<CS>::new(Rng))
        .context("insert IdentityKey")?;
    let sign_id = store
        .insert_key(&eng, SigningKey::<CS>::new(Rng))
        .context("insert SigningKey")?;
    let enc_id = store
        .insert_key(&eng, EncryptionKey::<CS>::new(Rng))
        .context("insert EncryptionKey")?;

    // Extract public keys
    let ident_pk = store
        .get_key::<_, IdentityKey<CS>>(&eng, device_id)
        .context("get IdentityKey")?
        .context("IdentityKey not found")?
        .public()?;
    let sign_pk = store
        .get_key::<_, SigningKey<CS>>(&eng, sign_id)
        .context("get SigningKey")?
        .context("SigningKey not found")?
        .public()?;
    let enc_pk = store
        .get_key::<_, EncryptionKey<CS>>(&eng, enc_id)
        .context("get EncryptionKey")?
        .context("EncryptionKey not found")?
        .public()?;

    // Serialize public keys
    let public_keys = PublicKeys {
        ident_key: postcard::to_allocvec(&ident_pk)?,
        sign_key: postcard::to_allocvec(&sign_pk)?,
        enc_key: postcard::to_allocvec(&enc_pk)?,
    };

    Ok(Device {
        engine: eng,
        store,
        device_id,
        sign_id,
        enc_id,
        public_keys,
    })
}

// ---------------------------------------------------------------------------
// Policy Compilation
// ---------------------------------------------------------------------------

const POLICY_SOURCE: &str = include_str!("policy.md");

fn compile_policy(eng: CE, store: MemStore, device_id: DeviceId) -> Result<VmPolicyStore<CE>> {
    let ast = parse_policy_document(POLICY_SOURCE).context("parse policy document")?;
    let module = Compiler::new(&ast)
        .ffi_modules(&[
            CryptoFfi::<MemStore>::SCHEMA,
            DeviceFfi::SCHEMA,
            EnvelopeFfi::SCHEMA,
            IdamFfi::<MemStore>::SCHEMA,
            PerspectiveFfi::SCHEMA,
        ])
        .compile()
        .context("compile policy")?;

    let machine = Machine::from_module(module).context("create machine")?;

    let ffis: Vec<Box<dyn FfiCallable<CE> + Send + 'static>> = vec![
        Box::from(CryptoFfi::new(store.clone())),
        Box::from(DeviceFfi::new(device_id)),
        Box::from(EnvelopeFfi),
        Box::from(IdamFfi::new(store)),
        Box::from(PerspectiveFfi),
    ];

    let policy = VmPolicy::new(machine, eng, ffis).context("create VmPolicy")?;
    Ok(VmPolicyStore::new(policy))
}

// ---------------------------------------------------------------------------
// Sync Helpers
// ---------------------------------------------------------------------------

fn dispatch(
    data: &[u8],
    target: &mut [u8],
    provider: &mut LinearStorageProvider<FileManager>,
    response_cache: &mut PeerCache,
) -> Result<usize> {
    let sync_type: SyncType = postcard::from_bytes(data)?;
    let len = match sync_type {
        SyncType::Poll { request } => {
            let mut responder = SyncResponder::new();
            let mut buffers = TraversalBuffers::default();
            responder.receive(request)?;
            responder.poll(target, provider, response_cache, &mut buffers)?
        }
        _ => anyhow::bail!("unsupported sync type"),
    };
    Ok(len)
}

fn sync_graphs(
    graph_id: GraphId,
    source: &mut ClientState<VmPolicyStore<CE>, LinearStorageProvider<FileManager>>,
    dest: &mut ClientState<VmPolicyStore<CE>, LinearStorageProvider<FileManager>>,
    sink: &mut PrintSink,
    spill_dir: &std::path::Path,
) -> Result<()> {
    let mut request_cache = PeerCache::default();
    let mut response_cache = PeerCache::default();
    let mut traversal = TraversalBuffer::default();
    let mut rt_buffers = RuntimeBuffers::new();

    let mut syncer = SyncRequester::new(graph_id, Rng);
    let mut trx = dest.transaction(graph_id);

    let mut buf = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let (len, _sent) = syncer
        .poll(
            &mut buf,
            dest.provider(),
            &mut request_cache,
            &mut traversal,
        )
        .context("sync poll failed")?;

    let mut target = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let resp_len = dispatch(
        &buf[..len],
        &mut target,
        source.provider(),
        &mut response_cache,
    )
    .context("sync dispatch")?;

    if resp_len > 0
        && let Some(cmds) = syncer
            .receive(&target[..resp_len])
            .context("sync receive")?
    {
        let make_spill = || LibcSpill::new(spill_dir);
        let _received = dest
            .add_commands(&mut trx, sink, &cmds, &mut rt_buffers, make_spill)
            .context("add_commands failed")?;
        dest.commit(trx, sink, &mut rt_buffers, make_spill)
            .context("commit failed")?;
        dest.update_heads(
            graph_id,
            cmds.iter().filter_map(|cmd| cmd.address().ok()),
            &mut request_cache,
            &mut traversal,
        )
        .context("update_heads")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// main() — Full Two-Device Demo (file-backed storage)
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let storage_root = std::env::temp_dir().join("aranya-core-example");

    // Create per-device storage directories.
    let dir_a = storage_root.join("device_a");
    let dir_b = storage_root.join("device_b");
    fs::create_dir_all(&dir_a).context("create device_a storage dir")?;
    fs::create_dir_all(&dir_b).context("create device_b storage dir")?;

    let provider_a =
        LinearStorageProvider::new(FileManager::new(&dir_a).context("FileManager for device A")?);
    let provider_b =
        LinearStorageProvider::new(FileManager::new(&dir_b).context("FileManager for device B")?);

    println!("== Device Setup ==");

    // Step 1: Create Device A (owner)
    println!("\nStep 1: Creating Device A (owner)...");
    let dev_a = create_device()?;
    println!("  Device A ID: {}", dev_a.device_id);

    // Step 2: Create Device B (joiner)
    println!("\nStep 2: Creating Device B (joiner)...");
    let dev_b = create_device()?;
    println!("  Device B ID: {}", dev_b.device_id);

    // Step 3: Compile policy for Device A, create Client A
    println!("\n== Device A: Create Team ==");
    println!("\nStep 3: Compiling policy for Device A...");
    let policy_store_a = compile_policy(dev_a.engine, dev_a.store, dev_a.device_id)?;
    let mut cs_a = ClientState::new(policy_store_a, provider_a);
    let mut sink = PrintSink::new();

    // Step 4: Create graph with init action
    println!("\nStep 4: Creating graph (init)...");
    let graph_id = init(dev_a.public_keys, 42)
        .with_action(|action| cs_a.new_graph(&[0u8], action, &mut sink))
        .context("new_graph")?;
    sink.drain_and_print("Device A / init");
    println!("  Graph ID: {graph_id}");

    // Step 5: Add Device B
    println!("\n== Device A: Add Device B ==");
    println!("\nStep 5: Adding Device B...");
    add_device(dev_b.public_keys)
        .with_action(|action| cs_a.action(graph_id, &mut sink, action))
        .context("add_device")?;
    sink.drain_and_print("Device A / add_device");

    // Step 6: Set counter
    println!("\n== Device A: Application Commands ==");
    println!("\nStep 6: Setting counter(1) = 100...");
    set_counter(1, 100)
        .with_action(|action| cs_a.action(graph_id, &mut sink, action))
        .context("set_counter")?;
    sink.drain_and_print("Device A / set_counter");

    // Step 7: Increment counter
    println!("\nStep 7: Incrementing counter(1) by 50...");
    increment_counter(1, 50)
        .with_action(|action| cs_a.action(graph_id, &mut sink, action))
        .context("increment_counter")?;
    sink.drain_and_print("Device A / increment_counter");

    // Step 8: Compile policy for Device B, create Client B
    println!("\n== Sync: A -> B ==");
    println!("\nStep 8: Compiling policy for Device B...");
    let policy_store_b = compile_policy(dev_b.engine, dev_b.store, dev_b.device_id)?;
    let mut cs_b = ClientState::new(policy_store_b, provider_b);

    // Step 9: Sync graph from A to B
    println!("\nStep 9: Syncing A -> B...");
    sync_graphs(graph_id, &mut cs_a, &mut cs_b, &mut sink, &storage_root)?;
    sink.drain_and_print("Device B / sync from A");

    // Step 10: Device B runs its own action
    println!("\n== Device B: Own Action ==");
    println!("\nStep 10: Device B incrementing counter(1) by 25...");
    increment_counter(1, 25)
        .with_action(|action| cs_b.action(graph_id, &mut sink, action))
        .context("Device B increment_counter")?;
    sink.drain_and_print("Device B / increment_counter");

    // Step 11: Sync B -> A
    println!("\n== Sync: B -> A ==");
    println!("\nStep 11: Syncing B -> A...");
    sync_graphs(graph_id, &mut cs_b, &mut cs_a, &mut sink, &storage_root)?;
    sink.drain_and_print("Device A / sync from B");

    println!("\n== Done! ==");

    // Clean up temp storage.
    let _ = fs::remove_dir_all(&storage_root);
    Ok(())
}
