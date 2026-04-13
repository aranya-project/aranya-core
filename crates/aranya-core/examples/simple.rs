//! Minimal aranya-core usage with the built-in file-backed storage.
//!
//! Uses the `FileManager` from `aranya_runtime` (the same storage the real
//! aranya daemon uses), so there is zero custom storage code. This is the
//! simplest path to a working `Client`.

use std::fs;

use anyhow::{Context as _, Result};
use aranya_core::{
    Client, Command as _, GraphId, Sink, TraversalBuffer, TraversalBuffers,
    policy::{FfiCallable, VmEffect, VmPolicy, VmPolicyStore},
    storage::{FileManager, LinearStorageProvider},
    sync::{MAX_SYNC_MESSAGE_SIZE, PeerCache, SyncRequester, SyncResponder, SyncType},
};
use aranya_crypto::{
    DeviceId, EncryptionKey, IdentityKey, Rng, SigningKey,
    default::{DefaultCipherSuite, DefaultEngine},
    keystore::{KeyStoreExt as _, memstore::MemStore},
};
use aranya_crypto_ffi::Ffi as CryptoFfi;
use aranya_device_ffi::FfiDevice as DeviceFfi;
use aranya_envelope_ffi::Ffi as EnvelopeFfi;
use aranya_idam_ffi::Ffi as IdamFfi;
use aranya_perspective_ffi::FfiPerspective as PerspectiveFfi;
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{Machine, Struct, Value, ffi::FfiModule as _, ident};

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

type CE = DefaultEngine<Rng, DefaultCipherSuite>;
type CS = DefaultCipherSuite;

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
            println!("  [{label}] Effect: {eff}");
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
struct DeviceKeys {
    engine: CE,
    store: MemStore,
    device_id: DeviceId,
    sign_id: <SigningKey<CS> as aranya_crypto::Identified>::Id,
    enc_id: <EncryptionKey<CS> as aranya_crypto::Identified>::Id,
    ident_pk_bytes: Vec<u8>,
    sign_pk_bytes: Vec<u8>,
    enc_pk_bytes: Vec<u8>,
}

fn create_device() -> Result<DeviceKeys> {
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
    let ident_pk_bytes = postcard::to_allocvec(&ident_pk)?;
    let sign_pk_bytes = postcard::to_allocvec(&sign_pk)?;
    let enc_pk_bytes = postcard::to_allocvec(&enc_pk)?;

    Ok(DeviceKeys {
        engine: eng,
        store,
        device_id,
        sign_id,
        enc_id,
        ident_pk_bytes,
        sign_pk_bytes,
        enc_pk_bytes,
    })
}

// ---------------------------------------------------------------------------
// Policy Compilation
// ---------------------------------------------------------------------------

fn compile_policy(eng: CE, store: MemStore, device_id: DeviceId) -> Result<VmPolicyStore<CE>> {
    let ast = parse_policy_document(include_str!("policy.md"))
        .context("unable to parse policy document")?;

    let module = Compiler::new(&ast)
        .ffi_modules(&[
            CryptoFfi::<MemStore>::SCHEMA,
            DeviceFfi::SCHEMA,
            EnvelopeFfi::SCHEMA,
            IdamFfi::<MemStore>::SCHEMA,
            PerspectiveFfi::SCHEMA,
        ])
        .compile()
        .context("unable to compile policy")?;

    let machine = Machine::from_module(module).context("unable to create machine")?;

    let ffis: Vec<Box<dyn FfiCallable<CE> + Send + 'static>> = vec![
        Box::from(CryptoFfi::new(store.clone())),
        Box::from(DeviceFfi::new(device_id)),
        Box::from(EnvelopeFfi),
        Box::from(IdamFfi::new(store)),
        Box::from(PerspectiveFfi),
    ];

    let policy = VmPolicy::new(machine, eng, ffis).context("unable to create VmPolicy")?;
    Ok(VmPolicyStore::new(policy))
}

// ---------------------------------------------------------------------------
// Helper — Build PublicKeys Value
// ---------------------------------------------------------------------------

fn make_public_keys(ident: &[u8], sign: &[u8], enc: &[u8]) -> Value {
    Value::Struct(Struct::new(
        ident!("PublicKeys"),
        [
            (ident!("ident_key"), Value::Bytes(ident.to_vec())),
            (ident!("sign_key"), Value::Bytes(sign.to_vec())),
            (ident!("enc_key"), Value::Bytes(enc.to_vec())),
        ],
    ))
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
    source: &mut Client<CE, FileManager>,
    dest: &mut Client<CE, FileManager>,
    sink: &mut PrintSink,
) -> Result<()> {
    let mut request_cache = PeerCache::default();
    let mut response_cache = PeerCache::default();
    let mut buffer = TraversalBuffer::default();

    let mut syncer = SyncRequester::new(graph_id, Rng);

    let mut trx = dest.transaction(graph_id);

    let mut buf = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let (len, _sent) = syncer
        .poll(&mut buf, dest.provider(), &mut request_cache, &mut buffer)
        .context("sync poll failed")?;

    let mut target = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let resp_len = dispatch(
        &buf[..len],
        &mut target,
        source.provider(),
        &mut response_cache,
    )
    .context("sync dispatch failed")?;

    if resp_len > 0
        && let Some(cmds) = syncer
            .receive(&target[..resp_len])
            .context("sync receive failed")?
    {
        let _received = dest
            .add_commands(&mut trx, sink, &cmds, &mut buffer)
            .context("add_commands failed")?;
        dest.commit(trx, sink, &mut buffer)
            .context("commit failed")?;
        dest.update_heads(
            graph_id,
            cmds.iter().filter_map(|cmd| cmd.address().ok()),
            &mut request_cache,
            &mut buffer,
        )
        .context("update_heads failed")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// main() — Full Two-Device Demo (file-backed storage)
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let storage_root = std::env::temp_dir().join("aranya-core-simple");

    // Create per-device storage directories.
    let dir_a = storage_root.join("device_a");
    let dir_b = storage_root.join("device_b");
    fs::create_dir_all(&dir_a).context("create device_a storage dir")?;
    fs::create_dir_all(&dir_b).context("create device_b storage dir")?;

    let provider_a = LinearStorageProvider::new(
        FileManager::new(&dir_a).context("create FileManager for device A")?,
    );
    let provider_b = LinearStorageProvider::new(
        FileManager::new(&dir_b).context("create FileManager for device B")?,
    );

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
    let mut cs_a = Client::new(policy_store_a, provider_a);
    let mut sink = PrintSink::new();

    // Step 4: Create graph with init action
    println!("\nStep 4: Creating graph (init)...");
    let owner_keys = make_public_keys(
        &dev_a.ident_pk_bytes,
        &dev_a.sign_pk_bytes,
        &dev_a.enc_pk_bytes,
    );
    let graph_id = cs_a
        .new_graph(
            &[0u8],
            aranya_runtime::vm_action!(init(owner_keys, 42)),
            &mut sink,
        )
        .context("new_graph failed")?;
    sink.drain_and_print("Device A / init");
    println!("  Graph ID: {graph_id}");

    // Step 5: Add Device B
    println!("\n== Device A: Add Device B ==");
    println!("\nStep 5: Adding Device B...");
    let device_keys_b = make_public_keys(
        &dev_b.ident_pk_bytes,
        &dev_b.sign_pk_bytes,
        &dev_b.enc_pk_bytes,
    );
    cs_a.action(
        graph_id,
        &mut sink,
        aranya_runtime::vm_action!(add_device(device_keys_b)),
    )
    .context("add_device failed")?;
    sink.drain_and_print("Device A / add_device");

    // Step 6: Set counter
    println!("\n== Device A: Application Commands ==");
    println!("\nStep 6: Setting counter(1) = 100...");
    cs_a.action(
        graph_id,
        &mut sink,
        aranya_runtime::vm_action!(set_counter(1, 100)),
    )
    .context("set_counter failed")?;
    sink.drain_and_print("Device A / set_counter");

    // Step 7: Increment counter
    println!("\nStep 7: Incrementing counter(1) by 50...");
    cs_a.action(
        graph_id,
        &mut sink,
        aranya_runtime::vm_action!(increment_counter(1, 50)),
    )
    .context("increment_counter failed")?;
    sink.drain_and_print("Device A / increment_counter");

    // Step 8: Compile policy for Device B, create Client B
    println!("\n== Sync: A -> B ==");
    println!("\nStep 8: Compiling policy for Device B...");
    let policy_store_b = compile_policy(dev_b.engine, dev_b.store, dev_b.device_id)?;
    let mut cs_b = Client::new(policy_store_b, provider_b);

    // Step 9: Sync graph from A to B
    println!("\nStep 9: Syncing A -> B...");
    sync_graphs(graph_id, &mut cs_a, &mut cs_b, &mut sink)?;
    sink.drain_and_print("Device B / sync from A");

    // Step 10: Device B runs its own action
    println!("\n== Device B: Own Action ==");
    println!("\nStep 10: Device B incrementing counter(1) by 25...");
    cs_b.action(
        graph_id,
        &mut sink,
        aranya_runtime::vm_action!(increment_counter(1, 25)),
    )
    .context("Device B increment_counter failed")?;
    sink.drain_and_print("Device B / increment_counter");

    // Step 11: Sync B -> A
    println!("\n== Sync: B -> A ==");
    println!("\nStep 11: Syncing B -> A...");
    sync_graphs(graph_id, &mut cs_b, &mut cs_a, &mut sink)?;
    sink.drain_and_print("Device A / sync from B");

    println!("\n== Done! ==");

    // Clean up temp storage.
    let _ = fs::remove_dir_all(&storage_root);

    Ok(())
}
