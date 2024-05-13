mod keygen;
extern crate alloc;
use alloc::vec::Vec;
use core::cell::RefCell;
use std::fs;

use crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    keystore::fs_keystore::Store,
    Rng, UserId,
};
use crypto_ffi::Ffi as CryptoFfi;
use device_ffi::FfiDevice as DeviceFfi;
use envelope_ffi::Ffi as EnvelopeFfi;
use idam_ffi::Ffi as IdamFfi;
use perspective_ffi::FfiPerspective as PerspectiveFfi;
use policy_compiler::Compiler;
use policy_lang::lang::parse_policy_document;
use policy_vm::{
    ffi::{FfiModule, ModuleSchema},
    Machine,
};
use runtime::{
    storage::memory::MemStorageProvider,
    vm_action, vm_effect,
    vm_policy::{testing::TestFfiEnvelope, VmPolicy},
    ClientState, FfiCallable,
};
use tempfile::tempdir;
use test_log::test;

use crate::{
    tests::keygen::{KeyBundle, PublicKeys},
    ClientFactory, Model, ModelClient, ModelEngine, ModelError, RuntimeModel,
};

/// Policy loaded from md file.
const FFI_POLICY: &str = include_str!("./ffi-policy.md");
const BASIC_POLICY: &str = include_str!("./basic-policy.md");

// NOTE: In actual usage, we would only have one client factory per
// implementation, I included two here simply for testing purposes.
struct BasicClientFactory {
    machine: Machine,
}

impl BasicClientFactory {
    fn new(policy_doc: &str) -> Result<Self, ModelError> {
        let ffi_schema: &[ModuleSchema<'static>] = &[TestFfiEnvelope::SCHEMA];

        let policy_ast = parse_policy_document(policy_doc)?;
        // Policy machine
        let module = Compiler::new(&policy_ast)
            .ffi_modules(ffi_schema)
            .compile()?;
        let machine = Machine::from_module(module).expect("should be able to load compiled module");

        Ok(Self { machine })
    }
}

// BasicClientFactory doesn't use signing keys, we add a empty struct to satisfy
// the requirement.
#[derive(Default)]
struct EmptyKeys;

impl ClientFactory for BasicClientFactory {
    type Engine = ModelEngine<DefaultEngine>;
    type StorageProvider = MemStorageProvider;
    type PublicKeys = EmptyKeys;

    fn create_client(&mut self) -> ModelClient<BasicClientFactory> {
        let (eng, _) = DefaultEngine::from_entropy(Rng);

        // Configure testing FFIs
        let ffis: Vec<Box<dyn FfiCallable<DefaultEngine> + Send + 'static>> =
            vec![Box::from(TestFfiEnvelope {
                user: UserId::random(&mut Rng),
            })];

        let policy = VmPolicy::new(self.machine.clone(), eng, ffis).expect("should create policy");
        let engine = ModelEngine::new(policy);
        let provider = MemStorageProvider::new();

        ModelClient {
            state: RefCell::new(ClientState::new(engine, provider)),
            public_keys: EmptyKeys,
        }
    }
}

struct FfiClientFactory {
    machine: Machine,
}

impl FfiClientFactory {
    fn new(policy_doc: &str) -> Result<Self, ModelError> {
        let ffi_schema: &[ModuleSchema<'static>] = &[
            DeviceFfi::SCHEMA,
            EnvelopeFfi::SCHEMA,
            PerspectiveFfi::SCHEMA,
            CryptoFfi::<Store>::SCHEMA,
            IdamFfi::<Store>::SCHEMA,
        ];

        let policy_ast = parse_policy_document(policy_doc)?;
        // Policy machine
        let module = Compiler::new(&policy_ast)
            .ffi_modules(ffi_schema)
            .compile()?;
        let machine = Machine::from_module(module).expect("should be able to load compiled module");

        Ok(Self { machine })
    }
}

// The FfiClientFactory uses signing keys in it's envelope, thus requires
// supporting FFIs.
impl ClientFactory for FfiClientFactory {
    type Engine = ModelEngine<DefaultEngine>;
    type StorageProvider = MemStorageProvider;
    type PublicKeys = PublicKeys<DefaultCipherSuite>;

    fn create_client(&mut self) -> ModelClient<FfiClientFactory> {
        // Setup keystore
        let temp_dir = tempdir().expect("should create temp directory");
        let root = temp_dir.into_path().join("client");
        assert!(
            !root.try_exists().expect("should create root path"),
            "duplicate client name"
        );
        let mut store = {
            let path = root.join("keystore");
            fs::create_dir_all(&path).expect("should create directory");
            Store::open(&path).expect("should create keystore")
        };

        // Generate key bundle
        let (mut eng, _) = DefaultEngine::from_entropy(Rng);
        let bundle =
            KeyBundle::generate(&mut eng, &mut store).expect("unable to generate `KeyBundle`");
        let public_keys = bundle
            .public_keys(&mut eng, &store)
            .expect("unable to generate public keys");

        // Configure FFIs
        let ffis: Vec<Box<dyn FfiCallable<DefaultEngine> + Send + 'static>> = vec![
            Box::from(DeviceFfi::new(bundle.user_id)),
            Box::from(EnvelopeFfi),
            Box::from(PerspectiveFfi),
            Box::from(CryptoFfi::new(
                store.try_clone().expect("should clone key store"),
            )),
            Box::from(IdamFfi::new(store)),
        ];

        let policy = VmPolicy::new(self.machine.clone(), eng, ffis).expect("should create policy");
        let engine = ModelEngine::new(policy);
        let provider = MemStorageProvider::new();

        ModelClient {
            state: RefCell::new(ClientState::new(engine, provider)),
            public_keys,
        }
    }
}

/// Tests the creation of a single client/graph and adds actions.
#[test]
fn should_create_basic_client_and_add_commands() {
    let basic_clients =
        BasicClientFactory::new(BASIC_POLICY).expect("should create client factory");
    let mut test_model = RuntimeModel::new(basic_clients);

    test_model.add_client(1).expect("Should create a client");

    let nonce = 1;
    test_model
        .new_graph(1, 1, vm_action!(init(nonce)))
        .expect("Should create a graph");

    let effects = test_model
        .action(1, 1, vm_action!(create(3)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 3 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(1, 1, vm_action!(increment(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 4 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(1, 1, vm_action!(increment(5)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 9 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(1, 1, vm_action!(decrement(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 8 })];
    assert_eq!(effects, expected);
}

/// Tests the creation of a single client/graph and adds actions using FFIs.
#[test]
fn should_create_client_with_ffi_and_add_commands() {
    let ffi_clients = FfiClientFactory::new(FFI_POLICY).expect("should create client factory");
    let mut test_model = RuntimeModel::new(ffi_clients);

    test_model.add_client(1).expect("Should create a client");

    let client_public_keys = test_model
        .get_public_keys(1)
        .expect("could not get public keys");

    let client_sign_pk =
        postcard::to_allocvec(&client_public_keys.sign_pk).expect("should get sign pk");
    let client_ident_pk =
        postcard::to_allocvec(&client_public_keys.ident_pk).expect("should get ident pk");

    let nonce = 1;

    // Create a graph for client one.
    test_model
        .new_graph(1, 1, vm_action!(init(nonce, client_sign_pk.clone())))
        .expect("Should create a graph");

    // Add client's keys to the fact db
    test_model
        .action(
            1,
            1,
            vm_action!(add_user_keys(
                client_ident_pk.clone(),
                client_sign_pk.clone()
            )),
        )
        .expect("should add user");

    let effects = test_model
        .action(1, 1, vm_action!(create(3)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 3 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(1, 1, vm_action!(increment(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 4 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(1, 1, vm_action!(increment(5)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 9 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(1, 1, vm_action!(decrement(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 8 })];
    assert_eq!(effects, expected);
}

/// Test that the creation of multiple clients with the same proxy id fail.
#[test]
fn should_fail_duplicate_client_ids() {
    let basic_clients =
        BasicClientFactory::new(BASIC_POLICY).expect("should create client factory");
    let mut test_model = RuntimeModel::new(basic_clients);

    test_model.add_client(1).expect("Should create a client");

    test_model
        .add_client(1)
        .expect_err("Should fail client creation if proxy_id is reused");
}

/// Test that the creation of multiple graphs with the same proxy id fail.
#[test]
fn should_fail_duplicate_graph_ids() {
    let basic_clients =
        BasicClientFactory::new(BASIC_POLICY).expect("should create client factory");
    let mut test_model = RuntimeModel::new(basic_clients);

    test_model.add_client(1).expect("Should create a client");

    let nonce = 1;
    test_model
        .new_graph(1, 1, vm_action!(init(nonce)))
        .expect("Should create a graph");

    let nonce = 2;
    test_model
        .new_graph(1, 1, vm_action!(init(nonce)))
        .expect_err("Should fail graph creation if proxy_id is reused");
}

/// Test that a client can support multiple graphs.
#[test]
fn should_allow_multiple_graphs() {
    let basic_clients =
        BasicClientFactory::new(BASIC_POLICY).expect("should create client factory");
    let mut test_model = RuntimeModel::new(basic_clients);

    test_model.add_client(1).expect("Should create a client");

    let nonce = 1;
    test_model
        .new_graph(1, 1, vm_action!(init(nonce)))
        .expect("Should create a graph");

    let nonce = 2;
    test_model
        .new_graph(2, 1, vm_action!(init(nonce)))
        .expect("Should support the ability to add multiple graphs");
}

/// Test that two clients using FFIs can sync with each other.
#[test]
fn should_sync_ffi_clients() {
    let ffi_clients = FfiClientFactory::new(FFI_POLICY).expect("should create client factory");
    let mut test_model = RuntimeModel::new(ffi_clients);

    // Create client 1
    test_model.add_client(1).expect("Should create a client");

    let client_one_public_keys = test_model
        .get_public_keys(1)
        .expect("could not get public keys");

    let client_one_sign_pk =
        postcard::to_allocvec(&client_one_public_keys.sign_pk).expect("should get sign pk");
    let client_one_ident_pk =
        postcard::to_allocvec(&client_one_public_keys.ident_pk).expect("should get ident pk");

    let nonce = 1;

    // Create graph for client one
    test_model
        .new_graph(1, 1, vm_action!(init(nonce, client_one_sign_pk.clone())))
        .expect("Should create a graph");

    // Add client's keys to the fact db
    test_model
        .action(
            1,
            1,
            vm_action!(add_user_keys(
                client_one_ident_pk.clone(),
                client_one_sign_pk.clone()
            )),
        )
        .expect("should add user");

    test_model
        .action(1, 1, vm_action!(create(3)))
        .expect("Should return effect");

    let effects = test_model
        .action(1, 1, vm_action!(increment(1)))
        .expect("Should return effect");

    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 4 })];
    assert_eq!(effects, expected);

    // Create client 2
    test_model.add_client(2).expect("Should create a client");

    let client_two_public_keys = test_model
        .get_public_keys(2)
        .expect("could not get public keys");

    let client_two_sign_pk =
        postcard::to_allocvec(&client_two_public_keys.sign_pk).expect("should get sign pk");
    let client_two_ident_pk =
        postcard::to_allocvec(&client_two_public_keys.ident_pk).expect("should get ident pk");

    // Sync client 2 from client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Add client's keys to the fact db
    test_model
        .action(
            2,
            1,
            vm_action!(add_user_keys(
                client_two_ident_pk.clone(),
                client_two_sign_pk.clone()
            )),
        )
        .expect("should add user");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(2, 1, vm_action!(increment(2)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 6 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(2, 1, vm_action!(increment(3)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 9 })];
    assert_eq!(effects, expected);

    // Sync client 1 from client 2 (2 -> 1)
    test_model.sync(1, 2, 1).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(1, 1, vm_action!(increment(4)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 13 })];
    assert_eq!(effects, expected);

    // Sync client 2 with client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(2, 1, vm_action!(increment(5)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 18 })];
    assert_eq!(effects, expected);
}

/// Test that we can sync two basic clients.
#[test]
fn should_sync_basic_clients() {
    let basic_clients =
        BasicClientFactory::new(BASIC_POLICY).expect("should create client factory");
    let mut test_model = RuntimeModel::new(basic_clients);

    // Create client 1
    test_model.add_client(1).expect("Should create a client");

    let nonce = 1;
    test_model
        .new_graph(1, 1, vm_action!(init(nonce)))
        .expect("Should create a graph");

    test_model
        .action(1, 1, vm_action!(create(3)))
        .expect("Should return effect");

    let effects = test_model
        .action(1, 1, vm_action!(increment(1)))
        .expect("Should return effect");

    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 4 })];
    assert_eq!(effects, expected);

    // Create client 2
    test_model.add_client(2).expect("Should create a client");

    // Sync client 2 from client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(2, 1, vm_action!(increment(2)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 6 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(2, 1, vm_action!(increment(3)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 9 })];
    assert_eq!(effects, expected);

    // Sync client 1 from client 2 (2 -> 1)
    test_model.sync(1, 2, 1).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(1, 1, vm_action!(increment(4)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 13 })];
    assert_eq!(effects, expected);

    // Sync client 2 with client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(2, 1, vm_action!(increment(5)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 18 })];
    assert_eq!(effects, expected);
}

/// Test that we can sync two basic clients that have identical payloads.
#[test]
fn should_sync_clients_with_duplicate_payloads() {
    let basic_clients =
        BasicClientFactory::new(BASIC_POLICY).expect("should create client factory");
    let mut test_model = RuntimeModel::new(basic_clients);

    test_model.add_client(1).expect("Should create a client");

    let nonce = 1;
    test_model
        .new_graph(1, 1, vm_action!(init(nonce)))
        .expect("Should create a graph");

    let effects = test_model
        .action(1, 1, vm_action!(create(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 1 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(1, 1, vm_action!(increment(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 2 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(1, 1, vm_action!(increment(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 3 })];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(1, 1, vm_action!(increment(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 4 })];
    assert_eq!(effects, expected);

    // Create client 2
    test_model.add_client(2).expect("Should create a client");

    // Sync client 2 from client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

    let effects = test_model
        .action(2, 1, vm_action!(increment(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 5 })];
    assert_eq!(effects, expected);
}

/// Test that we can use multiple instances of the model.
#[test]
fn should_allow_multiple_instances_of_model() {
    let basic_clients_1 =
        BasicClientFactory::new(BASIC_POLICY).expect("should create client factory");
    let mut test_model_1 = RuntimeModel::new(basic_clients_1);

    let basic_clients_2 =
        BasicClientFactory::new(BASIC_POLICY).expect("should create client factory");
    let mut test_model_2 = RuntimeModel::new(basic_clients_2);

    // Model 1 with client id of 1
    test_model_1.add_client(1).expect("Should create a client");

    // Model 2 with client id of 1
    test_model_2.add_client(1).expect("Should create a client");

    // Create a graph on the first model
    let nonce = 1;
    test_model_1
        .new_graph(1, 1, vm_action!(init(nonce)))
        .expect("Should create a graph");

    // Issue a action on the first model
    let effects = test_model_1
        .action(1, 1, vm_action!(create(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 1 })];
    assert_eq!(effects, expected);

    // Create a graph on the second model
    let nonce = 1;
    test_model_2
        .new_graph(1, 1, vm_action!(init(nonce)))
        .expect("Should create a graph");

    // Issue a action on the second model
    let effects = test_model_2
        .action(1, 1, vm_action!(create(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 1 })];
    assert_eq!(effects, expected);
}

/// Test that we can use multiple instances of the model with clients that use FFIs.
#[test]
fn should_allow_multiple_instances_of_model_with_ffi() {
    let ffi_clients_1 = FfiClientFactory::new(FFI_POLICY).expect("should create client factory");
    let mut test_model_1 = RuntimeModel::new(ffi_clients_1);

    let ffi_clients_2 = FfiClientFactory::new(FFI_POLICY).expect("should create client factory");
    let mut test_model_2 = RuntimeModel::new(ffi_clients_2);

    // Model 1 with client id of 1
    test_model_1.add_client(1).expect("Should create a client");

    let model_one_public_keys = test_model_1
        .get_public_keys(1)
        .expect("should get public keys");

    let model_one_sign_pk =
        postcard::to_allocvec(&model_one_public_keys.sign_pk).expect("should get sign pk");
    let model_one_ident_pk =
        postcard::to_allocvec(&model_one_public_keys.ident_pk).expect("should get ident pk");

    let nonce = 1;
    // Create a graph on the first model
    test_model_1
        .new_graph(1, 1, vm_action!(init(nonce, model_one_sign_pk.clone())))
        .expect("Should create a graph");

    // Add client's keys to the fact db
    test_model_1
        .action(
            1,
            1,
            vm_action!(add_user_keys(
                model_one_ident_pk.clone(),
                model_one_sign_pk.clone()
            )),
        )
        .expect("should add user");

    // Issue a action on the first model
    let effects = test_model_1
        .action(1, 1, vm_action!(create(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 1 })];
    assert_eq!(effects, expected);

    // Model 2 with client id of 1
    test_model_2.add_client(1).expect("Should create a client");

    let model_two_public_keys = test_model_2
        .get_public_keys(1)
        .expect("should get public keys");

    let model_two_sign_pk =
        postcard::to_allocvec(&model_two_public_keys.sign_pk).expect("should get sign_pk");
    let model_two_ident_pk =
        postcard::to_allocvec(&model_two_public_keys.ident_pk).expect("should get ident pk");

    let nonce = 1;
    // Create a graph on the second model
    test_model_2
        .new_graph(1, 1, vm_action!(init(nonce, model_two_sign_pk.clone())))
        .expect("Should create a graph");

    test_model_2
        .action(
            1,
            1,
            vm_action!(add_user_keys(
                model_two_ident_pk.clone(),
                model_two_sign_pk.clone()
            )),
        )
        .expect("should add user");

    // Issue a action on the second model
    let effects = test_model_2
        .action(1, 1, vm_action!(create(1)))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![vm_effect!(StuffHappened { a: 1, x: 1 })];
    assert_eq!(effects, expected);
}
