//! VM tests.

extern crate alloc;
use alloc::{boxed::Box, vec, vec::Vec};

use aranya_crypto::{DeviceId, Rng, default::DefaultEngine, id::IdExt as _};
use aranya_policy_module::Module;
use aranya_policy_vm::{FactKey, HashableValue, KVPair, Machine, Value, ast::ident};
use tracing::trace;

use super::dsl::dispatch;
use crate::{
    ClientState, CmdId, GraphId, MAX_SYNC_MESSAGE_SIZE, NullSink, PeerCache, SyncRequester,
    VmEffect, VmEffectData, VmPolicy, VmPolicyError,
    engine::{Engine, EngineError, PolicyId, Sink},
    ser_keys,
    storage::{Query, Storage, StorageProvider, memory::MemStorageProvider},
    vm_action, vm_effect,
    vm_policy::testing::TestFfiEnvelope,
};

/// The policy used by these tests.
pub const TEST_POLICY_1: &str = r#"---
policy-version: 2
---

```policy
use envelope

fact Stuff[x int]=>{y int}

effect StuffHappened {
    x int,
    y int,
}

effect OutOfRange {
    value int,
    increment int,
}

command Init {
    fields {
        nonce int,
    }
    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }
    policy {
        finish {}
    }
}

action init(nonce int) {
    publish Init {
        nonce: nonce,
    }
}

command Create {
    fields {
        key int,
        value int,
    }
    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }
    policy {
        finish {
            create Stuff[x: this.key]=>{y: this.value}
            emit StuffHappened{x: this.key, y: this.value}
        }
    }
}

action create_action(v int) {
    publish Create{
        key: 1,
        value: v,
    }
}

command Increment {
    fields {
        key int,
        amount int,
    }
    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }
    policy {
        let stuff = unwrap query Stuff[x: this.key]=>{y: ?}
        check stuff.y > 0
        let new_y = stuff.y + this.amount
        finish {
            update Stuff[x: this.key]=>{y: stuff.y} to {y: new_y}
            emit StuffHappened{x: this.key, y: new_y}
        }
    }

    recall {
        let stuff = unwrap query Stuff[x: this.key]=>{y: ?}
        finish {
            emit OutOfRange {
                value: stuff.y,
                increment: this.amount,
            }
        }
    }
}

action increment() {
    publish Increment{
        key: 1,
        amount: 1
    }
}

ephemeral command IncrementEphemeral {
    fields {
        key int,
        amount int,
    }
    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }
    policy {
        let stuff = unwrap query Stuff[x: this.key]=>{y: ?}
        check stuff.y > 0
        let new_y = stuff.y + this.amount
        finish {
            update Stuff[x: this.key]=>{y: stuff.y} to {y: new_y}
            emit StuffHappened{x: this.key, y: new_y}
        }
    }

    recall {
        let stuff = unwrap query Stuff[x: this.key]=>{y: ?}
        finish {
            emit OutOfRange {
                value: stuff.y,
                increment: this.amount,
            }
        }
    }
}

ephemeral action increment_ephemeral() {
    publish IncrementEphemeral {
        key: 1,
        amount: 1
    }
}


ephemeral action incrementFour(n int) {
    check n == 4
    publish IncrementEphemeral {
        key: 1,
        amount: n,
    }
}

ephemeral action lookup(k int, v int, expected bool) {
    let f = query Stuff[x: k]=>{y: v}
    match expected {
        true => { check f is Some }
        false => { check f is None }
    }
}

command Invalidate {
    attributes {
        priority: 1
    }
    fields {
        key int
    }
    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }
    policy {
        let stuff = unwrap query Stuff[x: this.key]=>{y: ?}
        let newval = -1  // hack around negative number parse bug; see #869
        finish {
            update Stuff[x: this.key]=>{y: stuff.y} to {y: newval}
            emit StuffHappened{x: this.key, y: newval}
        }
    }
}

action invalidate() {
    publish Invalidate { key: 1 }
}
```
"#;

#[derive(Debug, Default)]
pub struct TestSink {
    expect: Vec<VmEffectData>,
}

impl TestSink {
    pub fn new() -> Self {
        TestSink { expect: Vec::new() }
    }

    pub fn add_expectation(&mut self, expect: VmEffectData) {
        self.expect.push(expect);
    }
}

impl Sink<VmEffect> for TestSink {
    fn begin(&mut self) {
        trace!("sink begin");
    }

    fn consume(&mut self, effect: VmEffect) {
        trace!(?effect, "sink consume");
        let expect = self.expect.remove(0);
        assert_eq!(effect, expect);
    }

    fn rollback(&mut self) {
        trace!("sink rollback");
    }

    fn commit(&mut self) {
        trace!("sink commit");
    }
}

#[derive(Default)]
struct MsgSink(Vec<Box<[u8]>>);

impl MsgSink {
    fn new() -> Self {
        Self::default()
    }
}

impl Sink<&[u8]> for MsgSink {
    fn begin(&mut self) {
        trace!("sink begin");
    }

    fn consume(&mut self, effect: &[u8]) {
        trace!("sink consume");
        self.0.push(effect.into())
    }

    fn rollback(&mut self) {
        trace!("sink rollback");
    }

    fn commit(&mut self) {
        trace!("sink commit");
    }
}

/// A sink which allows more detailed inspection of effect metadata, as opposed to TestSink,
/// which only cares about the data.
#[derive(Default)]
struct VecSink(Vec<VmEffect>);

impl VecSink {
    fn new() -> Self {
        Self::default()
    }

    fn clear(&mut self) {
        self.0.clear();
    }

    fn last(&self) -> &VmEffect {
        self.0.last().expect("no elements")
    }
}

impl Sink<VmEffect> for VecSink {
    fn begin(&mut self) {
        trace!("sink begin");
    }

    fn consume(&mut self, effect: VmEffect) {
        trace!("sink consume");
        self.0.push(effect)
    }

    fn rollback(&mut self) {
        trace!("sink rollback");
    }

    fn commit(&mut self) {
        trace!("sink commit");
    }
}

/// Used by the VM tests.
pub struct TestEngine {
    policy: VmPolicy<DefaultEngine<Rng>>,
}

impl TestEngine {
    /// Creates a `TestEngine` from a [`Module`].
    pub fn from_module(module: Module) -> Self {
        let machine = Machine::from_module(module).expect("could not load compiled module");

        let (eng, _) = DefaultEngine::from_entropy(Rng);
        let policy = VmPolicy::new(
            machine,
            eng,
            vec![Box::from(TestFfiEnvelope {
                device: DeviceId::random(&mut Rng),
            })],
        )
        .expect("Could not load policy");
        TestEngine { policy }
    }
}

impl Engine for TestEngine {
    type Policy = VmPolicy<DefaultEngine<Rng>>;
    type Effect = VmEffect;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, EngineError> {
        Ok(PolicyId::new(policy[0] as usize))
    }

    fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, EngineError> {
        Ok(&self.policy)
    }
}

/// This test currently serves as the only real example of using
/// the Policy VM to execute Policy. Hopefully the comments will
/// make this useful for adaptation into a proper implementation.
///
/// The [`TestEngine`] must be instantiated with
/// [`TEST_POLICY_1`].
pub fn test_vmpolicy(engine: TestEngine) -> Result<(), VmPolicyError> {
    // TestEngine implements the Engine interface. It defines the core types that implement
    // the Engine itself, one of which is the Policy implementation. This particular Engine
    // implementation parses a policy document to create a VMPolicy instance which it owns.
    // But there is no requirement that it should do this, and in the future, it is
    // expected that the VM will consume compiled policy code to eliminate the need for the
    // parser/compiler to work in constrained environments.

    // We're using MemStorageProvider as our storage interface.
    let provider = MemStorageProvider::new();
    // ClientState contains the engine and the storage provider. It is the main interface
    // for using Aranya.
    let mut cs = ClientState::new(engine, provider);
    // TestSink implements the Sink interface to consume Effects. TestSink is borrowed from
    // the tests in protocol.rs. Here we
    let mut sink = TestSink::new();

    // Create a new graph. This builds an Init event and returns an ID referencing the
    // storage for the graph.
    let storage_id = cs
        .new_graph(&[0u8], vm_action!(init(0)), &mut sink)
        .expect("could not create graph");

    // Add an expected effect from the create action.
    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 3 }));

    // Create and execute an action in the policy. The action type is defined by the Engine
    // and here it is a pair of action name and a Vec of arguments. This is mapped directly
    // to the action call in policy language.
    //
    // The Commands produced by actions are evaluated immediately and sent to the sink.
    // This is why a sink is passed to the action method.
    cs.action(storage_id, &mut sink, vm_action!(create_action(3)))
        .expect("could not call action");

    // Add an expected effect for the increment action.
    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 4 }));

    // Call the increment action
    cs.action(storage_id, &mut sink, vm_action!(increment()))
        .expect("could not call action");

    // Everything past this point is validation that the facts exist and were created
    // correctly. Direct access to the storage provider should not be necessary in normal
    // operation.

    // Get the storage provider and get the storage associated with our storage ID to peek
    // into its graph.
    let storage = cs.provider().get_storage(storage_id)?;
    // Find the head Location.
    let head = storage.get_head()?;

    // Serialize the keys of the fact we created/updated in the previous actions.
    let fact_name = "Stuff";
    let fact_keys = ser_keys([FactKey::new(ident!("x"), HashableValue::Int(1))]);

    // This is the value part of the fact that we expect to retrieve.
    let expected_value = vec![KVPair::new(ident!("y"), Value::Int(4))];
    // Get a perspective for the head ID we got earlier. It should contain the facts we
    // seek.
    let perspective = storage.get_fact_perspective(head).expect("perspective");
    // Query the perspective using our key.
    let result = perspective
        .query(fact_name, &fact_keys)
        .expect("query")
        .expect("key does not exist");
    // Deserialize the value.
    let value: Vec<_> = postcard::from_bytes(&result).expect("result deserialization");
    // And check that it matches the value we expect.
    assert_eq!(expected_value, value);

    Ok(())
}

/// Test creating a fact.
///
/// The [`TestEngine`] must be instantiated with
/// [`TEST_POLICY_1`].
pub fn test_query_fact_value(engine: TestEngine) -> Result<(), VmPolicyError> {
    let provider = MemStorageProvider::new();
    let mut cs = ClientState::new(engine, provider);

    let graph = cs
        .new_graph(&[0u8], vm_action!(init(0)), &mut NullSink)
        .expect("could not create graph");

    cs.action(graph, &mut NullSink, vm_action!(create_action(1)))
        .expect("can create");

    let mut session = cs.session(graph).expect("should be able to create session");

    session
        .action(
            &cs,
            &mut NullSink,
            &mut NullSink,
            vm_action!(lookup(1, 1, true)),
        )
        .expect("should find 1,1");

    session
        .action(
            &cs,
            &mut NullSink,
            &mut NullSink,
            vm_action!(lookup(1, 2, false)),
        )
        .expect("should not find 1,2");

    Ok(())
}

/// Test ephemeral Aranya session.
/// See `https://github.com/aranya-project/aranya-docs/blob/main/src/Aranya-Sessions-note.md`.
///
/// The [`TestEngine`] must be instantiated with
/// [`TEST_POLICY_1`].
pub fn test_aranya_session(engine: TestEngine) -> Result<(), VmPolicyError> {
    let provider = MemStorageProvider::new();
    let mut cs = ClientState::new(engine, provider);

    let mut sink = TestSink::new();

    // Create a new graph. This builds an Init event and returns an ID referencing the
    // storage for the graph.
    let storage_id = cs
        .new_graph(&[0u8], vm_action!(init(0)), &mut sink)
        .expect("could not create graph");

    // Add an expected effect from the create action.
    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 3 }));

    // Create and execute an action in the policy. The action type is defined by the Engine
    // and here it is a pair of action name and a Vec of arguments. This is mapped directly
    // to the action call in policy language.
    //
    // The Commands produced by actions are evaluated immediately and sent to the sink.
    // This is why a sink is passed to the action method.
    cs.action(storage_id, &mut sink, vm_action!(create_action(3)))
        .expect("could not call action");

    // Add an expected effect for the increment action.
    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 4 }));

    // Call the increment action
    cs.action(storage_id, &mut sink, vm_action!(increment()))
        .expect("could not call action");

    {
        let msgs = {
            let mut session = cs.session(storage_id).expect("failed to create session");
            let mut msg_sink = MsgSink::new();

            // increment
            sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 5 }));
            session
                .action(
                    &cs,
                    &mut sink,
                    &mut msg_sink,
                    vm_action!(increment_ephemeral()),
                )
                .expect("failed session action");

            // reject incrementFour(33)
            session
                .action(&cs, &mut sink, &mut msg_sink, vm_action!(incrementFour(33)))
                .expect_err("action should fail");

            // succeed incrementFour(4)
            sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 9 }));
            session
                .action(&cs, &mut sink, &mut msg_sink, vm_action!(incrementFour(4)))
                .expect("failed session action");

            msg_sink.0
        };

        assert_eq!(msgs.len(), 2);

        {
            sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 5 }));
            sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 9 }));

            // Receive the increment commands
            let mut session = cs.session(storage_id).expect("failed to create session");
            for msg in &msgs {
                session
                    .receive(&cs, &mut sink, msg)
                    .expect("failed session receive");
            }
        }

        // Modify the graph to test against different head
        sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 5 }));

        // Call the increment action
        cs.action(storage_id, &mut sink, vm_action!(increment()))
            .expect("could not call action");

        {
            sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 6 }));
            sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 10 }));

            // Receive the increment commands
            let mut session = cs.session(storage_id).expect("failed to create session");
            for msg in &msgs {
                session
                    .receive(&cs, &mut sink, msg)
                    .expect("failed session receive");
            }
        }
    }

    // Verify that the graph was not affected by the ephemeral commands.

    let storage = cs.provider().get_storage(storage_id)?;
    let head = storage.get_head()?;

    let fact_name = "Stuff";
    let fact_keys = ser_keys([FactKey::new(ident!("x"), HashableValue::Int(1))]);

    let expected_value = vec![KVPair::new(ident!("y"), Value::Int(5))];
    let perspective = storage.get_fact_perspective(head).expect("perspective");
    let result = perspective
        .query(fact_name, &fact_keys)
        .expect("query")
        .expect("key does not exist");
    let value: Vec<_> = postcard::from_bytes(&result).expect("result deserialization");
    assert_eq!(expected_value, value);

    Ok(())
}

/// Syncs the first client at `storage_id` to the second client.
fn test_sync<E, P, S>(
    storage_id: GraphId,
    cs1: &mut ClientState<E, P>,
    cs2: &mut ClientState<E, P>,
    sink: &mut S,
) where
    P: StorageProvider,
    E: Engine,
    S: Sink<<E>::Effect>,
{
    let mut rng = Rng::new();
    let mut sync_requester = SyncRequester::new(storage_id, &mut rng, ());

    let mut req_transaction = cs1.transaction(storage_id);

    while sync_requester.ready() {
        let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
        let (len, _) = sync_requester
            .poll(&mut buffer, cs2.provider(), &mut PeerCache::new())
            .expect("sync req->res");

        let mut target = [0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = dispatch::<()>(
            &buffer[..len],
            &mut target,
            cs1.provider(),
            &mut PeerCache::new(),
        )
        .expect("dispatch sync response");

        if let Some(cmds) = sync_requester.receive(&target[..len]).expect("recieve req") {
            cs2.add_commands(&mut req_transaction, sink, &cmds)
                .expect("add commands");
        };
    }

    cs2.commit(&mut req_transaction, sink).expect("commit");
}

/// Tests the command ID and recall status in emitted `VmEffect`s.
///
/// The [`TestEngine`] must be instantiated with
/// [`TEST_POLICY_1`].
pub fn test_effect_metadata(engine: TestEngine, engine2: TestEngine) -> Result<(), VmPolicyError> {
    // create client 1 and initialize it with a nonce of 1
    let provider = MemStorageProvider::new();
    let mut cs1 = ClientState::new(engine, provider);
    let mut sink = VecSink::new();
    let storage_id = cs1
        .new_graph(&[0u8], vm_action!(init(1)), &mut sink)
        .expect("could not create graph");

    // Create a new counter with a value of 1
    cs1.action(storage_id, &mut sink, vm_action!(create_action(1)))
        .expect("could not call action");
    assert_eq!(sink.last(), &vm_effect!(StuffHappened { x: 1, y: 1 }));
    assert_ne!(sink.last().command, CmdId::default());
    assert!(!sink.last().recalled);
    sink.clear();

    // create client 2 and sync it with client 1
    let provider = MemStorageProvider::new();
    let mut cs2 = ClientState::new(engine2, provider);
    test_sync(storage_id, &mut cs1, &mut cs2, &mut sink);
    assert_eq!(sink.last(), &vm_effect!(StuffHappened { x: 1, y: 1 }));
    sink.clear();

    // At this point, clients are fully synced. Client 2 adds an Increment command, which
    // brings the counter to 2 from their perspective.
    cs2.action(storage_id, &mut sink, vm_action!(increment()))
        .expect("could not call action");
    assert_eq!(sink.last(), &vm_effect!(StuffHappened { x: 1, y: 2 }));
    let increment_cmd_id = sink.last().command;
    sink.clear();

    // MEANWHILE, IN A PARALLEL UNIVERSE - client 1 adds the Invalidate command, which sets
    // the counter value to a negative number. This will cause the check to fail in the
    // Increment command, preventing any further use of this counter.
    cs1.action(storage_id, &mut sink, vm_action!(invalidate()))
        .expect("could not call action");
    assert_eq!(sink.last(), &vm_effect!(StuffHappened { x: 1, y: -1 }));
    sink.clear();

    // Sync client 1 to client 2. Should produce a recall because `Invalidate` is
    // prioritized before `Increment`. Now that the counter value is starting with `-1`, the
    // check will fail, and recall will be executed. This produces an OutOfRange effect.
    test_sync(storage_id, &mut cs1, &mut cs2, &mut sink);
    assert_eq!(
        sink.last(),
        &vm_effect!(OutOfRange {
            increment: 1,
            value: -1
        })
    );
    // We further check that the command that caused this effect is the increment command we
    // created earlier,
    assert_eq!(sink.last().command, increment_cmd_id);
    // and that the `recalled` flag is set.
    assert!(sink.last().recalled);

    Ok(())
}
