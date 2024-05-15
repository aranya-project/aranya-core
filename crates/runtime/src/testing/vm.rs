//! VM tests.

extern crate alloc;
use alloc::{boxed::Box, string::String, vec, vec::Vec};

use crypto::{default::DefaultEngine, Rng, UserId};
use policy_module::Module;
use policy_vm::{KVPair, Machine, Value};
use tracing::trace;

use crate::{
    engine::{Engine, EngineError, PolicyId, Sink},
    storage::{memory::MemStorageProvider, Query, Storage, StorageProvider},
    vm_action, vm_effect,
    vm_policy::testing::TestFfiEnvelope,
    ClientState, NullSink, VmEffect, VmPolicy, VmPolicyError,
};

/// The policy used by these tests.
pub const TEST_POLICY_1: &str = r#"---
policy-version: 1
---

```policy
fact Stuff[x int]=>{y int}

effect StuffHappened {
    x int,
    y int,
}

command Init {
    fields {
        nonce int,
    }
    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }
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
    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }
    policy {
        finish {
            create Stuff[x: this.key]=>{y: this.value}
            emit StuffHappened{x: this.key, y: this.value}
        }
    }
}

action create(v int) {
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
    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }
    policy {
        let stuff = unwrap query Stuff[x: this.key]=>{y: ?}
        let new_y = stuff.y + this.amount
        finish {
            update Stuff[x: this.key]=>{y: stuff.y} to {y: new_y}
            emit StuffHappened{x: this.key, y: new_y}
        }
    }
}

action increment() {
    publish Increment{
        key: 1,
        amount: 1
    }
}

action incrementFour(n int) {
    check n == 4
    publish Increment {
        key: 1,
        amount: n,
    }
}

action lookup(k int, v int, expected bool) {
    let f = query Stuff[x: k]=>{y: v}
    match expected {
        true => { check f is Some }
        false => { check f is None }
    }
}
```
"#;

#[derive(Debug, Default)]
struct TestSink {
    expect: Vec<VmEffect>,
}

impl TestSink {
    fn new() -> Self {
        TestSink { expect: Vec::new() }
    }

    fn add_expectation(&mut self, expect: VmEffect) {
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
                user: UserId::random(&mut Rng),
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

    fn get_policy<'a>(&'a self, _id: &PolicyId) -> Result<&'a Self::Policy, EngineError> {
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
    cs.action(&storage_id, &mut sink, vm_action!(create(3)))
        .expect("could not call action");

    // Add an expected effect for the increment action.
    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 4 }));

    // Call the increment action
    cs.action(&storage_id, &mut sink, vm_action!(increment()))
        .expect("could not call action");

    // Everything past this point is validation that the facts exist and were created
    // correctly. Direct access to the storage provider should not be necessary in normal
    // operation.

    // Get the storage provider and get the storage associated with our storage ID to peek
    // into its graph.
    let storage = cs.provider().get_storage(&storage_id)?;
    // Find the head Location.
    let head = storage.get_head()?;

    // Serialize an object that represents the key of the fact we created/updated in the
    // previous actions.
    let key_vec: Vec<u8> = postcard::to_allocvec(&(
        String::from("Stuff"),
        vec![(String::from("x"), Value::Int(1))],
    ))
    .expect("key serialization");

    // This is the value part of the fact that we expect to retrieve.
    let expected_value = vec![KVPair::new("y", Value::Int(4))];
    // Get a perspective for the head ID we got earlier. It should contain the facts we
    // seek.
    let perspective = storage.get_fact_perspective(head).expect("perspective");
    // Query the perspective using our key.
    let result = perspective
        .query(&key_vec)
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

    cs.action(&graph, &mut NullSink, vm_action!(create(1)))
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
/// See `flow3-docs/src/Aranya-Sessions-note.md`.
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
    cs.action(&storage_id, &mut sink, vm_action!(create(3)))
        .expect("could not call action");

    // Add an expected effect for the increment action.
    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 4 }));

    // Call the increment action
    cs.action(&storage_id, &mut sink, vm_action!(increment()))
        .expect("could not call action");

    {
        let msgs = {
            let mut session = cs.session(storage_id).expect("failed to create session");
            let mut msg_sink = MsgSink::new();

            // increment
            sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 5 }));
            session
                .action(&cs, &mut sink, &mut msg_sink, vm_action!(increment()))
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
        cs.action(&storage_id, &mut sink, vm_action!(increment()))
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

    let storage = cs.provider().get_storage(&storage_id)?;
    let head = storage.get_head()?;

    let key_vec = postcard::to_allocvec(&(
        String::from("Stuff"),
        vec![(String::from("x"), Value::Int(1))],
    ))
    .expect("key serialization");

    let expected_value = vec![KVPair::new("y", Value::Int(5))];
    let perspective = storage.get_fact_perspective(head).expect("perspective");
    let result = perspective
        .query(&key_vec)
        .expect("query")
        .expect("key does not exist");
    let value: Vec<_> = postcard::from_bytes(&result).expect("result deserialization");
    assert_eq!(expected_value, value);

    Ok(())
}
