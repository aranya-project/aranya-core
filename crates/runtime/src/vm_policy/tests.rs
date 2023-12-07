use policy_lang::lang::parse_policy_document;
use policy_vm::{compile_from_policy, KVPair, Value};
use postcard::{from_bytes, to_vec};

use super::{error::VmPolicyError, VmPolicy};
use crate::{
    engine::{Engine, EngineError, PolicyId, Sink},
    storage::{memory::MemStorageProvider, FactPerspective, Storage, StorageProvider},
    ClientState,
};

const TEST_POLICY_1: &str = r#"---
policy-version: 3
---

```policy
fact Value[x int]=>{y int}

effect StuffHappened {
    x int,
    y int,
}

command Create {
    fields {
        key int,
        value int,
    }
    seal { return None }
    open { return None }
    policy {
        finish {
            create Stuff[x: this.key]=>{y: this.value}
            effect StuffHappened{x: this.key, y: this.value}
        }
    }
}

action create(v int) {
    emit Create{
        key: 1,
        value: v,
    }
}

command Increment {
    fields {
        key int,
    }
    seal { return None }
    open { return None }
    policy {
        let stuff = unwrap query Stuff[x: this.key]=>{y: ?}
        let new_y = stuff.y + 1
        finish {
            update Stuff[x: this.key]=>{y: stuff.y} to {y: new_y}
            effect StuffHappened{x: this.key, y: new_y}
        }
    }
}

action increment() {
    emit Increment{
        key: 1,
    }
}
```
"#;

type TestEffect = (String, Vec<KVPair>);
#[derive(Debug)]
pub struct TestSink {
    expect: Vec<TestEffect>,
}

impl TestSink {
    pub fn new() -> Self {
        TestSink { expect: Vec::new() }
    }

    pub fn add_expectation(&mut self, expect: TestEffect) {
        self.expect.push(expect);
    }
}

impl Sink<TestEffect> for TestSink {
    fn begin(&mut self) {
        //NOOP
        println!("sink begin");
    }

    fn consume(&mut self, effect: TestEffect) {
        println!("sink consume");
        let expect = self.expect.remove(0);
        assert_eq!(effect, expect);
    }

    fn rollback(&mut self) {
        //NOOP
        println!("sink rollback");
    }

    fn commit(&mut self) {
        //NOOP
        println!("sink commit");
    }
}

pub struct TestEngine {
    policy: VmPolicy,
}

impl TestEngine {
    pub fn new(policy_doc: &str) -> TestEngine {
        let ast = parse_policy_document(policy_doc).expect("parse policy document");
        let machine = compile_from_policy(&ast, &[]).expect("compile policy");
        let policy = VmPolicy::new(machine).expect("Could not load policy");
        TestEngine { policy }
    }
}

impl Engine for TestEngine {
    type Policy = VmPolicy;
    type Payload = ();
    type Effects = TestEffect;
    type Actions = (String, Vec<Value>);

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, EngineError> {
        Ok(PolicyId::new(policy[0] as usize))
    }

    fn get_policy<'a>(&'a self, _id: &PolicyId) -> Result<&'a Self::Policy, EngineError> {
        Ok(&self.policy)
    }
}

#[test]
// This test currently serves as the only real example of using the Policy VM to execute
// Policy. Hopefully the comments will make this useful for adaptation into a proper
// implementation.
fn test_vmpolicy() -> Result<(), VmPolicyError> {
    // TestEngine implements the Engine interface. It defines the core types that implement
    // the Engine itself, one of which is the Policy implementation. This particular Engine
    // implementation parses a policy document to create a VMPolicy instance which it owns.
    // But there is no requirement that it should do this, and in the future, it is
    // expected that the VM will consume compiled policy code to eliminate the need for the
    // parser/compiler to work in constrained environments.
    let engine = TestEngine::new(TEST_POLICY_1);
    // We're using MemStorageProvider as our storage interface.
    let provider = MemStorageProvider::new();
    // ClientState contains the engine and the storage provider. It is the main interface
    // for using Aranya.
    let mut cs = ClientState::new(engine, provider);
    // TestSink implements the Sink interface to consume Effects. TestSink is borrowed from
    // the tests in protocol.rs. Here we
    let mut sink = TestSink::new();

    // Create a new graph. This builds an Init event and returns an Id referencing the
    // storage for the graph.
    let storage_id = cs
        .new_graph(&[0u8], &(), &mut sink)
        .expect("could not create graph");

    // Add an expected effect from the create action.
    sink.add_expectation((
        String::from("StuffHappened"),
        vec![
            KVPair::new("x", Value::Int(1)),
            KVPair::new("y", Value::Int(3)),
        ],
    ));

    // Create and execute an action in the policy. The action type is defined by the Engine
    // and here it is a pair of action name and a Vec of arguments. This is mapped directly
    // to the action call in policy language.
    //
    // The Commands produced by actions are evaluated immediately and sent to the sink.
    // This is why a sink is passed to the action method.
    let action = (String::from("create"), vec![Value::Int(3)]);
    cs.action(&storage_id, &mut sink, &action)
        .expect("could not call action");

    // Add an expected effect for the increment action.
    sink.add_expectation((
        String::from("StuffHappened"),
        vec![
            KVPair::new("x", Value::Int(1)),
            KVPair::new("y", Value::Int(4)),
        ],
    ));

    // Call the increment action
    let action = (String::from("increment"), vec![]);
    cs.action(&storage_id, &mut sink, &action)
        .expect("could not call action");

    // Everything past this point is validation that the facts exist and were created
    // correctly. Direct access to the storage provider should not be necessary in normal
    // operation.

    // Get the storage provider and get the storage associated with our storage Id to peek
    // into its graph.
    let storage = cs.provider().get_storage(&storage_id)?;
    // Find the head Location.
    let head = storage.get_head()?;

    // Serialize an object that represents the key of the fact we created/updated in the
    // previous actions.
    let key_vec: heapless::Vec<u8, 256> = to_vec(&(
        String::from("Stuff"),
        vec![(String::from("x"), Value::Int(1))],
    ))
    .expect("key serialization");

    // This is the value part of the fact that we expect to retrieve.
    let expected_value = vec![KVPair::new("y", Value::Int(4))];
    // Get a perspective for the head Id we got earlier. It should contain the facts we
    // seek.
    let perspective = storage.get_fact_perspective(&head).expect("perspective");
    // Query the perspective using our key.
    let result = perspective
        .query(&key_vec)
        .expect("query")
        .expect("key does not exist");
    // Deserialize the value.
    let value: Vec<_> = from_bytes(&result).expect("result deserialization");
    // And check that it matches the value we expect.
    assert_eq!(expected_value, value);

    Ok(())
}
