use core::cell::RefCell;

extern crate alloc;
use alloc::{borrow::Cow, collections::BTreeMap, string::String, vec::Vec};

use crypto::Rng;
use policy_lang::lang::parse_policy_document;
use policy_vm::{compile_from_policy, ffi::FfiModule, KVPair, Value};

use super::{Model, ModelEffect, ModelEngine, ModelError, ProxyClientID, ProxyGraphID};
use crate::{
    command::Id,
    engine::Sink,
    storage::memory::MemStorageProvider,
    vm_policy::{ffi::FfiEnvelope, VmPolicy},
    ClientState, SyncRequester, SyncResponder, MAX_SYNC_MESSAGE_SIZE,
};

const TEST_POLICY_1: &str = r#"---
policy-version: 3
---

```policy
fact Stuff[a int, b int]=>{x int}

effect StuffHappened {
    a int,
    b int,
    x int,
}

command Create {
    // Local variables for command
    fields {
        key_a int,
        key_b int,
        value int,
    }
    seal { return envelope::seal(this) }
    open { return envelope::open(envelope) }
    policy {
        finish {
            create Stuff[a: this.key_a, b: this.key_b]=>{x: this.value}
            effect StuffHappened{a: this.key_a, b: this.key_b, x: this.value}
        }
    }
}

action create(v int) {
    emit Create{
        key_a: 1,
        key_b: 2,
        value: v,
    }
}

command Increment {
    fields {
        key_a int,
        key_b int,
        value int,
    }
    seal { return envelope::seal(this) }
    open { return envelope::open(envelope) }
    policy {
        let stuff = unwrap query Stuff[a: this.key_a, b: this.key_b]=>{x: ?}
        let new_x = stuff.x + this.value
        check new_x < 25
        finish {
            update Stuff[a: this.key_a, b: this.key_b]=>{x: stuff.x} to {x: new_x}
            effect StuffHappened{a: this.key_a, b: this.key_b, x: new_x}
        }
    }
}

action increment(v int) {
    emit Increment{
        key_a: 1,
        key_b: 2,
        value: v,
    }
}

command Decrement {
    fields {
        key_a int,
        key_b int,
        value int,
    }
    seal { return envelope::seal(this) }
    open { return envelope::open(envelope) }
    policy {
        let stuff = unwrap query Stuff[a: this.key_a, b: this.key_b]=>{x: ?}
        let new_x = stuff.x - value
        finish {
            update Stuff[a: this.key_a, b: this.key_b]=>{x: stuff.x} to {x: new_x}
            effect StuffHappened{a: this.key_a, b: this.key_b, x: new_x}
        }
    }
}

action decrement(v int) {
    emit Decrement{
        key_a: 1,
        key_b: 2,
        value: v,
    }
}
```
"#;

#[derive(Default, Debug, Copy, Clone)]
pub struct TestMetrics {
    effect_count: u64,           // Consume
    accepted_command_count: u64, // Commit
    rejected_command_count: u64, // Rollbacks
    step_count: u64,             // Begin
}

impl TestMetrics {
    pub fn update(&mut self, sink: &TestSink) {
        self.effect_count = self
            .effect_count
            .checked_add(sink.effects.len().try_into().unwrap())
            .expect("effect_count + sink length mustn't overflow");
        self.accepted_command_count = self
            .accepted_command_count
            .checked_add(sink.accepted_command_count)
            .expect("accepted_command_count + sink accepted_command_count mustn't overflow");
        self.rejected_command_count = self
            .rejected_command_count
            .checked_add(sink.rejected_command_count)
            .expect("rejected_command_count + sink rejected_command_count mustn't overflow");
        self.step_count = self
            .step_count
            .checked_add(sink.step_count)
            .expect("step_count + sink step_count mustn't overflow");
    }
}

struct TestClient {
    metrics: BTreeMap<ProxyGraphID, TestMetrics>,
    state: RefCell<ClientState<ModelEngine, MemStorageProvider>>,
}

#[derive(Debug, Default)]
pub struct TestSink {
    effects: Vec<ModelEffect>,
    accepted_command_count: u64,
    rejected_command_count: u64,
    step_count: u64,
}

impl Sink<ModelEffect> for TestSink {
    fn begin(&mut self) {
        self.step_count = self
            .step_count
            .checked_add(1)
            .expect("step_count mustn't overflow");
    }

    fn consume(&mut self, effect: ModelEffect) {
        self.effects.push(effect);
    }

    fn rollback(&mut self) {
        self.rejected_command_count = self
            .rejected_command_count
            .checked_add(1)
            .expect("rejected_command_count + sink rejected_command_count mustn't overflow");
    }

    fn commit(&mut self) {
        self.accepted_command_count = self
            .accepted_command_count
            .checked_add(1)
            .expect("accepted_command_count + sink accepted_command_count mustn't overflow");
    }
}

#[derive(Default)]
pub struct TestModel {
    clients: BTreeMap<ProxyClientID, TestClient>,
    storage_ids: BTreeMap<ProxyGraphID, Id>,
}

impl Model for TestModel {
    type Effects = Vec<ModelEffect>;
    type Metrics = TestMetrics;
    type Action<'a> = (&'a str, Cow<'a, [Value]>);

    // NOTE: Metrics cannot be stores until a graph is initialized, a `proxy_graph_id` is required to store metrics.
    fn add_client(&mut self, proxy_id: ProxyClientID, policy_doc: &str) -> Result<(), ModelError> {
        // A client with this ID already exists.
        if self.clients.get(&proxy_id).is_some() {
            return Err(ModelError::DuplicateClient);
        };

        let policy_ast = parse_policy_document(policy_doc).expect("parse policy document");
        let machine =
            compile_from_policy(&policy_ast, &[FfiEnvelope::SCHEMA]).expect("compile policy");
        let policy =
            VmPolicy::new(machine, vec![Box::from(FfiEnvelope {})]).expect("Could not load policy");
        let engine = ModelEngine::new(policy);
        let provider = MemStorageProvider::new();
        let metrics: BTreeMap<ProxyGraphID, Self::Metrics> = BTreeMap::new();
        let cs = ClientState::new(engine, provider);
        let state = RefCell::new(cs);

        let client = TestClient { metrics, state };

        self.clients.insert(proxy_id, client);

        Ok(())
    }

    fn new_graph(
        &mut self,
        proxy_id: ProxyGraphID,
        client_proxy_id: ProxyClientID,
    ) -> Result<Self::Effects, ModelError> {
        if self.storage_ids.get(&proxy_id).is_some() {
            return Err(ModelError::DuplicateGraph);
        }

        let mut sink = TestSink::default();

        let client = self
            .clients
            .get_mut(&client_proxy_id)
            .expect("Could not get client");

        let mut state = client.state.borrow_mut();

        let storage_id = state
            .new_graph(&[0u8], Default::default(), &mut sink)
            .expect("could not create graph");

        self.storage_ids.insert(proxy_id, storage_id);

        let mut metrics = Self::Metrics::default();

        metrics.update(&sink);

        client.metrics.insert(proxy_id, metrics);

        Ok(sink.effects)
    }

    fn action(
        &mut self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
        action: Self::Action<'_>,
    ) -> Result<Self::Effects, ModelError> {
        let mut sink = TestSink::default();

        let client = self
            .clients
            .get_mut(&client_proxy_id)
            .expect("Could not get client");

        let mut state = client.state.borrow_mut();

        let storage_id = self
            .storage_ids
            .get(&graph_proxy_id)
            .expect("Could not get storage id");

        let metrics = client
            .metrics
            .get_mut(&graph_proxy_id)
            .expect("Could not get client metrics.");

        match state.action(storage_id, &mut sink, action) {
            Ok(_) => {
                metrics.update(&sink);
            }
            Err(e) => {
                // Update metrics even if action is rejected.
                metrics.update(&sink);
                return Err(e.into());
            }
        }

        Ok(sink.effects)
    }

    fn get_statistics(
        &self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
    ) -> Result<Self::Metrics, ModelError> {
        let client = self
            .clients
            .get(&client_proxy_id)
            .expect("Could not get client");

        let metrics = client
            .metrics
            .get(&graph_proxy_id)
            .expect("Could not get client metrics.");

        Ok(*metrics)
    }

    fn sync(
        &mut self,
        graph_proxy_id: ProxyGraphID,
        source_client_proxy_id: ProxyClientID,
        dest_client_proxy_id: ProxyClientID,
    ) -> Result<(), ModelError> {
        let mut request_sink = TestSink::default();

        // Destination of the sync
        let mut request_state = self
            .clients
            .get(&dest_client_proxy_id)
            .expect("Could not get client")
            .state
            .borrow_mut();

        // Source of the sync
        let mut response_state = self
            .clients
            .get(&source_client_proxy_id)
            .expect("Could not get client")
            .state
            .borrow_mut();

        let storage_id = self
            .storage_ids
            .get(&graph_proxy_id)
            .expect("Could not get storage id");

        unidirectional_sync(
            storage_id,
            &mut request_state,
            &mut response_state,
            &mut request_sink,
        )?;

        drop(response_state);
        drop(request_state);

        // Destination of the sync
        self.clients
            .get_mut(&dest_client_proxy_id)
            .expect("Could not get client")
            .metrics
            .entry(graph_proxy_id)
            .or_default()
            .update(&request_sink);

        Ok(())
    }
}

fn unidirectional_sync(
    storage_id: &Id,
    request_state: &mut ClientState<ModelEngine, MemStorageProvider>,
    response_state: &mut ClientState<ModelEngine, MemStorageProvider>,
    request_sink: &mut TestSink,
) -> Result<(), ModelError> {
    let mut request_syncer = SyncRequester::new(*storage_id, &mut Rng::new());
    let mut response_syncer = SyncResponder::new();

    assert!(request_syncer.ready());

    let mut request_trx = request_state.transaction(storage_id);

    // TODO: (Scott) Once https://git.spideroak-inc.com/spideroak-inc/flow3-rs/pull/476 gets merged in we'll need to initiate another loop or run of unidirectional_sync func. The syncer will only queue up to 100 segments to sync at a time.

    loop {
        if !request_syncer.ready() && !response_syncer.ready() {
            break;
        }

        if request_syncer.ready() {
            let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
            let len = request_syncer.poll(&mut buffer, request_state.provider())?;

            response_syncer.receive(&buffer[..len])?;
        }

        if response_syncer.ready() {
            let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
            let len = response_syncer.poll(&mut buffer, response_state.provider())?;

            if len == 0 {
                break;
            }

            if let Some(cmds) = request_syncer.receive(&buffer[..len])? {
                request_state.add_commands(&mut request_trx, request_sink, &cmds)?;
            };
        }
    }

    request_state
        .commit(&mut request_trx, request_sink)
        .expect("Should commit the transaction");

    Ok(())
}

#[test]
fn test_runtime_model() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect_err("Should fail client creation if proxy_id is reused");

    test_model.new_graph(1, 1).expect("Should create a graph");

    test_model
        .new_graph(1, 1)
        .expect_err("Should fail graph creation if proxy_id is reused");

    test_model
        .new_graph(2, 1)
        .expect("Should support the ability to add multiple graphs");

    let action = ("create", [Value::Int(3)].as_slice().into());
    let effects = test_model
        .action(1, 1, action)
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(3)),
        ],
    )];
    assert_eq!(effects, expected);

    let action = ("increment", [Value::Int(1)].as_slice().into());
    let effects = test_model
        .action(1, 1, action)
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(4)),
        ],
    )];
    assert_eq!(effects, expected);

    let action = ("increment", [Value::Int(5)].as_slice().into());
    let effects = test_model
        .action(1, 1, action)
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(9)),
        ],
    )];
    assert_eq!(effects, expected);

    let metrics = test_model
        .get_statistics(1, 1)
        .expect("Should return metrics");
    assert_eq!(metrics.effect_count, 3);
    assert_eq!(metrics.accepted_command_count, 4);
    assert_eq!(metrics.rejected_command_count, 0);
    assert_eq!(metrics.step_count, 4);

    test_model
        .add_client(2, TEST_POLICY_1)
        .expect("Client not be created");

    test_model.sync(1, 1, 2).expect("Should sync clients");

    let metrics = test_model
        .get_statistics(2, 1)
        .expect("Should return metrics");
    assert_eq!(metrics.effect_count, 3);
    assert_eq!(metrics.accepted_command_count, 4);
    assert_eq!(metrics.rejected_command_count, 0);
    assert_eq!(metrics.step_count, 4);

    let action = ("increment", [Value::Int(1)].as_slice().into());
    let effects = test_model
        .action(2, 1, action)
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(10)),
        ],
    )];
    assert_eq!(effects, expected);

    let action = ("increment", [Value::Int(5)].as_slice().into());
    let effects = test_model
        .action(1, 1, action)
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(14)),
        ],
    )];
    assert_eq!(effects, expected);

    test_model.sync(1, 2, 1).expect("Should sync clients");

    let metrics = test_model
        .get_statistics(1, 1)
        .expect("Should return metrics");
    assert_eq!(metrics.effect_count, 6);
    assert_eq!(metrics.accepted_command_count, 7);
    assert_eq!(metrics.rejected_command_count, 0);
    assert_eq!(metrics.step_count, 7);

    let action = ("increment", [Value::Int(1)].as_slice().into());
    let effects = test_model
        .action(1, 1, action)
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(16)),
        ],
    )];
    assert_eq!(effects, expected);

    test_model.sync(1, 1, 2).expect("Should sync clients");

    let metrics = test_model
        .get_statistics(2, 1)
        .expect("Should return metrics");
    assert_eq!(metrics.effect_count, 7);
    assert_eq!(metrics.accepted_command_count, 8);
    assert_eq!(metrics.rejected_command_count, 0);
    assert_eq!(metrics.step_count, 8);

    let metrics = test_model
        .get_statistics(1, 1)
        .expect("Should return metrics");
    assert_eq!(metrics.effect_count, 7);
    assert_eq!(metrics.accepted_command_count, 8);
    assert_eq!(metrics.rejected_command_count, 0);
    assert_eq!(metrics.step_count, 8);

    // This test case should fail
    // The `increment` command has a policy condition to only allow a final x value under 25.
    let action = ("increment", [Value::Int(25)].as_slice().into());
    let effects = test_model
        .action(1, 1, action)
        .expect_err("Should fail policy");
    assert!(matches!(effects, ModelError::Client(_)));

    let metrics = test_model
        .get_statistics(1, 1)
        .expect("Should return metrics");

    assert_eq!(metrics.effect_count, 7);
    assert_eq!(metrics.accepted_command_count, 8);
    assert_eq!(metrics.rejected_command_count, 1);
    assert_eq!(metrics.step_count, 9);
}
