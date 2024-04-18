extern crate alloc;

use alloc::{borrow::Cow, collections::BTreeMap, string::String, vec::Vec};
use core::{cell::RefCell, matches, time::Duration};
use std::time::Instant;

use crypto::{default::DefaultEngine, Rng, UserId};
use policy_lang::lang::parse_policy_document;
use policy_vm::{ffi::FfiModule, Compiler, KVPair, Value};
use runtime::{
    engine::Sink,
    metrics::{Metric, MetricError, Metrics},
    storage::{memory::MemStorageProvider, GraphId},
    vm_policy::{testing::TestFfiEnvelope, VmPolicy},
    ClientState, SyncRequester, SyncResponder, MAX_SYNC_MESSAGE_SIZE,
};
use test_log::test;

use crate::{Model, ModelEffect, ModelEngine, ModelError, ProxyClientID, ProxyGraphID};

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

command Init {
    fields {
        nonce int
    }

    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    policy {
        check this.nonce > 0
        finish {}
    }
}

action init(nonce int) {
    publish Init {
        nonce: nonce,
    }
}

command Create {
    // Local variables for command
    fields {
        key_a int,
        key_b int,
        value int,
    }
    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }
    policy {
        finish {
            create Stuff[a: this.key_a, b: this.key_b]=>{x: this.value}
            emit StuffHappened{a: this.key_a, b: this.key_b, x: this.value}
        }
    }
}

action create(v int) {
    publish Create{
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
    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }
    policy {
        let stuff = unwrap query Stuff[a: this.key_a, b: this.key_b]=>{x: ?}
        let new_x = stuff.x + this.value
        check new_x < 25
        finish {
            update Stuff[a: this.key_a, b: this.key_b]=>{x: stuff.x} to {x: new_x}
            emit StuffHappened{a: this.key_a, b: this.key_b, x: new_x}
        }
    }
}

action increment(v int) {
    publish Increment{
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
    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }
    policy {
        let stuff = unwrap query Stuff[a: this.key_a, b: this.key_b]=>{x: ?}
        let new_x = stuff.x - value
        finish {
            update Stuff[a: this.key_a, b: this.key_b]=>{x: stuff.x} to {x: new_x}
            emit StuffHappened{a: this.key_a, b: this.key_b, x: new_x}
        }
    }
}

action decrement(v int) {
    publish Decrement{
        key_a: 1,
        key_b: 2,
        value: v,
    }
}
```
"#;

/// Test metrics.
///
/// Holds a collection of [`Metric`] values.
#[derive(Default, Debug, Clone)]
pub struct TestMetrics {
    metrics: BTreeMap<&'static str, Metric>,
}

impl TestMetrics {
    fn list(&self) -> Vec<&str> {
        self.metrics.keys().cloned().collect()
    }
}

impl Metrics for TestMetrics {
    type Error = ModelError;

    fn update(&mut self, name: &'static str, metric: Metric) -> Result<(), Self::Error> {
        use alloc::collections::btree_map::Entry;

        match self.metrics.entry(name) {
            Entry::Vacant(e) => {
                e.insert(metric);
            }
            Entry::Occupied(mut e) => match (e.get_mut(), metric) {
                (Metric::Count(v), Metric::Count(m)) => {
                    *v = v.checked_add(m).expect("sink count mustn't overflow");
                }
                (Metric::Duration(v), Metric::Duration(m)) => {
                    *v = v.checked_add(m).expect("sink duration mustn't overflow");
                }
                _ => {
                    return Err(ModelError::Metric(MetricError::IncorrectType));
                }
            },
        }

        Ok(())
    }
}

/// Test client.
///
/// Holds [`ClientState`] for graphs that belong to the client.
struct TestClient {
    state: RefCell<ClientState<ModelEngine<DefaultEngine<Rng>>, MemStorageProvider>>,
}

/// Test sink.
///
/// Holds a collection of [`Metric`] and [`ModelEffect`] data.
#[derive(Debug)]
pub struct TestSink<'a> {
    sink_metrics: &'a mut TestMetrics,
    effects: Vec<ModelEffect>,
}

impl Sink<ModelEffect> for TestSink<'_> {
    fn begin(&mut self) {
        self.sink_metrics
            .update("step_count", Metric::Count(1))
            .unwrap();
    }

    fn consume(&mut self, effect: ModelEffect) {
        self.sink_metrics
            .update("effect_count", Metric::Count(1))
            .unwrap();
        self.effects.push(effect);
    }

    fn rollback(&mut self) {
        self.sink_metrics
            .update("rejected_command_count", Metric::Count(1))
            .unwrap();
    }

    fn commit(&mut self) {
        self.sink_metrics
            .update("accepted_command_count", Metric::Count(1))
            .unwrap();
    }
}

type GraphMetrics = BTreeMap<ProxyGraphID, TestMetrics>;
type ClientMetrics = BTreeMap<ProxyClientID, GraphMetrics>;
type ClientStorageIds = BTreeMap<ProxyGraphID, GraphId>;
type Clients = BTreeMap<ProxyClientID, TestClient>;

/// Test model.
///
/// Holds a collection of [`TestClient`] and Graph ID data.
#[derive(Default)]
pub struct TestModel {
    clients: Clients,
    storage_ids: ClientStorageIds,
    metrics: ClientMetrics,
}

impl TestModel {
    fn list_metrics_keys(
        &mut self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
    ) -> Result<Vec<&str>, ModelError> {
        let metrics = self
            .metrics
            .get(&client_proxy_id)
            .expect("Could not get client")
            .get(&graph_proxy_id)
            .expect("Could not get client metrics.");

        Ok(metrics.list())
    }

    fn get_metric(
        &self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
        key: &str,
    ) -> Option<Metric> {
        self.metrics
            .get(&client_proxy_id)?
            .get(&graph_proxy_id)?
            .metrics
            .get(&key)
            .copied()
    }
}

impl Model for TestModel {
    type Effect = Vec<ModelEffect>;
    type Action<'a> = (&'a str, Cow<'a, [Value]>);

    // NOTE: Metrics cannot be stores until a graph is initialized, a `proxy_graph_id` is required to store metrics.
    fn add_client(&mut self, proxy_id: ProxyClientID, policy_doc: &str) -> Result<(), ModelError> {
        // A client with this ID already exists.
        if self.clients.get(&proxy_id).is_some() {
            return Err(ModelError::DuplicateClient);
        };

        let policy_ast = parse_policy_document(policy_doc).expect("parse policy document");
        let machine = Compiler::new(&policy_ast)
            .ffi_modules(&[TestFfiEnvelope::SCHEMA])
            .compile()
            .expect("compile policy");
        let (eng, _) = DefaultEngine::from_entropy(Rng);
        let policy = VmPolicy::new(
            machine,
            eng,
            vec![Box::from(TestFfiEnvelope {
                user: UserId::random(&mut Rng),
            })],
        )
        .expect("Could not load policy");
        let engine = ModelEngine::new(policy);
        let provider = MemStorageProvider::new();
        let cs = ClientState::new(engine, provider);
        let state = RefCell::new(cs);

        let client = TestClient { state };
        self.clients.insert(proxy_id, client);

        Ok(())
    }

    fn new_graph(
        &mut self,
        proxy_id: ProxyGraphID,
        client_proxy_id: ProxyClientID,
    ) -> Result<Self::Effect, ModelError> {
        if self.storage_ids.get(&proxy_id).is_some() {
            return Err(ModelError::DuplicateGraph);
        }

        let test_metrics = self
            .metrics
            .entry(client_proxy_id)
            .or_default()
            .entry(proxy_id)
            .or_default();

        let mut sink = TestSink {
            sink_metrics: test_metrics,
            effects: vec![],
        };

        let mut state = self
            .clients
            .get_mut(&client_proxy_id)
            .expect("Could not get client")
            .state
            .borrow_mut();

        let nonce =
            i64::try_from(proxy_id).expect("proxy_id too big to be represented as Value::Int");
        let storage_id = state
            .new_graph(
                &[0u8],
                ("init", [Value::Int(nonce)].as_slice().into()),
                &mut sink,
            )
            .expect("could not create graph");

        self.storage_ids.insert(proxy_id, storage_id);

        Ok(sink.effects)
    }

    fn action(
        &mut self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
        action: Self::Action<'_>,
    ) -> Result<Self::Effect, ModelError> {
        let action_exc_time = Instant::now();

        let storage_id = self
            .storage_ids
            .get(&(graph_proxy_id))
            .expect("Could not get storage id");

        let mut state = self
            .clients
            .get_mut(&client_proxy_id)
            .expect("Could not get client")
            .state
            .borrow_mut();

        let test_metrics = self
            .metrics
            .entry(client_proxy_id)
            .or_default()
            .entry(graph_proxy_id)
            .or_default();

        let mut sink = TestSink {
            sink_metrics: test_metrics,
            effects: vec![],
        };

        state.action(storage_id, &mut sink, action)?;

        sink.sink_metrics
            .update(
                "action_exc_time",
                Metric::Duration(action_exc_time.elapsed()),
            )
            .unwrap();

        Ok(sink.effects)
    }

    fn sync(
        &mut self,
        graph_proxy_id: ProxyGraphID,
        source_client_proxy_id: ProxyClientID,
        dest_client_proxy_id: ProxyClientID,
    ) -> Result<(), ModelError> {
        // Destination of the sync
        let mut request_state = self
            .clients
            .get(&dest_client_proxy_id)
            .expect("Could not get client")
            .state
            .borrow_mut();

        let response_metrics = self
            .metrics
            .get_mut(&source_client_proxy_id)
            .expect("Should return graph metrics")
            .get_mut(&graph_proxy_id)
            .expect("should return metrics");

        let mut sink = TestSink {
            sink_metrics: response_metrics,
            effects: vec![],
        };

        // Source of the sync
        let mut response_state = self
            .clients
            .get(&source_client_proxy_id)
            .expect("Could not get client")
            .state
            .borrow_mut();

        let storage_id = self
            .storage_ids
            .get(&(graph_proxy_id))
            .expect("Could not get storage id");

        unidirectional_sync(
            storage_id,
            &mut request_state,
            &mut response_state,
            &mut sink,
        )?;

        Ok(())
    }
}

fn unidirectional_sync<E: crypto::Engine>(
    storage_id: &GraphId,
    request_state: &mut ClientState<ModelEngine<E>, MemStorageProvider>,
    response_state: &mut ClientState<ModelEngine<E>, MemStorageProvider>,
    sink: &mut TestSink<'_>,
) -> Result<(), ModelError> {
    let mut request_syncer = SyncRequester::new(*storage_id, &mut Rng::new());
    let mut response_syncer = SyncResponder::new();
    assert!(request_syncer.ready());

    let mut request_trx = request_state.transaction(storage_id);

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

            sink.sink_metrics
                .update("bytes_synced", Metric::Count(len.try_into().unwrap()))
                .unwrap();

            if let Some(cmds) = request_syncer.receive(&buffer[..len])? {
                request_state.add_commands(&mut request_trx, sink, &cmds)?;
            };
        }
    }

    request_state
        .commit(&mut request_trx, sink)
        .expect("Should commit the transaction");

    Ok(())
}

#[test]
fn should_create_client_and_add_commands() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

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
}

#[test]
fn should_fail_duplicate_client_ids() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect_err("Should fail client creation if proxy_id is reused");
}

#[test]
fn should_fail_duplicate_graph_ids() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

    test_model
        .new_graph(1, 1)
        .expect_err("Should fail graph creation if proxy_id is reused");
}

#[test]
fn should_allow_multiple_graphs() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

    test_model
        .new_graph(2, 1)
        .expect("Should support the ability to add multiple graphs");
}

#[test]
fn should_sync_clients() {
    let mut test_model = TestModel::default();

    // Create client 1
    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

    test_model
        .action(1, 1, ("create", [Value::Int(3)].as_slice().into()))
        .expect("Should return effect");

    let effects = test_model
        .action(1, 1, ("increment", [Value::Int(1)].as_slice().into()))
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

    // Create client 2
    test_model
        .add_client(2, TEST_POLICY_1)
        .expect("Should create a client");

    // Sync client 2 from client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(2, 1, ("increment", [Value::Int(2)].as_slice().into()))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(6)),
        ],
    )];
    assert_eq!(effects, expected);

    let effects = test_model
        .action(2, 1, ("increment", [Value::Int(3)].as_slice().into()))
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

    // Sync client 1 from client 2 (2 -> 1)
    test_model.sync(1, 2, 1).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(1, 1, ("increment", [Value::Int(4)].as_slice().into()))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(13)),
        ],
    )];
    assert_eq!(effects, expected);

    // Sync client 2 with client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(2, 1, ("increment", [Value::Int(5)].as_slice().into()))
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(18)),
        ],
    )];
    assert_eq!(effects, expected);
}

#[test]
fn should_list_metrics() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

    test_model
        .action(1, 1, ("create", [Value::Int(3)].as_slice().into()))
        .expect("Should return effect");

    // Query all the metric keys
    let client_metrics_keys = test_model
        .list_metrics_keys(1, 1)
        .expect("Should return metrics keys");

    // Test correct keys exist
    assert!(client_metrics_keys.contains(&"step_count"));
    assert!(client_metrics_keys.contains(&"effect_count"));
    assert!(client_metrics_keys.contains(&"accepted_command_count"));
    // and don't exist
    assert!(!client_metrics_keys.contains(&"rejected_command_count"));

    // Add failing action. The test policy has a check that rejects a command if
    // the value is greater than 25.
    test_model
        .action(1, 1, ("increment", [Value::Int(30)].as_slice().into()))
        .expect_err("Should return effect");

    let client_metrics_keys = test_model
        .list_metrics_keys(1, 1)
        .expect("Should return metrics keys");
    assert!(client_metrics_keys.contains(&"rejected_command_count"));
}

#[test]
fn should_get_metrics() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

    test_model
        .action(1, 1, ("create", [Value::Int(3)].as_slice().into()))
        .expect("Should return effect");

    // Add failing action. The test policy has a check that rejects a command if
    // the value is greater than 25.
    test_model
        .action(1, 1, ("increment", [Value::Int(30)].as_slice().into()))
        .expect_err("Should return effect");

    // Should return metrics
    let steps = test_model.get_metric(1, 1, "step_count");
    assert_eq!(steps, Some(Metric::Count(3)));

    let effects = test_model.get_metric(1, 1, "effect_count");
    assert_eq!(effects, Some(Metric::Count(1)));

    let accepted = test_model.get_metric(1, 1, "accepted_command_count");
    assert_eq!(accepted, Some(Metric::Count(2)));

    let rejected = test_model.get_metric(1, 1, "rejected_command_count");
    assert_eq!(rejected, Some(Metric::Count(1)));

    // Should return None for nonexisting metric type
    let missing = test_model.get_metric(1, 1, "blerg!");
    assert_eq!(missing, None);

    // Should return None for nonexisting client
    let steps = test_model.get_metric(3, 1, "step_count");
    assert_eq!(steps, None);
}

#[test]
fn should_gather_action_execution_time_metrics() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

    test_model
        .action(1, 1, ("create", [Value::Int(3)].as_slice().into()))
        .expect("Should return effect");

    // Action execution time should be a Metric enum variant Duration
    let action_time = test_model.get_metric(1, 1, "action_exc_time");
    assert!(matches!(action_time, Some(Metric::Duration(_))));
}

#[test]
fn should_fail_to_update_incorrect_metric_type() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

    test_model
        .action(1, 1, ("create", [Value::Int(3)].as_slice().into()))
        .expect("Should return effect");

    let metrics = test_model
        .metrics
        .get_mut(&1)
        .expect("Should return graph metrics")
        .get_mut(&1)
        .expect("should return metrics");

    // "accepted_command_count" is of type Count
    // updating it with a Duration should return an error
    let metric = Metric::Duration(Duration::from_secs(5));
    metrics
        .update("accepted_command_count", metric)
        .expect_err("Should return error with mis-matched types");

    // "action_exc_time" is of type Duration
    // updating it with a Count should return an error
    let metric = Metric::Count(1);
    metrics
        .update("action_exc_time", metric)
        .expect_err("Should return error with mis-matched types");
}

#[test]
fn should_gather_sync_metrics() {
    let mut test_model = TestModel::default();

    // Create client 1
    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

    test_model
        .action(1, 1, ("create", [Value::Int(3)].as_slice().into()))
        .expect("Should return effect");

    test_model
        .action(1, 1, ("increment", [Value::Int(1)].as_slice().into()))
        .expect("Should return effect");

    // Create client 2
    test_model
        .add_client(2, TEST_POLICY_1)
        .expect("Should create a client");

    // Sync client 2 from client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Query client 1 metric keys after sync
    let client_metrics_keys = test_model
        .list_metrics_keys(1, 1)
        .expect("Should return metrics keys");
    // Ensure correct sync metrics are added
    assert!(client_metrics_keys.contains(&"bytes_synced"));

    // Get request sync byte length for client 1
    let sync_requested_byte_len = test_model.get_metric(1, 1, "bytes_synced");
    // The metric exists and is a count enum variant
    assert!(matches!(sync_requested_byte_len, Some(Metric::Count(_))));
    // and it is a number greater than zero
    if let Some(Metric::Count(length)) = sync_requested_byte_len {
        assert!(length > 0);
    }

    // Should return accepted command counts for client 1
    let accepted_command_count = test_model.get_metric(1, 1, "accepted_command_count");
    assert_eq!(accepted_command_count, Some(Metric::Count(6)));

    // Increment client 2 after syncing with client 1
    test_model
        .action(2, 1, ("increment", [Value::Int(2)].as_slice().into()))
        .expect("Should return effect");

    test_model
        .action(2, 1, ("increment", [Value::Int(3)].as_slice().into()))
        .expect("Should return effect");

    // Sync client 1 from client 2 (2 -> 1)
    test_model.sync(1, 2, 1).expect("Should sync clients");

    // Should return accepted command counts for client 1
    let client_1_accepted_command_count = test_model.get_metric(1, 1, "accepted_command_count");
    assert_eq!(client_1_accepted_command_count, Some(Metric::Count(6)));

    // Should return accepted command counts for client 2
    let client_2_accepted_command_count = test_model.get_metric(2, 1, "accepted_command_count");
    assert_eq!(client_2_accepted_command_count, Some(Metric::Count(4)));

    // Query client 2 metric keys after sync
    let client_metrics_keys = test_model
        .list_metrics_keys(2, 1)
        .expect("Should return metrics keys");
    // Ensure correct sync metrics are added
    assert!(client_metrics_keys.contains(&"bytes_synced"));

    // Should return accepted command counts for client 2
    let sync_requested_byte_len = test_model.get_metric(2, 1, "bytes_synced");
    // The metric exists and is a count enum variant
    assert!(matches!(sync_requested_byte_len, Some(Metric::Count(_))));
    // and it is a number greater than zero
    if let Some(Metric::Count(length)) = sync_requested_byte_len {
        assert!(length > 0);
    }

    // Increment client 2 after syncing with client 1
    test_model
        .action(1, 1, ("increment", [Value::Int(4)].as_slice().into()))
        .expect("Should return effect");

    // Sync client 2 with client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    test_model
        .action(2, 1, ("increment", [Value::Int(5)].as_slice().into()))
        .expect("Should return effect");

    // Should return accepted command counts for client 1
    let client_1_accepted_command_count = test_model.get_metric(1, 1, "accepted_command_count");
    assert_eq!(client_1_accepted_command_count, Some(Metric::Count(8)));

    // Should return accepted command counts for client 2
    let client_2_accepted_command_count = test_model.get_metric(2, 1, "accepted_command_count");
    assert_eq!(client_2_accepted_command_count, Some(Metric::Count(5)));
}

#[test]
fn should_sync_clients_with_duplicate_payloads() {
    let mut test_model = TestModel::default();

    test_model
        .add_client(1, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 1).expect("Should create a graph");

    let action = ("create", [Value::Int(1)].as_slice().into());
    let effects = test_model
        .action(1, 1, action)
        .expect("Should return effect");
    assert_eq!(effects.len(), 1);
    let expected = vec![(
        String::from("StuffHappened"),
        vec![
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::Int(2)),
            KVPair::new("x", Value::Int(1)),
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
            KVPair::new("x", Value::Int(2)),
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

    // Create client 2
    test_model
        .add_client(2, TEST_POLICY_1)
        .expect("Should create a client");

    // Sync client 2 from client 1 (1 -> 2)
    test_model.sync(1, 1, 2).expect("Should sync clients");

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
            KVPair::new("x", Value::Int(5)),
        ],
    )];
    assert_eq!(effects, expected);
}
