extern crate alloc;

use alloc::{borrow::Cow, collections::BTreeMap, string::String, vec::Vec};
use core::{cell::RefCell, matches, time::Duration};
use std::time::Instant;

use crypto::{default::DefaultEngine, Rng};
use policy_lang::lang::parse_policy_document;
use policy_vm::{compile_from_policy, ffi::FfiModule, KVPair, Value};
use runtime::{
    command::Id,
    engine::Sink,
    metrics::{Metric, MetricError, Metrics},
    storage::memory::MemStorageProvider,
    vm_policy::{ffi::FfiEnvelope, VmPolicy},
    ClientState, SyncRequester, SyncResponder, MAX_SYNC_MESSAGE_SIZE,
};

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
type ClientStorageIds = BTreeMap<(ProxyClientID, ProxyGraphID), Id>;
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
    ) -> Result<Option<Metric>, ModelError> {
        let metric = self
            .metrics
            .get(&client_proxy_id)
            .expect("Could not get client")
            .get(&graph_proxy_id)
            .expect("Could not get client metrics.")
            .metrics
            .get(&key);

        Ok(metric.copied())
    }
}

impl Model for TestModel {
    type Effects = Vec<ModelEffect>;
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
        let (eng, _) = DefaultEngine::from_entropy(Rng);
        let policy = VmPolicy::new(machine, eng, vec![Box::from(FfiEnvelope {})])
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
    ) -> Result<Self::Effects, ModelError> {
        if self.storage_ids.get(&(client_proxy_id, proxy_id)).is_some() {
            return Err(ModelError::DuplicateGraph);
        }

        let mut test_metrics = TestMetrics::default();
        let mut sink = TestSink {
            sink_metrics: &mut test_metrics,
            effects: vec![],
        };

        let mut state = self
            .clients
            .get_mut(&client_proxy_id)
            .expect("Could not get client")
            .state
            .borrow_mut();

        let storage_id = state
            .new_graph(&[0u8], Default::default(), &mut sink)
            .expect("could not create graph");

        self.storage_ids
            .insert((client_proxy_id, proxy_id), storage_id);

        let metrics = sink.sink_metrics.to_owned();
        let mut graph_metrics: GraphMetrics = BTreeMap::new();
        graph_metrics.insert(proxy_id, metrics);
        self.metrics.insert(client_proxy_id, graph_metrics);

        Ok(sink.effects)
    }

    fn action(
        &mut self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
        action: Self::Action<'_>,
    ) -> Result<Self::Effects, ModelError> {
        let action_exc_time = Instant::now();

        let storage_id = self
            .storage_ids
            .get(&(client_proxy_id, graph_proxy_id))
            .expect("Could not get storage id");

        let mut state = self
            .clients
            .get_mut(&client_proxy_id)
            .expect("Could not get client")
            .state
            .borrow_mut();

        let test_metrics = self
            .metrics
            .get_mut(&client_proxy_id)
            .expect("Should return graph metrics")
            .get_mut(&graph_proxy_id)
            .expect("should return metrics");

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

        let request_metrics = self
            .metrics
            .get_mut(&dest_client_proxy_id)
            .expect("Should return graph metrics")
            .get_mut(&graph_proxy_id)
            .expect("should return metrics");

        let mut sink = TestSink {
            sink_metrics: request_metrics,
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
            .get(&(source_client_proxy_id, graph_proxy_id))
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

fn unidirectional_sync<E: crypto::Engine + ?Sized>(
    storage_id: &Id,
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

    test_model
        .action(1, 1, ("increment", [Value::Int(1)].as_slice().into()))
        .expect("Should return effect");

    let effects = test_model
        .action(1, 1, ("increment", [Value::Int(5)].as_slice().into()))
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

    // Create client 2
    test_model
        .add_client(2, TEST_POLICY_1)
        .expect("Should create a client");

    test_model.new_graph(1, 2).expect("Should create a graph");

    // Sync client 2 with client 1
    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Increment client 2 after syncing with client 1
    let effects = test_model
        .action(2, 1, ("increment", [Value::Int(1)].as_slice().into()))
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

    let steps = test_model
        .get_metric(1, 1, "step_count")
        .expect("Should return steps metric");
    assert_eq!(steps, Some(Metric::Count(3)));

    let effects = test_model
        .get_metric(1, 1, "effect_count")
        .expect("Should return effects metrics");
    assert_eq!(effects, Some(Metric::Count(1)));

    let accepted = test_model
        .get_metric(1, 1, "accepted_command_count")
        .expect("Should return accepted metrics");
    assert_eq!(accepted, Some(Metric::Count(2)));

    let rejected = test_model
        .get_metric(1, 1, "rejected_command_count")
        .expect("Should not return non-existent metric");
    assert_eq!(rejected, Some(Metric::Count(1)));

    let missing = test_model
        .get_metric(1, 1, "blerg!")
        .expect("Should return None for non-existent metric");
    assert_eq!(missing, None);
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
    let action_time = test_model
        .get_metric(1, 1, "action_exc_time")
        .expect("Should return action execution time");
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

    test_model
        .action(1, 1, ("increment", [Value::Int(5)].as_slice().into()))
        .expect("Should return effect");

    test_model
        .add_client(2, TEST_POLICY_1)
        .expect("Should create a client");
    test_model.new_graph(1, 2).expect("Should create a graph");

    test_model.sync(1, 1, 2).expect("Should sync clients");

    // Query client 2 metric keys after sync
    let client_metrics_keys = test_model
        .list_metrics_keys(2, 1)
        .expect("Should return metrics keys");
    // Ensure correct sync metrics are added
    assert!(client_metrics_keys.contains(&"bytes_synced"));

    // Get request sync byte length for client 2
    let sync_requested_byte_len = test_model
        .get_metric(2, 1, "bytes_synced")
        .expect("Should return metric");

    // The metric exists and is a count enum variant
    assert!(matches!(sync_requested_byte_len, Some(Metric::Count(_))));
    // and it is a number greater than zero
    if let Some(Metric::Count(length)) = sync_requested_byte_len {
        assert!(length > 0);
    }
}