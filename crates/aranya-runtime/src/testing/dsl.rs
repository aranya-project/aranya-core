//! DSL tests.
//!
//! # Example
//!
//! If you're writing unit tests, the [`test_suite`] macro
//! expands to a bunch of Rust unit tests.
//!
//! ```
//! use aranya_runtime::{
//!     storage::linear::testing::MemStorageProvider,
//!     testing::dsl::{StorageBackend, test_suite},
//! };
//!
//! struct MemBackend;
//! impl StorageBackend for MemBackend {
//!     type StorageProvider = MemStorageProvider;
//!
//!     fn provider(&mut self, _client_id: u64) -> Self::StorageProvider {
//!         MemStorageProvider::default()
//!     }
//! }
//! test_suite!(|| MemBackend);
//! ```
//!
//! Otherwise, if you're writing integration tests, use
//! [`vectors::run_all`].
//!
//! ```
//! use aranya_runtime::{
//!     storage::linear::testing::MemStorageProvider,
//!     testing::dsl::{StorageBackend, vectors},
//! };
//!
//! struct MemBackend;
//! impl StorageBackend for MemBackend {
//!     type StorageProvider = MemStorageProvider;
//!
//!     fn provider(&mut self, _client_id: u64) -> Self::StorageProvider {
//!         MemStorageProvider::default()
//!     }
//! }
//! vectors::run_all(|| MemBackend).unwrap();
//! ```

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::unwrap_used)]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::{
    cell::RefCell,
    fmt::{self, Display},
    iter,
};
#[cfg(any(test, feature = "std"))]
use std::{env, fs};

use aranya_crypto::{Rng, dangerous::spideroak_crypto::csprng::rand::Rng as RandRng};
use buggy::{Bug, BugExt as _};
use rand::{SeedableRng as _, rngs::SmallRng};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::{
    Address, Bytes, COMMAND_RESPONSE_MAX, ClientError, ClientState, CmdId, Command as _,
    CommandExt as _, GraphId, Keys, Location, MAX_SYNC_MESSAGE_SIZE, MaxCut, MemSpill, PeerCache,
    PolicyError, Prior, Query as _, RuntimeBuffers, Segment as _, Storage, StorageError,
    StorageProvider, SyncError, SyncHello, SyncIncoming, SyncRequester, SyncResponder, Transaction,
    TraversalBuffer, TraversalBuffers,
    sync::wire::{SyncHelloType, SyncType},
    testing::{
        protocol::{TestActions, TestEffect, TestPolicyStore, TestSink},
        short_b58,
    },
};

/// Fact names written by the DSL test policies.
///
/// The DSL harness runs `TestPolicy` (see `testing::protocol`), whose only
/// fact write is `insert("payload", ...)` (in `origin_check_message`). The
/// VM test policy (`testing::vm`) writes `"Stuff"`. We enumerate these known
/// names because the [`Query`] API only supports lookups by a known fact name
/// (`query` / `query_prefix`); there is no API to enumerate fact names. For
/// the DSL tests this is FULL coverage of the merged fact state, since
/// `"payload"` is the only name those tests ever write.
const TEST_FACT_NAMES: &[&str] = &["payload", "Stuff", "seq", "stuff"];

fn default_repeat() -> u64 {
    1
}

fn default_max_syncs() -> u64 {
    1
}

fn default_max_cascade_depth() -> u64 {
    100
}

fn default_notify_interval() -> u64 {
    1
}

fn default_key_range() -> u64 {
    1
}

fn default_sync_interval() -> u64 {
    1
}

/// Tracks per-subscriber state for hello sync debouncing.
#[derive(Clone, Debug)]
struct HelloSub {
    /// Notify after this many graph changes.
    notify_interval: u64,
    /// Graph changes since last notification.
    changes_since_notify: u64,
}

/// Determines how GenerateGraph synchronizes clients.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SyncMethod {
    /// Explicit poll-based sync (existing behavior).
    Poll {
        /// Probability weight for generating a sync action.
        sync_chance: u64,
        /// Probability weight for generating a command action.
        add_command_chance: u64,
    },
    /// Hello notification-driven sync.
    HelloSync {
        /// Notify after this many graph changes (debounce).
        #[serde(default = "default_notify_interval")]
        notify_interval: u64,
        /// How clients are connected for hello notifications.
        #[serde(default)]
        topology: HelloTopology,
    },
    /// No syncing during command generation. Commands are distributed
    /// evenly (round-robin) across the participating clients and only
    /// propagated to the rest during convergence. Useful for benchmarking
    /// sync performance against a large graph.
    None {
        /// If true, client 0 participates in the round-robin distribution.
        /// If false, client 0 is excluded and commands are split across
        /// clients 1..N only.
        #[serde(default)]
        add_commands_to_client_zero: bool,
    },
    /// Deterministic tick-driven generation. On each tick, every client
    /// whose write interval divides the tick writes one command; then,
    /// if the tick is a sync tick, the peers sync bidirectionally.
    /// A branch forms whenever multiple clients write on the same tick,
    /// giving controlled branching. Uses no randomness, so the generated
    /// rule sequence is fully reproducible.
    Tick {
        /// Client `i` writes a command every `write_intervals[i]` ticks.
        /// An interval of 0 means the client never writes (pure
        /// subscriber). Length must equal `clients`; at least one entry
        /// must be nonzero.
        write_intervals: Vec<u64>,
        /// Bidirectional pairwise sync every `sync_interval` ticks.
        /// Ignored when `hello_notify_interval` is set.
        #[serde(default = "default_sync_interval")]
        sync_interval: u64,
        /// If set, sync via hello notifications instead of explicit
        /// per-tick pair syncs: the peers subscribe to each other with
        /// this notify (debounce) interval and sync only when notified
        /// of a change.
        #[serde(default)]
        hello_notify_interval: Option<u64>,
    },
}

/// Client connection topology for hello sync.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HelloTopology {
    /// Client 0 is the hub; all others subscribe to it and it subscribes to all.
    #[default]
    HubAndSpoke,
    /// Each client subscribes to the next: 0→1, 1→2, ..., N-1→0.
    Ring,
}

/// Dispatches the sync message contained in data.
/// This function is only for testing using polling. In production
/// usage the syncer implementation will handle this.
pub fn dispatch(
    data: &[u8],
    target: &mut [u8],
    provider: &mut impl StorageProvider,
    response_cache: &mut PeerCache,
    buffers: &mut TraversalBuffers,
) -> Result<usize, SyncError> {
    let len = match SyncIncoming::decode(data)? {
        SyncIncoming::Poll(poll) => {
            let mut response_syncer = SyncResponder::new();
            response_syncer.receive(poll)?;
            assert!(response_syncer.ready());
            response_syncer.poll(target, provider, response_cache, buffers)?
        }
        SyncIncoming::Subscribe(_) => unimplemented!(),
        SyncIncoming::Unsubscribe(_) => unimplemented!(),
        SyncIncoming::Push(_) => unimplemented!(),
        SyncIncoming::Hello(_) => unimplemented!(),
    };
    Ok(len)
}

/// Processes hello sync notifications cascading from a graph change.
///
/// Models the daemon's hello protocol: when a client's graph changes, each
/// subscriber is sent a wire-encoded `Hello` notification carrying the
/// publisher's advertised head ([`ClientState::hello_head`]: the head itself,
/// or the virtual synthetic merge of a multi-head set). A subscriber for
/// which the advertisement signals nothing new
/// ([`ClientState::should_sync_on_hello`]) does not sync; otherwise it syncs
/// from the publisher, and if it receives new data it becomes a "changed
/// client" whose own subscribers are notified. This repeats until no new
/// data flows or `max_depth` is exceeded.
#[allow(clippy::too_many_arguments)]
fn process_hello_notifications<SP: StorageProvider>(
    graph: u64,
    initial_changed: u64,
    subscriptions: &mut BTreeMap<(u64, u64), BTreeMap<u64, HelloSub>>,
    graph_id: GraphId,
    clients: &BTreeMap<u64, RefCell<ClientState<TestPolicyStore, SP>>>,
    client_heads: &mut BTreeMap<(u64, u64, u64), RefCell<PeerCache>>,
    sink: &mut TestSink,
    rt_buffers: &mut RuntimeBuffers<SP::Segment>,
    max_depth: u64,
) -> Result<(), TestError> {
    let mut changed: BTreeSet<u64> = BTreeSet::new();
    changed.insert(initial_changed);
    for depth in 0..max_depth {
        let mut next_changed: BTreeSet<u64> = BTreeSet::new();

        for &publisher in &changed {
            // Collect subscribers that are ready to be notified.
            let ready: Vec<u64> = match subscriptions.get_mut(&(graph, publisher)) {
                Some(subs) => subs
                    .iter_mut()
                    .filter_map(|(&subscriber, sub)| {
                        sub.changes_since_notify += 1;
                        if sub.changes_since_notify >= sub.notify_interval {
                            sub.changes_since_notify = 0;
                            Some(subscriber)
                        } else {
                            None
                        }
                    })
                    .collect(),
                None => continue,
            };

            for subscriber in ready {
                debug!(
                    depth,
                    publisher, subscriber, "hello sync: notifying subscriber"
                );

                // The publisher builds the notification the same way the
                // daemon does: a single head address on the wire. A
                // multi-head graph advertises its virtual synthetic head.
                let head = clients
                    .get(&publisher)
                    .ok_or(TestError::MissingClient)?
                    .borrow_mut()
                    .hello_head(graph_id)?;

                // Round-trip the notification through the wire format.
                let mut wire = [0u8; MAX_SYNC_MESSAGE_SIZE];
                let len = postcard::to_slice(
                    &SyncType::Hello(SyncHelloType::Hello { graph_id, head }),
                    &mut wire,
                )
                .map_err(SyncError::from)?
                .len();
                let SyncIncoming::Hello(SyncHello::Hello(notification)) =
                    SyncIncoming::decode(&wire[..len])?
                else {
                    buggy::bug!("hello notification decoded as a different message type");
                };

                let mut request_client = clients
                    .get(&subscriber)
                    .ok_or(TestError::MissingClient)?
                    .borrow_mut();

                // The subscriber only syncs if the advertised head signals
                // state it does not hold.
                let needs_sync = request_client.should_sync_on_hello(
                    notification.graph_id(),
                    notification.head(),
                    &mut rt_buffers.traversal.primary,
                )?;

                client_heads
                    .entry((graph, subscriber, publisher))
                    .or_default();
                client_heads
                    .entry((graph, publisher, subscriber))
                    .or_default();

                let mut received = 0;
                if needs_sync {
                    let mut request_cache = client_heads
                        .get(&(graph, subscriber, publisher))
                        .assume("cache must exist")?
                        .borrow_mut();
                    let mut response_cache = client_heads
                        .get(&(graph, publisher, subscriber))
                        .assume("cache must exist")?
                        .borrow_mut();
                    let mut response_client = clients
                        .get(&publisher)
                        .ok_or(TestError::MissingClient)?
                        .borrow_mut();

                    // The hello cascade needs committed state to serve
                    // onward, so commit per notification here.
                    let mut trx = request_client.transaction(graph_id);
                    let mut received_addrs = Vec::new();
                    loop {
                        let (_, exchange_received) = sync::<SP>(
                            &mut trx,
                            (&request_cache, &mut request_client),
                            (&mut response_cache, &mut response_client),
                            &mut received_addrs,
                            sink,
                            graph_id,
                            rt_buffers,
                        )?;
                        received += exchange_received;
                        if exchange_received == 0 {
                            break;
                        }
                    }
                    request_client.commit(trx, sink, rt_buffers, MemSpill::new)?;
                    request_client.update_heads(
                        graph_id,
                        received_addrs,
                        &mut request_cache,
                        &mut rt_buffers.traversal.primary,
                    )?;
                }

                // Track the advertised head in the subscriber's cache for the
                // publisher. A multi-head publisher advertises a virtual
                // merge that exists in no one's storage, so only locatable
                // commands go in the cache.
                if request_client.command_exists(
                    notification.graph_id(),
                    notification.head(),
                    &mut rt_buffers.traversal.primary,
                ) {
                    let mut request_cache = client_heads
                        .get(&(graph, subscriber, publisher))
                        .assume("cache must exist")?
                        .borrow_mut();
                    request_client.update_heads(
                        notification.graph_id(),
                        [notification.head()],
                        &mut request_cache,
                        &mut rt_buffers.traversal.primary,
                    )?;
                }

                if received > 0 {
                    debug!(
                        depth,
                        subscriber, received, "hello sync: subscriber received new data"
                    );
                    next_changed.insert(subscriber);
                }
            }
        }

        if next_changed.is_empty() {
            debug!(depth, "hello sync: cascade complete");
            return Ok(());
        }

        changed = next_changed;
    }

    #[allow(clippy::panic)]
    {
        panic!("hello sync cascade exceeded max depth of {max_depth}");
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TestRule {
    AddClient {
        id: u64,
    },
    NewGraph {
        client: u64,
        id: u64,
        policy: u64,
    },
    RemoveGraph {
        client: u64,
        id: u64,
    },
    Sync {
        graph: u64,
        client: u64,
        from: u64,
        must_send: Option<usize>,
        must_receive: Option<usize>,
        #[serde(default = "default_max_syncs")]
        max_syncs: u64,
    },
    AddExpectation(u64),
    AddExpectations {
        expectation: u64,
        repeat: u64,
    },
    ActionSet {
        client: u64,
        graph: u64,
        key: u64,
        value: u64,
        #[serde(default = "default_repeat")]
        repeat: u64,
        #[serde(default)]
        priority: u32,
    },
    ActionDelete {
        client: u64,
        graph: u64,
        key: u64,
        #[serde(default)]
        priority: u32,
    },
    ActionNoOp {
        client: u64,
        graph: u64,
        nonce: u64,
        #[serde(default)]
        priority: u32,
    },
    CompareGraphs {
        clienta: u64,
        clientb: u64,
        graph: u64,
        equal: bool,
    },
    PrintGraph {
        client: u64,
        graph: u64,
    },
    IgnoreExpectations {
        ignore: bool,
    },
    GenerateGraph {
        clients: u64,
        graph: u64,
        commands: u64,
        #[serde(default)]
        policy: u64,
        #[serde(default)]
        sync_client_zero: bool,
        sync_method: SyncMethod,
        /// Percent (0-100) of generated commands that delete a fact.
        #[serde(default, alias = "delete_chance")]
        delete_proportion: u64,
        /// Percent (0-100) of generated commands that are no-ops (no fact
        /// mutation). Produces segments with empty fact maps.
        #[serde(default, alias = "noop_chance")]
        noop_proportion: u64,
        /// Fact keys are drawn from `0..key_range`.
        #[serde(default = "default_key_range")]
        key_range: u64,
        /// Command priorities are drawn from `0..=max_priority`.
        #[serde(default)]
        max_priority: u32,
        /// Seed for the RNG driving generation, making the run
        /// repeatable. When absent, a random seed is drawn and
        /// reported so a failure can still be replayed.
        #[serde(default)]
        seed: Option<u64>,
    },
    SetupClientsAndGraph {
        clients: u64,
        graph: u64,
        policy: u64,
    },
    MaxCut {
        client: u64,
        graph: u64,
        max_cut: MaxCut,
    },
    VerifyGraphIds {
        client: u64,
        ids: Vec<u64>,
    },
    ConvergeAll {
        graph: u64,
        clients: u64,
        max_syncs: u64,
    },
    HelloSubscribe {
        client: u64,
        peer: u64,
        graph: u64,
        #[serde(default = "default_notify_interval")]
        notify_interval: u64,
    },
    HelloUnsubscribe {
        client: u64,
        peer: u64,
        graph: u64,
    },
    /// Asserts a client's graph holds exactly `count` heads. With lazy merges a
    /// divergent graph holds multiple heads; this checks the lazy property.
    HeadCount {
        client: u64,
        graph: u64,
        count: usize,
    },
}

impl Display for TestRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sync {
                graph,
                client,
                from,
                must_send: None,
                must_receive: None,
                max_syncs,
            } => write!(
                f,
                r#"{{"Sync": {{ "graph": {}, "client": {}, "from": {}, "max_syncs": {} }} }},"#,
                graph, client, from, max_syncs,
            ),
            Self::Sync {
                graph,
                client,
                from,
                must_send: None,
                must_receive: Some(must_receive),
                max_syncs,
            } => write!(
                f,
                r#"{{"Sync": {{ "graph": {}, "client": {}, "from": {}, "must_receive": {}, "max_syncs": {} }} }},"#,
                graph, client, from, must_receive, max_syncs,
            ),
            Self::Sync {
                graph,
                client,
                from,
                must_send: Some(must_send),
                must_receive: None,
                max_syncs,
            } => write!(
                f,
                r#"{{"Sync": {{ "graph": {}, "client": {}, "from": {}, "must_send": {}, "max_syncs": {} }} }},"#,
                graph, client, from, must_send, max_syncs,
            ),
            Self::Sync {
                graph,
                client,
                from,
                must_send: Some(must_send),
                must_receive: Some(must_receive),
                max_syncs,
            } => write!(
                f,
                r#"{{"Sync": {{ "graph": {}, "client": {}, "from": {}, "must_send": {}, "must_receive": {}, "max_syncs": {} }} }},"#,
                graph, client, from, must_send, must_receive, max_syncs,
            ),
            Self::ActionSet {
                client,
                graph,
                key,
                value,
                repeat,
                priority,
            } => write!(
                f,
                r#"{{"ActionSet": {{ "graph": {}, "client": {}, "key": {}, "value": {}, "repeat": {}, "priority": {} }} }},"#,
                graph, client, key, value, repeat, priority,
            ),
            Self::ActionDelete {
                client,
                graph,
                key,
                priority,
            } => write!(
                f,
                r#"{{"ActionDelete": {{ "graph": {}, "client": {}, "key": {}, "priority": {} }} }},"#,
                graph, client, key, priority,
            ),
            Self::ActionNoOp {
                client,
                graph,
                nonce,
                priority,
            } => write!(
                f,
                r#"{{"ActionNoOp": {{ "graph": {}, "client": {}, "nonce": {}, "priority": {} }} }},"#,
                graph, client, nonce, priority,
            ),
            Self::AddClient { id } => write!(f, r#"{{"AddClient": {{ "id": {} }} }},"#, id),
            Self::AddExpectation(value) => write!(f, r#"{{"AddExpectation": {} }},"#, value),
            Self::AddExpectations {
                expectation,
                repeat,
            } => write!(
                f,
                r#"{{"AddExpectations": {{ "expectation": {}, "repeat": {} }} }},"#,
                expectation, repeat,
            ),
            Self::CompareGraphs {
                clienta,
                clientb,
                graph,
                equal,
            } => write!(
                f,
                r#"{{"CompareGraphs": {{ "clienta": {}, "clientb": {}, "graph": {}, "equal": {} }} }},"#,
                clienta, clientb, graph, equal,
            ),
            Self::GenerateGraph {
                clients,
                graph,
                commands,
                policy,
                sync_client_zero,
                sync_method,
                delete_proportion,
                noop_proportion,
                key_range,
                max_priority,
                seed,
            } => write!(
                f,
                r#"{{"GenerateGraph": {{ "clients": {}, "graph": {}, "commands": {}, "policy": {}, "sync_client_zero": {}, "sync_method": "{:?}", "delete_proportion": {}, "noop_proportion": {}, "key_range": {}, "max_priority": {}, "seed": {} }} }},"#,
                clients,
                graph,
                commands,
                policy,
                sync_client_zero,
                sync_method,
                delete_proportion,
                noop_proportion,
                key_range,
                max_priority,
                seed.map_or_else(|| "null".into(), |s| s.to_string()),
            ),
            Self::IgnoreExpectations { ignore } => write!(
                f,
                r#"{{"IgnoreExpectations": {{ "ignore": {} }} }},"#,
                ignore,
            ),
            Self::MaxCut {
                client,
                graph,
                max_cut,
            } => write!(
                f,
                r#"{{"MaxCut": {{ "client": {}, "graph": {}, "max_cut": {} }} }},"#,
                client, graph, max_cut,
            ),
            Self::NewGraph { client, id, policy } => write!(
                f,
                r#"{{"NewGraph": {{ "client": {}, "id": {}, "policy": {} }} }},"#,
                client, id, policy,
            ),
            Self::RemoveGraph { client, id } => write!(
                f,
                r#"{{"RemoveGraph": {{ "client": {}, "id": {} }} }},"#,
                client, id,
            ),
            Self::PrintGraph { client, graph } => write!(
                f,
                r#"{{"PrintGraph": {{ "client": {}, "graph": {} }} }},"#,
                client, graph,
            ),
            Self::SetupClientsAndGraph {
                clients,
                graph,
                policy,
            } => write!(
                f,
                r#"{{"SetupClientsAndGraph": {{ "clients": {}, "graph": {}, "policy": {} }} }},"#,
                clients, graph, policy,
            ),
            Self::VerifyGraphIds { client, ids } => write!(
                f,
                r#"{{"VerifyGraphIds": {{ "client": {}, "ids": {:?} }} }},"#,
                client, ids
            ),
            Self::ConvergeAll {
                graph,
                clients,
                max_syncs,
            } => write!(
                f,
                r#"{{"ConvergeAll": {{ "graph": {}, "clients": {}, "max_syncs": {} }} }},"#,
                graph, clients, max_syncs,
            ),
            Self::HelloSubscribe {
                client,
                peer,
                graph,
                notify_interval,
            } => write!(
                f,
                r#"{{"HelloSubscribe": {{ "client": {}, "peer": {}, "graph": {}, "notify_interval": {} }} }},"#,
                client, peer, graph, notify_interval,
            ),
            Self::HelloUnsubscribe {
                client,
                peer,
                graph,
            } => write!(
                f,
                r#"{{"HelloUnsubscribe": {{ "client": {}, "peer": {}, "graph": {} }} }},"#,
                client, peer, graph,
            ),
            Self::HeadCount {
                client,
                graph,
                count,
            } => write!(
                f,
                r#"{{"HeadCount": {{ "client": {}, "graph": {}, "count": {} }} }},"#,
                client, graph, count,
            ),
        }
    }
}

/// An error result from a test.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // fields used only via `Debug`
pub enum TestError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error("missing client")]
    MissingClient,
    #[error("missing graph {0}")]
    MissingGraph(u64),
    #[error(transparent)]
    Bug(#[from] Bug),
}

/// Provides [`StorageProvider`] impls for testing.
///
/// This will probably end up replaced by the model work.
pub trait StorageBackend {
    /// The [`StorageProvider`].
    type StorageProvider: StorageProvider;
    /// Returns the provider for `client_id`.
    fn provider(&mut self, client_id: u64) -> Self::StorageProvider;
}

/// Randomly generates a set, delete, or no-op rule shaped by the
/// `GenerateGraph` knobs. `delete_proportion` and `noop_proportion` are percentages
/// (their sum at most 100); keys are drawn from `0..key_range` and
/// priorities from `0..=max_priority`.
fn gen_command_rule<R: RandRng>(
    rng: &mut R,
    client: u64,
    graph: u64,
    delete_proportion: u64,
    noop_proportion: u64,
    key_range: u64,
    max_priority: u32,
) -> TestRule {
    let key = rng.gen_range(0..key_range);
    let priority = if max_priority == 0 {
        0
    } else {
        rng.gen_range(0..=max_priority)
    };
    let roll = rng.gen_range(0..100);
    if noop_proportion > 0 && roll < noop_proportion {
        TestRule::ActionNoOp {
            client,
            graph,
            nonce: rng.r#gen(),
            priority,
        }
    } else if delete_proportion > 0 && roll < noop_proportion + delete_proportion {
        TestRule::ActionDelete {
            client,
            graph,
            key,
            priority,
        }
    } else {
        TestRule::ActionSet {
            client,
            graph,
            key,
            value: rng.gen_range(0..10),
            repeat: 1,
            priority,
        }
    }
}

/// Runs a particular test.
pub fn run_test<SB>(mut backend: SB, rules: &[TestRule]) -> Result<(), TestError>
where
    SB: StorageBackend,
{
    let actions: Vec<_> = rules
        .iter()
        .cloned()
        .flat_map(|rule| {
            match rule {
                TestRule::GenerateGraph {
                    clients,
                    graph,
                    commands,
                    policy,
                    sync_client_zero,
                    sync_method,
                    delete_proportion,
                    noop_proportion,
                    key_range,
                    max_priority,
                    seed,
                } => {
                    assert!(key_range > 0, "key_range must be at least 1");
                    assert!(
                        delete_proportion + noop_proportion <= 100,
                        "delete_proportion + noop_proportion are percentages of generated commands"
                    );
                    let seed = seed.unwrap_or_else(|| RandRng::r#gen(&mut Rng));
                    // Reported so a failing generated run can be replayed
                    // by setting `"seed"` on the `GenerateGraph` rule.
                    #[cfg(any(test, feature = "std"))]
                    eprintln!("GenerateGraph rng seed: {seed}");
                    debug!(seed, "GenerateGraph rng seed");
                    let mut rng = SmallRng::seed_from_u64(seed);
                    // Setup clients and graph first.
                    let mut generated_actions = Vec::new();
                    for i in 0..clients {
                        generated_actions.push(TestRule::AddClient { id: i });
                    }
                    generated_actions.push(TestRule::NewGraph {
                        client: 0,
                        id: graph,
                        policy,
                    });
                    for i in 1..clients {
                        generated_actions.push(TestRule::Sync {
                            graph,
                            client: i,
                            from: 0,
                            must_send: None,
                            must_receive: None,
                            max_syncs: 100000,
                        });
                    }
                    for i in 1..clients {
                        generated_actions.push(TestRule::CompareGraphs {
                            clienta: 0,
                            clientb: i,
                            graph,
                            equal: true,
                        });
                    }

                    match sync_method {
                        SyncMethod::Poll {
                            sync_chance,
                            add_command_chance,
                        } => {
                            let min_clients = if sync_client_zero { 2 } else { 3 };
                            assert!(
                                clients >= min_clients,
                                "There must be at least {min_clients} clients"
                            );
                            assert!(
                                add_command_chance > 0,
                                "There must be a positive command chance or it will never exit"
                            );
                            // Calculate the maximum number of syncs needed to send all commands.
                            // We add 100 to account for extra syncs needed for merge commands.
                            let max_syncs = (commands / COMMAND_RESPONSE_MAX as u64) + 100;
                            let command_ceiling: u64 = add_command_chance;
                            let sync_ceiling = command_ceiling + sync_chance;
                            generated_actions.push(TestRule::IgnoreExpectations { ignore: true });
                            let client_start = if sync_client_zero { 0 } else { 1 };
                            let mut count = 0;
                            // Randomly generate actions and syncs. This will create a graph with many branches.
                            while count < commands {
                                let client = rng.gen_range(client_start..clients);
                                match rng.gen_range(0..sync_ceiling) {
                                    x if x < command_ceiling => {
                                        generated_actions.push(gen_command_rule(
                                            &mut rng,
                                            client,
                                            graph,
                                            delete_proportion,
                                            noop_proportion,
                                            key_range,
                                            max_priority,
                                        ));
                                        count += 1;
                                    }
                                    _ => {
                                        let mut from = (client + 1) % clients;
                                        if !sync_client_zero && from == 0 {
                                            from += 1;
                                        }
                                        generated_actions.push(TestRule::Sync {
                                            graph,
                                            client,
                                            from,
                                            must_send: None,
                                            must_receive: None,
                                            max_syncs: 1,
                                        });
                                    }
                                }
                            }
                            // Converge all clients by syncing every pair in both
                            // directions until no client receives new commands.
                            generated_actions.push(TestRule::ConvergeAll {
                                graph,
                                clients,
                                max_syncs,
                            });
                            // Verify all graphs are identical after convergence.
                            for i in 1..clients {
                                generated_actions.push(TestRule::CompareGraphs {
                                    clienta: 0,
                                    clientb: i,
                                    graph,
                                    equal: true,
                                });
                            }
                            generated_actions.push(TestRule::IgnoreExpectations { ignore: false });
                            generated_actions
                        }
                        SyncMethod::HelloSync {
                            notify_interval,
                            topology,
                        } => {
                            assert!(clients >= 2, "HelloSync requires at least 2 clients");
                            let max_syncs = (commands / COMMAND_RESPONSE_MAX as u64) + 100;

                            match topology {
                                HelloTopology::HubAndSpoke => {
                                    // Client 0 is the hub; all others subscribe
                                    // to it and it subscribes to all.
                                    for i in 1..clients {
                                        generated_actions.push(TestRule::HelloSubscribe {
                                            client: i,
                                            peer: 0,
                                            graph,
                                            notify_interval,
                                        });
                                        generated_actions.push(TestRule::HelloSubscribe {
                                            client: 0,
                                            peer: i,
                                            graph,
                                            notify_interval,
                                        });
                                    }
                                }
                                HelloTopology::Ring => {
                                    // Each client subscribes to the next:
                                    // 0→1, 1→2, ..., N-1→0.
                                    for i in 0..clients {
                                        let next = (i + 1) % clients;
                                        generated_actions.push(TestRule::HelloSubscribe {
                                            client: i,
                                            peer: next,
                                            graph,
                                            notify_interval,
                                        });
                                    }
                                }
                            }

                            generated_actions.push(TestRule::IgnoreExpectations { ignore: true });

                            let mut count = 0;

                            // Generate rounds. Each round, every client
                            // adds a command.
                            while count < commands {
                                for client in 0..clients {
                                    generated_actions.push(gen_command_rule(
                                        &mut rng,
                                        client,
                                        graph,
                                        delete_proportion,
                                        noop_proportion,
                                        key_range,
                                        max_priority,
                                    ));
                                    count += 1;
                                    if count >= commands {
                                        break;
                                    }
                                }
                            }

                            // Converge all clients as safety net.
                            generated_actions.push(TestRule::ConvergeAll {
                                graph,
                                clients,
                                max_syncs,
                            });
                            // Verify all graphs are identical.
                            for i in 1..clients {
                                generated_actions.push(TestRule::CompareGraphs {
                                    clienta: 0,
                                    clientb: i,
                                    graph,
                                    equal: true,
                                });
                            }
                            generated_actions.push(TestRule::IgnoreExpectations { ignore: false });
                            generated_actions
                        }
                        SyncMethod::Tick {
                            write_intervals,
                            sync_interval,
                            hello_notify_interval,
                        } => {
                            assert!(
                                clients == 2,
                                "Tick sync currently supports exactly 2 clients"
                            );
                            assert_eq!(
                                write_intervals.len(),
                                clients as usize,
                                "write_intervals must have one entry per client"
                            );
                            assert!(
                                write_intervals.iter().any(|&interval| interval >= 1),
                                "at least one write interval must be nonzero"
                            );
                            assert!(sync_interval >= 1, "sync_interval must be at least 1");
                            if let Some(notify_interval) = hello_notify_interval {
                                assert!(
                                    notify_interval >= 1,
                                    "hello_notify_interval must be at least 1"
                                );
                                // The peers subscribe to each other; syncs are
                                // then driven by change notifications instead
                                // of explicit Sync rules.
                                for client in 0..clients {
                                    let peer = (client + 1) % clients;
                                    generated_actions.push(TestRule::HelloSubscribe {
                                        client,
                                        peer,
                                        graph,
                                        notify_interval,
                                    });
                                }
                            }
                            let max_syncs = (commands / COMMAND_RESPONSE_MAX as u64) + 100;

                            generated_actions.push(TestRule::IgnoreExpectations { ignore: true });

                            let mut count = 0;
                            let mut tick: u64 = 0;
                            while count < commands {
                                tick += 1;
                                // Writes first: clients due on the same tick
                                // commit on the same head, creating a branch.
                                for (i, &interval) in write_intervals.iter().enumerate() {
                                    if count < commands && tick.is_multiple_of(interval) {
                                        generated_actions.push(TestRule::ActionSet {
                                            client: i as u64,
                                            graph,
                                            key: 0,
                                            value: tick % 10,
                                            repeat: 1,
                                            priority: 0,
                                        });
                                        count += 1;
                                    }
                                }
                                // Then sync both directions; the receiver of
                                // two heads commits a merge and the back-sync
                                // propagates it. With hello sync the runtime
                                // syncs on notification instead.
                                if hello_notify_interval.is_none()
                                    && tick.is_multiple_of(sync_interval)
                                {
                                    for client in 0..clients {
                                        let from = (client + 1) % clients;
                                        generated_actions.push(TestRule::Sync {
                                            graph,
                                            client,
                                            from,
                                            must_send: None,
                                            must_receive: None,
                                            max_syncs: 1,
                                        });
                                    }
                                }
                            }

                            generated_actions.push(TestRule::ConvergeAll {
                                graph,
                                clients,
                                max_syncs,
                            });
                            for i in 1..clients {
                                generated_actions.push(TestRule::CompareGraphs {
                                    clienta: 0,
                                    clientb: i,
                                    graph,
                                    equal: true,
                                });
                            }
                            generated_actions.push(TestRule::IgnoreExpectations { ignore: false });
                            generated_actions
                        }
                        SyncMethod::None {
                            add_commands_to_client_zero,
                        } => {
                            assert!(clients >= 2, "None sync requires at least 2 clients");
                            let max_syncs = (commands / COMMAND_RESPONSE_MAX as u64) + 100;
                            let participating: Vec<u64> = if add_commands_to_client_zero {
                                (0..clients).collect()
                            } else {
                                (1..clients).collect()
                            };

                            generated_actions.push(TestRule::IgnoreExpectations { ignore: true });

                            for i in 0..commands {
                                let client = participating[(i as usize) % participating.len()];
                                generated_actions.push(gen_command_rule(
                                    &mut rng,
                                    client,
                                    graph,
                                    delete_proportion,
                                    noop_proportion,
                                    key_range,
                                    max_priority,
                                ));
                            }

                            generated_actions.push(TestRule::ConvergeAll {
                                graph,
                                clients,
                                max_syncs,
                            });
                            for i in 1..clients {
                                generated_actions.push(TestRule::CompareGraphs {
                                    clienta: 0,
                                    clientb: i,
                                    graph,
                                    equal: true,
                                });
                            }
                            generated_actions.push(TestRule::IgnoreExpectations { ignore: false });
                            generated_actions
                        }
                    }
                }
                TestRule::SetupClientsAndGraph {
                    clients,
                    graph,
                    policy,
                } => {
                    let mut generated_actions = Vec::new();
                    for i in 0..clients {
                        generated_actions.push(TestRule::AddClient { id: i });
                    }
                    generated_actions.push(TestRule::NewGraph {
                        client: 0,
                        id: graph,
                        policy,
                    });
                    for i in 1..clients {
                        generated_actions.push(TestRule::Sync {
                            graph,
                            client: i,
                            from: 0,
                            must_send: None,
                            must_receive: None,
                            max_syncs: 100000,
                        });
                    }
                    for i in 1..clients {
                        generated_actions.push(TestRule::CompareGraphs {
                            clienta: 0,
                            clientb: i,
                            graph,
                            equal: true,
                        });
                    }
                    generated_actions
                }
                _ => vec![rule],
            }
        })
        .collect();

    // Check if we should dump generated rules to a file for debugging
    #[cfg(any(test, feature = "std"))]
    if let Ok(dump_path) = env::var("DUMP_GENERATED_RULES") {
        let json = serde_json::to_string_pretty(&actions).unwrap();
        // If path is relative and doesn't start with ./, save to testdata directory
        let final_path = if dump_path.starts_with('/') || dump_path.starts_with("./") {
            // Absolute or explicit relative path, use as-is
            dump_path
        } else {
            // Relative path, save to testdata directory
            let testdata_dir = format!("{}/src/testing/testdata", env!("CARGO_MANIFEST_DIR"));
            // Create testdata directory if it doesn't exist
            fs::create_dir_all(&testdata_dir).unwrap();
            format!("{}/{}", testdata_dir, dump_path)
        };
        fs::write(&final_path, json).unwrap();
        eprintln!(
            "[DUMP] Dumped {} generated rules to {}",
            actions.len(),
            final_path
        );
        debug!("Dumped generated rules to {}", final_path);
    }

    let mut graphs = BTreeMap::new();
    let mut clients = BTreeMap::new();

    let mut sink = TestSink::new();
    // Store all known heads for each client.
    // BtreeMap<(graph, caching_client, cached_client) RefCell<PeerCache>>
    let mut client_heads: BTreeMap<(u64, u64, u64), RefCell<PeerCache>> = BTreeMap::new();
    let mut rt_buffers = RuntimeBuffers::<<SB::StorageProvider as StorageProvider>::Segment>::new();
    let mut subscriptions: BTreeMap<(u64, u64), BTreeMap<u64, HelloSub>> = BTreeMap::new();

    for rule in actions {
        debug!(?rule);

        match rule {
            TestRule::AddClient { id } => {
                let policy_store = TestPolicyStore::new();
                let storage = backend.provider(id);

                let state = ClientState::new(policy_store, storage);
                clients.insert(id, RefCell::new(state));
            }
            TestRule::NewGraph { client, id, policy } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();
                let policy_data = policy.to_be_bytes();
                let graph_id = state.new_graph(
                    policy_data.as_slice(),
                    TestActions::Init(policy),
                    &mut sink,
                )?;

                graphs.insert(id, graph_id);

                assert_eq!(0, sink.count());
            }
            TestRule::RemoveGraph { client, id } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();
                let graph_id = graphs.get(&id).ok_or(TestError::MissingGraph(id))?;
                state.remove_graph(*graph_id)?;

                assert_eq!(0, sink.count());
            }
            TestRule::Sync {
                client,
                graph,
                from,
                must_send,
                must_receive,
                max_syncs,
            } => {
                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                let mut total_sent = 0;
                let mut total_received = 0;
                // Scope the client borrows so they are released before the
                // hello cascade below re-borrows the same clients.
                {
                    let mut request_client = clients
                        .get(&client)
                        .ok_or(TestError::MissingClient)?
                        .borrow_mut();
                    let mut response_client = clients
                        .get(&from)
                        .ok_or(TestError::MissingClient)?
                        .borrow_mut();

                    // One transaction held open across every exchange in this Sync,
                    // committed once after the loop (one fact-cache braid instead of
                    // one per exchange).
                    let mut trx = request_client.transaction(*graph_id);
                    let mut received_addrs = Vec::new();
                    client_heads.entry((graph, client, from)).or_default();
                    client_heads.entry((graph, from, client)).or_default();
                    for _ in 0..max_syncs {
                        let request_cache = client_heads
                            .get(&(graph, client, from))
                            .assume("cache must exist")?
                            .borrow();
                        let mut response_cache = client_heads
                            .get(&(graph, from, client))
                            .assume("cache must exist")?
                            .borrow_mut();

                        let (sent, received) = sync::<<SB as StorageBackend>::StorageProvider>(
                            &mut trx,
                            (&request_cache, &mut request_client),
                            (&mut response_cache, &mut response_client),
                            &mut received_addrs,
                            &mut sink,
                            *graph_id,
                            &mut rt_buffers,
                        )?;
                        total_received += received;
                        total_sent += sent;
                        // Break when no commands are received, meaning the requester has caught up
                        if received == 0 {
                            break;
                        }
                    }
                    request_client.commit(trx, &mut sink, &mut rt_buffers, MemSpill::new)?;
                    let mut request_cache = client_heads
                        .get(&(graph, client, from))
                        .assume("cache must exist")?
                        .borrow_mut();
                    request_client.update_heads(
                        *graph_id,
                        received_addrs,
                        &mut request_cache,
                        &mut rt_buffers.traversal.primary,
                    )?;
                }

                if let Some(mr) = must_receive {
                    assert_eq!(total_received, mr);
                }

                if let Some(ms) = must_send {
                    assert_eq!(total_sent, ms);
                }

                if total_received > 0 && !subscriptions.is_empty() {
                    let graph_id = *graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                    process_hello_notifications(
                        graph,
                        client,
                        &mut subscriptions,
                        graph_id,
                        &clients,
                        &mut client_heads,
                        &mut sink,
                        &mut rt_buffers,
                        default_max_cascade_depth(),
                    )?;
                }

                assert_eq!(0, sink.count());
            }

            TestRule::AddExpectation(expectation) => {
                sink.add_expectation(TestEffect::Got(expectation));
            }

            TestRule::AddExpectations {
                expectation,
                repeat,
            } => {
                for _ in 0..repeat {
                    sink.add_expectation(TestEffect::Got(expectation));
                }
            }

            TestRule::ActionSet {
                client,
                graph,
                key,
                value,
                repeat,
                priority,
            } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();

                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                for _ in 0..repeat {
                    let set = TestActions::SetValuePriority(key, value, priority);
                    state.action(*graph_id, &mut sink, set, &mut rt_buffers, MemSpill::new)?;
                }

                assert_eq!(0, sink.count());

                if !subscriptions.is_empty() {
                    let graph_id = *graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                    process_hello_notifications(
                        graph,
                        client,
                        &mut subscriptions,
                        graph_id,
                        &clients,
                        &mut client_heads,
                        &mut sink,
                        &mut rt_buffers,
                        default_max_cascade_depth(),
                    )?;
                    assert_eq!(0, sink.count());
                }
            }

            TestRule::ActionDelete {
                client,
                graph,
                key,
                priority,
            } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();

                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                state.action(
                    *graph_id,
                    &mut sink,
                    TestActions::DeleteValue(key, priority),
                    &mut rt_buffers,
                    MemSpill::new,
                )?;

                assert_eq!(0, sink.count());

                if !subscriptions.is_empty() {
                    let graph_id = *graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                    process_hello_notifications(
                        graph,
                        client,
                        &mut subscriptions,
                        graph_id,
                        &clients,
                        &mut client_heads,
                        &mut sink,
                        &mut rt_buffers,
                        default_max_cascade_depth(),
                    )?;
                    assert_eq!(0, sink.count());
                }
            }

            TestRule::ActionNoOp {
                client,
                graph,
                nonce,
                priority,
            } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();

                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                state.action(
                    *graph_id,
                    &mut sink,
                    TestActions::NoOp(nonce, priority),
                    &mut rt_buffers,
                    MemSpill::new,
                )?;

                assert_eq!(0, sink.count());

                if !subscriptions.is_empty() {
                    let graph_id = *graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                    process_hello_notifications(
                        graph,
                        client,
                        &mut subscriptions,
                        graph_id,
                        &clients,
                        &mut client_heads,
                        &mut sink,
                        &mut rt_buffers,
                        default_max_cascade_depth(),
                    )?;
                    assert_eq!(0, sink.count());
                }
            }

            TestRule::PrintGraph { client, graph } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();

                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                let storage = state.provider().get_storage(*graph_id)?;
                for head in storage.get_heads()?.iter() {
                    print_graph(storage, head.location(), &mut rt_buffers.traversal.primary)?;
                }
            }

            TestRule::CompareGraphs {
                clienta,
                clientb,
                graph,
                equal,
            } => {
                let mut state_a = clients
                    .get(&clienta)
                    .ok_or(TestError::MissingClient)?
                    .borrow_mut();

                let mut state_b = clients
                    .get(&clientb)
                    .ok_or(TestError::MissingClient)?
                    .borrow_mut();

                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                let storage_a = state_a.provider().get_storage(*graph_id)?;
                let storage_b = state_b.provider().get_storage(*graph_id)?;

                let same = graph_eq(storage_a, storage_b);
                if same != equal {
                    debug!("Graph A (client {})", clienta);
                    let mut cmds_a = BTreeSet::new();
                    for head in storage_a.get_heads()?.iter() {
                        cmds_a.extend(print_graph(
                            storage_a,
                            head.location(),
                            &mut rt_buffers.traversal.primary,
                        )?);
                    }
                    debug!("Graph B (client {})", clientb);
                    let mut cmds_b = BTreeSet::new();
                    for head in storage_b.get_heads()?.iter() {
                        cmds_b.extend(print_graph(
                            storage_b,
                            head.location(),
                            &mut rt_buffers.traversal.primary,
                        )?);
                    }

                    // Compare command sets
                    let only_in_a: Vec<_> = cmds_a.difference(&cmds_b).collect();
                    let only_in_b: Vec<_> = cmds_b.difference(&cmds_a).collect();

                    debug!("Commands only in Graph A: {} commands", only_in_a.len());
                    for &cmd in &only_in_a {
                        debug!("  Only in A: {}", short_b58(*cmd));
                    }
                    debug!("Commands only in Graph B: {} commands", only_in_b.len());
                    for &cmd in &only_in_b {
                        debug!("  Only in B: {}", short_b58(*cmd));
                    }
                }
                // `graph_eq` also asserts the merged fact state matches (via
                // `fact_cache_eq`), so equal graphs imply equal fact DBs.
                assert_eq!(equal, same);
            }
            TestRule::MaxCut {
                client,
                graph,
                max_cut,
            } => {
                let mut state = clients
                    .get(&client)
                    .ok_or(TestError::MissingClient)?
                    .borrow_mut();
                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                let storage = state.provider().get_storage(*graph_id)?;
                // Lazy merges keep the graph multi-head, so compare against the
                // greatest max_cut across all heads (the depth of the graph).
                let actual = storage
                    .get_heads()?
                    .iter()
                    .map(|la| la.max_cut)
                    .max()
                    .assume("graph has at least one head")?;
                assert_eq!(max_cut, actual);
            }
            TestRule::ConvergeAll {
                graph,
                clients: client_count,
                max_syncs,
            } => {
                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                // One transaction per client, held open across an entire outer
                // pass (the full mesh of i<->j exchanges) so a client's whole
                // catch-up from every peer in a pass is one fact-cache braid
                // instead of one per exchange. We commit at the END OF EACH
                // PASS, not at the very end: the responder serves from COMMITTED
                // storage (`get_heads`), so an intermediate node can only relay
                // data it received in a prior pass once that data is committed.
                // Committing per pass preserves the iterative-convergence
                // semantics while still collapsing the heavy initial fetch
                // (which happens within a single pass) to one braid.
                let mut trxs: Vec<
                    Option<Transaction<<SB as StorageBackend>::StorageProvider, TestPolicyStore>>,
                > = (0..client_count).map(|_| None).collect();

                loop {
                    let mut any_received = false;
                    // Received addresses per (requester, responder) pair, used
                    // to advance the persistent caches after this pass commits.
                    let mut pass_received: BTreeMap<_, Vec<Address>> = BTreeMap::new();
                    for i in 0..client_count {
                        for j in 0..client_count {
                            if i == j {
                                continue;
                            }

                            let mut request_client = clients
                                .get(&i)
                                .ok_or(TestError::MissingClient)?
                                .borrow_mut();
                            let mut response_client = clients
                                .get(&j)
                                .ok_or(TestError::MissingClient)?
                                .borrow_mut();

                            let slot = trxs.get_mut(i as usize).assume("trx slot exists")?;
                            if slot.is_none() {
                                *slot = Some(request_client.transaction(*graph_id));
                            }
                            let request_trx = slot.as_mut().assume("trx just created")?;

                            let received_addrs = pass_received.entry((i, j)).or_default();
                            for _ in 0..max_syncs {
                                client_heads.entry((graph, i, j)).or_default();
                                client_heads.entry((graph, j, i)).or_default();
                                let request_cache = client_heads
                                    .get(&(graph, i, j))
                                    .assume("cache must exist")?
                                    .borrow();
                                let mut response_cache = client_heads
                                    .get(&(graph, j, i))
                                    .assume("cache must exist")?
                                    .borrow_mut();

                                let (_, received) = sync::<<SB as StorageBackend>::StorageProvider>(
                                    request_trx,
                                    (&request_cache, &mut request_client),
                                    (&mut response_cache, &mut response_client),
                                    received_addrs,
                                    &mut sink,
                                    *graph_id,
                                    &mut rt_buffers,
                                )?;

                                if received > 0 {
                                    any_received = true;
                                }
                                if received == 0 {
                                    break;
                                }
                            }
                        }
                    }

                    // Commit each client's accumulated transaction for this pass
                    // so the data becomes visible to serve onward next pass.
                    for i in 0..client_count {
                        if let Some(trx) =
                            trxs.get_mut(i as usize).assume("trx slot exists")?.take()
                        {
                            let mut client = clients
                                .get(&i)
                                .ok_or(TestError::MissingClient)?
                                .borrow_mut();
                            client.commit(trx, &mut sink, &mut rt_buffers, MemSpill::new)?;
                        }
                    }

                    // Now that the pass is committed, advance each pair's
                    // persistent cache with what was received.
                    for ((i, j), addrs) in pass_received {
                        if addrs.is_empty() {
                            continue;
                        }
                        let mut client = clients
                            .get(&i)
                            .ok_or(TestError::MissingClient)?
                            .borrow_mut();
                        let mut request_cache = client_heads
                            .get(&(graph, i, j))
                            .assume("cache must exist")?
                            .borrow_mut();
                        client.update_heads(
                            *graph_id,
                            addrs,
                            &mut request_cache,
                            &mut rt_buffers.traversal.primary,
                        )?;
                    }

                    if !any_received {
                        break;
                    }
                }

                assert_eq!(0, sink.count());
            }
            TestRule::IgnoreExpectations { ignore } => sink.ignore_expectations(ignore),
            TestRule::VerifyGraphIds { client, ids } => {
                let mut state = clients
                    .get(&client)
                    .ok_or(TestError::MissingClient)?
                    .borrow_mut();

                let actual_ids: BTreeSet<GraphId> = state
                    .provider()
                    .list_graph_ids()
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();

                let expected_ids: BTreeSet<GraphId> = ids.iter().map(|id| graphs[id]).collect();

                assert_eq!(actual_ids, expected_ids);
            }
            TestRule::HelloSubscribe {
                client,
                peer,
                graph,
                notify_interval,
            } => {
                debug!(client, peer, graph, notify_interval, "hello subscribe");
                subscriptions.entry((graph, peer)).or_default().insert(
                    client,
                    HelloSub {
                        notify_interval,
                        changes_since_notify: 0,
                    },
                );
            }
            TestRule::HelloUnsubscribe {
                client,
                peer,
                graph,
            } => {
                debug!(client, peer, graph, "hello unsubscribe");
                if let Some(subs) = subscriptions.get_mut(&(graph, peer)) {
                    subs.remove(&client);
                }
            }
            TestRule::HeadCount {
                client,
                graph,
                count,
            } => {
                let mut state = clients
                    .get(&client)
                    .ok_or(TestError::MissingClient)?
                    .borrow_mut();
                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                let storage = state.provider().get_storage(*graph_id)?;
                let actual = storage.get_heads()?.len();
                assert_eq!(
                    count, actual,
                    "client {client} graph {graph}: expected {count} heads, got {actual}"
                );
            }
            _ => {}
        }
    }

    Ok(())
}

/// Minimizes a failing test using delta debugging.
///
/// This function takes a test that is known to fail and systematically
/// removes commands to find a minimal failing test case. It operates
/// only on the "interesting" section between IgnoreExpectations markers and the convergence phase.
/// The convergence phase is defined as the first Sync with max_syncs > 10.
/// The interesting section is defined as the section between IgnoreExpectations markers.
/// The interesting section is then minimized using delta debugging.
/// The minimized test is then run and if it fails, the process is repeated.
/// The process is repeated until the test passes.
/// The minimized test is then returned.
///
/// This function is used to minimize failing tests for debugging purposes.
#[cfg(any(test, feature = "std"))]
pub fn minimize_test<SB, F>(backend_factory: F, rules: &[TestRule]) -> Vec<TestRule>
where
    SB: StorageBackend,
    F: FnMut() -> SB,
{
    use std::{cell::RefCell, panic, rc::Rc, time::Instant};

    // Wrap the factory in an Rc<RefCell> so we can use it across catch_unwind
    let factory_cell = Rc::new(RefCell::new(backend_factory));

    // Helper to check if a test fails (including panics)
    let test_fails = |rules: &[TestRule]| -> bool {
        let factory = Rc::clone(&factory_cell);
        let rules = rules.to_vec();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(move || {
            let backend = factory.borrow_mut()();
            run_test(backend, &rules)
        }));
        result.is_err() || matches!(result, Ok(Err(_)))
    };

    // First, verify the test actually fails
    if !test_fails(rules) {
        println!("WARNING: Test does not fail, returning original rules");
        return rules.to_vec();
    }

    // Find the interesting section (between IgnoreExpectations)
    let mut start_idx = 0;
    let mut end_idx = rules.len();

    for (i, rule) in rules.iter().enumerate() {
        if matches!(rule, TestRule::IgnoreExpectations { ignore: true }) {
            start_idx = i + 1;
            break;
        }
    }

    for (i, rule) in rules.iter().enumerate().skip(start_idx) {
        if matches!(rule, TestRule::IgnoreExpectations { ignore: false }) {
            end_idx = i;
            break;
        }
    }

    // Find the convergence phase which should be preserved.
    // The GenerateGraph rule creates either a ConvergeAll or a distinctive
    // Sync with high max_syncs before the verification CompareGraphs.
    // We look for ConvergeAll or a Sync with max_syncs > 10 as the start
    // of convergence.
    let mut convergence_idx = end_idx;
    for (i, rule) in rules.iter().enumerate().skip(start_idx) {
        match rule {
            TestRule::ConvergeAll { .. } => {
                convergence_idx = i;
                break;
            }
            TestRule::Sync { max_syncs, .. } if *max_syncs > 10 => {
                convergence_idx = i;
                break;
            }
            _ => {}
        }
    }

    // If we didn't find a convergence marker, fall back to looking for CompareGraphs
    if convergence_idx == end_idx {
        for (i, rule) in rules.iter().enumerate().skip(start_idx) {
            if matches!(rule, TestRule::CompareGraphs { .. }) {
                convergence_idx = i;
                break;
            }
        }
    }

    let prefix: Vec<_> = rules[..start_idx].to_vec();
    let mut interesting: Vec<_> = rules[start_idx..convergence_idx].to_vec();
    let suffix: Vec<_> = rules[convergence_idx..].to_vec();

    let start_time = Instant::now();
    let mut iterations = 0;

    // Delta debugging (ddmin) algorithm
    let mut granularity = 2;
    while granularity <= interesting.len() {
        let chunk_size = interesting.len() / granularity;
        if chunk_size == 0 {
            break;
        }

        let mut progress = false;

        // Try removing each chunk
        for i in 0..granularity {
            let start = i * chunk_size;
            let end = if i == granularity - 1 {
                interesting.len()
            } else {
                (i + 1) * chunk_size
            };

            // Create test without this chunk
            let mut test_rules = prefix.clone();
            test_rules.extend_from_slice(&interesting[..start]);
            test_rules.extend_from_slice(&interesting[end..]);
            test_rules.extend_from_slice(&suffix);

            iterations += 1;
            if test_fails(&test_rules) {
                // Still fails! Keep this reduction
                interesting = [&interesting[..start], &interesting[end..]].concat();
                println!(
                    "Reduced to {} interesting rules (removed chunk {}/{}, granularity {})",
                    interesting.len(),
                    i + 1,
                    granularity,
                    granularity
                );
                progress = true;
                break;
            }
        }

        if progress {
            // Start over with coarser granularity
            granularity = 2;
        } else {
            // Try finer granularity
            granularity *= 2;
        }
    }

    let elapsed = start_time.elapsed();
    let mut result = prefix;
    result.extend(interesting);
    result.extend(suffix);

    println!("Minimization complete!");
    println!("  Original: {} rules", rules.len());
    println!("  Minimal:  {} rules", result.len());
    println!("  Iterations: {}", iterations);
    println!("  Time: {:?}", elapsed);

    result
}

/// Perform a single sync exchange, ingesting received commands into the
/// caller-owned `request_trx` (held open across many exchanges so a whole
/// graph is committed once instead of per exchange).
///
/// Does NOT commit. Instead, after ingesting, it flushes the open transaction
/// and advances the requester's `PeerCache` from the transaction's accumulated
/// frontier (committed + received-but-uncommitted tips). `get_commands`
/// incorporates `peer_cache.heads()`, so this is what makes progressive
/// multi-exchange fetch advance without a per-exchange commit.
fn sync<SP: StorageProvider>(
    request_trx: &mut Transaction<SP, TestPolicyStore>,
    (request_cache, request_state): (&PeerCache, &mut ClientState<TestPolicyStore, SP>),
    (response_cache, response_state): (&mut PeerCache, &mut ClientState<TestPolicyStore, SP>),
    received_addrs: &mut Vec<Address>,
    sink: &mut TestSink,
    graph_id: GraphId,
    rt_buffers: &mut RuntimeBuffers<SP::Segment>,
) -> Result<(usize, usize), TestError> {
    let mut request_syncer = SyncRequester::new(graph_id, Rng);
    assert!(request_syncer.ready());

    // The persistent `request_cache` only ever holds committed commands
    // (callers advance it after commit). The transaction's uncommitted
    // frontier is advertised via `session_heads`, which cannot outlive the
    // transaction, so an abandoned transaction cannot leave the cache
    // claiming commands the requester never committed.
    let session = request_trx.session_heads(request_cache);
    let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let (len, sent) = request_syncer.poll(
        &mut buffer,
        request_state.provider(),
        &session,
        &mut rt_buffers.traversal.primary,
    )?;

    let mut received = 0;
    let mut target = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let len = dispatch(
        &buffer[..len],
        &mut target,
        response_state.provider(),
        response_cache,
        &mut rt_buffers.traversal,
    )?;

    if len == 0 {
        return Ok((sent, received));
    }

    if let Some(cmds) = request_syncer.receive(&target[..len])? {
        received =
            request_state.add_commands(request_trx, sink, &cmds, rt_buffers, MemSpill::new)?;

        // Persist any in-flight perspective so the next exchange's overlay
        // sees every accumulated command at a real location. This is what
        // lets progressive fetch advance while the transaction stays open.
        let storage = request_state.provider().get_storage(graph_id)?;
        request_trx.flush(storage)?;

        // Report what was received so the caller can advance the persistent
        // cache once these commands are committed.
        received_addrs.extend(cmds.iter().filter_map(|cmd| cmd.address().ok()));
    }

    Ok((sent, received))
}

struct Parent(Prior<Address>);

impl Display for Parent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Prior::Merge(a, b) => {
                write!(f, "Merge({}, {})", short_b58(a.id), short_b58(b.id))
            }
            Prior::Single(a) => write!(f, "Single({})", short_b58(a.id)),
            Prior::None => write!(f, "None"),
        }
    }
}

pub fn print_graph<S>(
    storage: &S,
    location: Location,
    buffer: &mut TraversalBuffer,
) -> Result<BTreeSet<CmdId>, StorageError>
where
    S: Storage,
{
    let mut visited = BTreeSet::new();
    let mut locations = vec![location];
    let mut command_ids = BTreeSet::new();

    while let Some(loc) = locations.pop() {
        if visited.contains(&loc.segment) {
            continue;
        }
        visited.insert(loc.segment);
        let segment = storage.get_segment(loc)?;
        let commands = segment.get_from(segment.first_location());
        for command in commands.iter().rev() {
            let cmd_id = command.id();
            command_ids.insert(cmd_id);
            debug!(
                "id: {} location {:?} max_cut: {} parent: {}",
                short_b58(cmd_id),
                storage
                    .get_location(command.address()?, buffer)?
                    .assume("location must exist"),
                command.max_cut()?,
                Parent(command.parent())
            );
        }
        locations.extend(segment.prior());
    }

    Ok(command_ids)
}

/// Walk the graph and yield all visited IDs.
///
/// Lazy merges keep the graph multi-head, so seed the walk from every head.
fn walk<S: Storage>(storage: &S) -> impl Iterator<Item = CmdId> + '_ {
    let mut visited = BTreeSet::new();
    let mut stack: Vec<Location> = storage
        .get_heads()
        .unwrap()
        .iter()
        .map(crate::LocatedAddress::location)
        .collect();
    // Sort so the multi-head walk order is deterministic across peers.
    stack.sort();
    let mut segment = None;

    iter::from_fn(move || {
        loop {
            let loc = stack.pop()?;
            if !visited.insert(loc) {
                // Already visited (e.g. a shared ancestor of two heads); skip
                // it and continue rather than ending the whole walk.
                segment = None;
                continue;
            }

            let seg = segment.get_or_insert_with(|| storage.get_segment(loc).unwrap());
            let id = seg.get_command(loc).unwrap().id();

            if let Some(previous) = seg.previous(loc) {
                // We will visit the segment again.
                stack.push(previous);
            } else {
                // We have exhausted this segment.
                stack.extend(seg.prior());
                segment = None;
            }

            return Some(id);
        }
    })
}

/// Collects the full set of `(name, keys, value)` fact entries from a peer's
/// merged fact cache, for every fact name the test policies are known to write.
///
/// Uses [`Query::query_prefix`] with an empty prefix to enumerate all keys
/// under each name (the empty prefix matches every key). There is no API to
/// enumerate fact names, so we iterate [`TEST_FACT_NAMES`]; for the DSL tests
/// the only written name is `"payload"`, so this captures the entire merged
/// fact state.
fn collect_facts<S: Storage>(
    storage: &S,
) -> Result<BTreeMap<(&'static str, Keys), Bytes>, StorageError> {
    let cache = storage.fact_cache()?;
    let mut facts = BTreeMap::new();
    for &name in TEST_FACT_NAMES {
        for fact in cache.query_prefix(name, &[])? {
            let fact = fact?;
            facts.insert((name, fact.key), fact.value);
        }
    }
    Ok(facts)
}

/// Asserts the merged fact state of two peers is identical.
///
/// This is the load-bearing convergence artifact for lazy merges: two peers
/// that hold the same commands must braid them into the same merged facts.
fn fact_cache_eq<S: Storage>(storage_a: &S, storage_b: &S) -> bool {
    let facts_a = collect_facts(storage_a).unwrap();
    let facts_b = collect_facts(storage_b).unwrap();
    if facts_a != facts_b {
        for key in facts_a.keys().chain(facts_b.keys()) {
            let (a, b) = (facts_a.get(key), facts_b.get(key));
            if a != b {
                error!(
                    name = key.0,
                    "merged fact-cache mismatch: A={:?} B={:?}", a, b
                );
            }
        }
        return false;
    }
    true
}

fn graph_eq<S: Storage>(storage_a: &S, storage_b: &S) -> bool {
    // Lazy merges keep graphs multi-head, and two converged peers may store the
    // same commands under different segment layouts. Convergence means the same
    // set of reachable commands and the same head set (head sets are sorted, so
    // equality is order-independent).
    let cmds_a: BTreeSet<CmdId> = walk(storage_a).collect();
    let cmds_b: BTreeSet<CmdId> = walk(storage_b).collect();
    if cmds_a != cmds_b {
        for id in cmds_a.symmetric_difference(&cmds_b) {
            error!(id = %short_b58(*id), "graph command-set mismatch");
        }
        return false;
    }

    // Compare heads by command id: segment indices are local storage layout and
    // may legitimately differ between converged peers.
    let heads_a: BTreeSet<CmdId> = storage_a
        .get_heads()
        .unwrap()
        .iter()
        .map(|la| la.id)
        .collect();
    let heads_b: BTreeSet<CmdId> = storage_b
        .get_heads()
        .unwrap()
        .iter()
        .map(|la| la.id)
        .collect();
    if heads_a != heads_b {
        error!("graph head-set mismatch");
        return false;
    }

    // Strengthened convergence oracle: peers with the same commands + heads must
    // also braid them into the same MERGED FACT STATE. This converts the
    // previously-inferred fact-cache equality into a directly checked invariant.
    if !fact_cache_eq(storage_a, storage_b) {
        error!("merged fact-cache mismatch");
        return false;
    }

    true
}

macro_rules! test_vectors {
    ($($name:ident),+ $(,)?) => {
        /// The current test vectors.
        pub mod vectors {
            use super::*;

            /// Runs all of the test vectors.
            pub fn run_all<SB, F>(mut f: F) -> Result<(), TestError>
            where
                SB: StorageBackend,
                F: FnMut() -> SB,
            {
                $(
                    $name(|| f())?;
                )+
                Ok(())
            }

            $(
                #[doc = concat!("Runs ", stringify!($name), ".")]
                pub fn $name<SB, F>(mut f: F) -> Result<(), TestError>
                where
                    SB: StorageBackend,
                    F: FnMut() -> SB,
                {
                    const DATA: &str = include_str!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/testing/testdata/",
                        stringify!($name),
                        ".test",
                    ));
                    let rules: Vec<TestRule> = serde_json::from_str(DATA)?;

                    // Check if we should minimize this test
                    #[cfg(any(test, feature = "std"))]
                    if let Ok(minimize_name) = env::var("MINIMIZE_TEST") {
                        if minimize_name == stringify!($name) {
                            let minimal_rules = minimize_test(&mut f, &rules);
                            let output_path = format!("{}_minimal.test", stringify!($name));
                            let json = serde_json::to_string_pretty(&minimal_rules).unwrap();
                            fs::write(&output_path, json).unwrap();
                            println!("Wrote minimal test to {}", output_path);
                            return Ok(());
                        }
                    }

                    run_test::<SB>(f(), &rules)
                }
            )+
        }

        /// Add all of the test vectors as Rust tests.
        ///
        /// `$backend` should be a `FnMut() -> impl StorageBackend`.
        #[macro_export]
        macro_rules! test_suite {
            ($backend:expr) => {
                $(
                    #[::test_log::test]
                    fn $name() -> ::core::result::Result<(), $crate::testing::dsl::TestError> {
                        $crate::testing::dsl::vectors::$name($backend)
                    }
                )*
            };
        }
        pub use test_suite;
    };
}

test_vectors! {
    duplicate_sync_causes_failure,
    empty_sync,
    generate_graph,
    generate_graph_hello_sync,
    generate_graph_no_branching,
    generate_graph_small_branching,
    hello_sync,
    hello_sync_extended_head,
    hello_sync_multiple_heads,
    no_such_parent,
    exponential_traversal_regression,
    find_needed_segments_queue_max,
    four_seventy_three_failure,
    large_sync,
    lazy_merge_converge,
    list_multiple_graph_ids,
    many_branches,
    max_cut,
    missing_parent_after_sync,
    remove_graph,
    skip_list,
    sync_all_at_once,
    sync_graph_larger_than_command_max,
    three_client_branch,
    three_client_compare_graphs,
    three_client_sync,
    two_client_branch,
    two_client_merge,
    two_client_sync,
    converge_conflict_heavy,
    converge_delete_heavy,
    converge_priority_mixed,
    converge_sparse_facts,
    stress_hot_key_ties,
    stress_long_divergence,
    stress_hello_ring,
    stress_hello_hub_noops,
    stress_no_sync_braid,
    stress_delete_noop_churn,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClientState, Keys,
        storage::linear::testing::MemStorageProvider,
        testing::protocol::{TestActions, TestPolicyStore, TestSink},
    };

    pub(super) struct MemBackend;

    impl StorageBackend for MemBackend {
        type StorageProvider = MemStorageProvider;

        fn provider(&mut self, _client_id: u64) -> Self::StorageProvider {
            MemStorageProvider::default()
        }
    }

    /// Returns the location of the graph's only head, asserting there is
    /// exactly one (true for the linear, single-client tests below).
    fn single_head<S: Storage>(storage: &S) -> Result<Location, TestError> {
        let heads = storage.get_heads()?;
        assert_eq!(heads.len(), 1, "expected a single head");
        Ok(heads.as_slice()[0].location())
    }

    #[test]
    fn collect_facts_sees_set_values() -> Result<(), TestError> {
        let mut sink = TestSink::new();
        sink.ignore_expectations(true);
        let mut state = ClientState::new(TestPolicyStore::new(), MemStorageProvider::default());
        let mut buffers = RuntimeBuffers::new();
        let graph_id = state.new_graph(&0u64.to_be_bytes(), TestActions::Init(0), &mut sink)?;
        state.action(
            graph_id,
            &mut sink,
            TestActions::SetValue(7, 9),
            &mut buffers,
            MemSpill::new,
        )?;

        let storage = state.provider().get_storage(graph_id)?;
        let facts = collect_facts(storage)?;
        assert_eq!(facts.len(), 1);
        let value = facts
            .get(&("payload", Keys::from_iter([7u64.to_be_bytes()])))
            .expect("fact for key 7");
        assert_eq!(&**value, 9u64.to_be_bytes().as_slice());
        Ok(())
    }

    #[test]
    fn delete_action_removes_fact() -> Result<(), TestError> {
        let mut sink = TestSink::new();
        sink.ignore_expectations(true);
        let mut state = ClientState::new(TestPolicyStore::new(), MemStorageProvider::default());
        let mut buffers = RuntimeBuffers::new();
        let graph_id = state.new_graph(&0u64.to_be_bytes(), TestActions::Init(0), &mut sink)?;
        for action in [
            TestActions::SetValue(7, 9),
            TestActions::SetValue(8, 10),
            TestActions::DeleteValue(7, 0),
        ] {
            state.action(graph_id, &mut sink, action, &mut buffers, MemSpill::new)?;
        }

        let storage = state.provider().get_storage(graph_id)?;
        let facts = collect_facts(storage)?;
        assert_eq!(facts.len(), 1);
        assert!(facts.contains_key(&("payload", Keys::from_iter([8u64.to_be_bytes()]))));
        Ok(())
    }

    #[test]
    fn set_value_priority_carries_priority() -> Result<(), TestError> {
        let mut sink = TestSink::new();
        sink.ignore_expectations(true);
        let mut state = ClientState::new(TestPolicyStore::new(), MemStorageProvider::default());
        let mut buffers = RuntimeBuffers::new();
        let graph_id = state.new_graph(&0u64.to_be_bytes(), TestActions::Init(0), &mut sink)?;
        state.action(
            graph_id,
            &mut sink,
            TestActions::SetValuePriority(1, 2, 7),
            &mut buffers,
            MemSpill::new,
        )?;

        let storage = state.provider().get_storage(graph_id)?;
        let head = single_head(storage)?;
        let segment = storage.get_segment(head)?;
        let command = segment.get_command(head).unwrap();
        assert_eq!(command.priority(), crate::Priority::Basic(7));
        Ok(())
    }

    #[test]
    fn action_set_json_backcompat() {
        let rule: TestRule = serde_json::from_str(
            r#"{"ActionSet": {"client": 0, "graph": 0, "key": 1, "value": 2, "repeat": 1}}"#,
        )
        .unwrap();
        assert_eq!(
            rule,
            TestRule::ActionSet {
                client: 0,
                graph: 0,
                key: 1,
                value: 2,
                repeat: 1,
                priority: 0,
            }
        );
    }

    #[test]
    fn action_rules_converge_facts() -> Result<(), TestError> {
        let rules = vec![
            TestRule::AddClient { id: 0 },
            TestRule::AddClient { id: 1 },
            TestRule::NewGraph {
                client: 0,
                id: 0,
                policy: 0,
            },
            TestRule::Sync {
                graph: 0,
                client: 1,
                from: 0,
                must_send: None,
                must_receive: None,
                max_syncs: 100,
            },
            TestRule::IgnoreExpectations { ignore: true },
            // Concurrent, conflicting operations on key 1 with different
            // priorities, plus an unrelated write on key 2. The braid
            // decides the outcome; both clients must agree.
            TestRule::ActionSet {
                client: 0,
                graph: 0,
                key: 1,
                value: 10,
                repeat: 1,
                priority: 2,
            },
            TestRule::ActionDelete {
                client: 1,
                graph: 0,
                key: 1,
                priority: 1,
            },
            TestRule::ActionSet {
                client: 1,
                graph: 0,
                key: 2,
                value: 5,
                repeat: 1,
                priority: 0,
            },
            TestRule::ConvergeAll {
                graph: 0,
                clients: 2,
                max_syncs: 100,
            },
            TestRule::CompareGraphs {
                clienta: 0,
                clientb: 1,
                graph: 0,
                equal: true,
            },
            TestRule::IgnoreExpectations { ignore: false },
        ];
        run_test(MemBackend, &rules)
    }

    #[test]
    fn noop_action_writes_no_facts() -> Result<(), TestError> {
        let mut sink = TestSink::new();
        sink.ignore_expectations(true);
        let mut state = ClientState::new(TestPolicyStore::new(), MemStorageProvider::default());
        let mut buffers = RuntimeBuffers::new();
        let graph_id = state.new_graph(&0u64.to_be_bytes(), TestActions::Init(0), &mut sink)?;
        for action in [TestActions::SetValue(7, 9), TestActions::NoOp(42, 1)] {
            state.action(graph_id, &mut sink, action, &mut buffers, MemSpill::new)?;
        }

        let storage = state.provider().get_storage(graph_id)?;
        let facts = collect_facts(storage)?;
        assert_eq!(facts.len(), 1);
        assert!(facts.contains_key(&("payload", Keys::from_iter([7u64.to_be_bytes()]))));

        let head = single_head(storage)?;
        let segment = storage.get_segment(head)?;
        let command = segment.get_command(head).unwrap();
        assert_eq!(command.priority(), crate::Priority::Basic(1));
        Ok(())
    }

    #[test]
    fn generate_graph_with_knobs_converges() -> Result<(), TestError> {
        let rules = vec![TestRule::GenerateGraph {
            clients: 3,
            graph: 0,
            commands: 60,
            policy: 0,
            sync_client_zero: true,
            sync_method: SyncMethod::Poll {
                sync_chance: 40,
                add_command_chance: 60,
            },
            delete_proportion: 30,
            noop_proportion: 0,
            key_range: 3,
            max_priority: 3,
            seed: None,
        }];
        run_test(MemBackend, &rules)
    }
}
