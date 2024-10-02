//! DSL tests.
//!
//! # Example
//!
//! If you're writing unit tests, the [`test_suite`] macro
//! expands to a bunch of Rust unit tests.
//!
//! ```
//! use runtime::{
//!     storage::memory::MemStorageProvider,
//!     testing::dsl::{test_suite, StorageBackend},
//! };
//!
//! struct MemBackend;
//! impl StorageBackend for MemBackend {
//!     type StorageProvider = MemStorageProvider;
//!
//!     fn provider(&mut self, _client_id: u64) -> Self::StorageProvider {
//!         MemStorageProvider::new()
//!     }
//! }
//! test_suite!(|| MemBackend);
//! ```
//!
//! Otherwise, if you're writing integration tests, use
//! [`vectors::run_all`].
//!
//! ```
//! use runtime::{
//!     storage::memory::MemStorageProvider,
//!     testing::dsl::{StorageBackend, vectors},
//! };
//!
//! struct MemBackend;
//! impl StorageBackend for MemBackend {
//!     type StorageProvider = MemStorageProvider;
//!
//!     fn provider(&mut self, _client_id: u64) -> Self::StorageProvider {
//!         MemStorageProvider::new()
//!     }
//! }
//! vectors::run_all(|| MemBackend).unwrap();
//! ```

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::unwrap_used)]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use core::{
    cell::RefCell,
    fmt::{self, Display},
    iter,
};
#[cfg(any(test, feature = "std"))]
use std::time::Instant;

use buggy::{Bug, BugExt};
use crypto::{csprng::rand::Rng as RRng, Csprng, Rng};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::{
    protocol::{TestActions, TestEffect, TestEngine, TestSink},
    Address, ClientError, ClientState, Command, CommandId, EngineError, GraphId, Location,
    PeerCache, Prior, Segment, Storage, StorageError, StorageProvider, SyncError, SyncRequester,
    SyncResponder, COMMAND_RESPONSE_MAX, MAX_SYNC_MESSAGE_SIZE,
};

fn default_repeat() -> u64 {
    1
}

fn default_max_syncs() -> u64 {
    1
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
        add_command_chance: u64,
        sync_chance: u64,
    },
    SetupClientsAndGraph {
        clients: u64,
        graph: u64,
        policy: u64,
    },
    MaxCut {
        client: u64,
        graph: u64,
        max_cut: usize,
    },
}

impl Display for TestRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestRule::Sync {
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
            TestRule::Sync {
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
            TestRule::Sync {
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
            TestRule::Sync {
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
            TestRule::ActionSet {
                client,
                graph,
                key,
                value,
                repeat,
            } => write!(
                f,
                r#"{{"ActionSet": {{ "graph": {}, "client": {}, "key": {}, "value": {}, "repeat": {} }} }},"#,
                graph, client, key, value, repeat,
            ),
            TestRule::AddClient { id } => write!(f, r#"{{"AddClient": {{ "id": {} }} }},"#, id),
            TestRule::AddExpectation(value) => write!(f, r#"{{"AddExpectation": {} }},"#, value),
            TestRule::AddExpectations {
                expectation,
                repeat,
            } => write!(
                f,
                r#"{{"AddExpectations": {{ "expectation": {}, "repeat": {} }} }},"#,
                expectation, repeat,
            ),
            TestRule::CompareGraphs {
                clienta,
                clientb,
                graph,
                equal,
            } => write!(
                f,
                r#"{{"CompareGraphs": {{ "clienta": {}, "clientb": {}, "graph": {}, "equal": {} }} }},"#,
                clienta, clientb, graph, equal,
            ),
            TestRule::GenerateGraph {
                clients,
                graph,
                commands,
                add_command_chance,
                sync_chance,
            } => write!(
                f,
                r#"{{"GenerateGraph": {{ "clients": {}, "graph": {}, "commands": {}, "add_command_chance": {}, "sync_chance": {} }} }},"#,
                clients, graph, commands, add_command_chance, sync_chance,
            ),
            TestRule::IgnoreExpectations { ignore } => write!(
                f,
                r#"{{"IgnoreExpectations": {{ "ignore": {} }} }},"#,
                ignore,
            ),
            TestRule::MaxCut {
                client,
                graph,
                max_cut,
            } => write!(
                f,
                r#"{{"MaxCut": {{ "client": {}, "graph": {}, "max_cut": {} }} }},"#,
                client, graph, max_cut,
            ),
            TestRule::NewGraph { client, id, policy } => write!(
                f,
                r#"{{"NewGraph": {{ "client": {}, "id": {}, "policy": {} }} }},"#,
                client, id, policy,
            ),
            TestRule::PrintGraph { client, graph } => write!(
                f,
                r#"{{"PrintGraph": {{ "client": {}, "graph": {} }} }},"#,
                client, graph,
            ),
            TestRule::SetupClientsAndGraph {
                clients,
                graph,
                policy,
            } => write!(
                f,
                r#"{{"SetupClientsAndGraph": {{ "clients": {}, "graph": {}, "policy": {} }} }},"#,
                clients, graph, policy,
            ),
        }
    }
}

/// An error result from a test.
#[derive(Debug)]
#[allow(dead_code)] // fields used only via `Debug`
pub enum TestError {
    Storage(StorageError),
    Client(ClientError),
    Engine(EngineError),
    Sync(SyncError),
    SerdeJson(serde_json::Error),
    MissingClient,
    MissingGraph(u64),
    Bug(Bug),
}

impl From<Bug> for TestError {
    fn from(bug: Bug) -> Self {
        Self::Bug(bug)
    }
}

impl From<StorageError> for TestError {
    fn from(error: StorageError) -> Self {
        TestError::Storage(error)
    }
}

impl From<ClientError> for TestError {
    fn from(err: ClientError) -> Self {
        TestError::Client(err)
    }
}

impl From<SyncError> for TestError {
    fn from(err: SyncError) -> Self {
        TestError::Sync(err)
    }
}

impl From<serde_json::Error> for TestError {
    fn from(err: serde_json::Error) -> Self {
        TestError::SerdeJson(err)
    }
}

impl From<EngineError> for TestError {
    fn from(err: EngineError) -> Self {
        TestError::Engine(err)
    }
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

/// Runs a particular test.
pub fn run_test<SB>(mut backend: SB, rules: &[TestRule]) -> Result<(), TestError>
where
    SB: StorageBackend,
{
    let mut rng = &mut Rng as &mut dyn Csprng;
    let actions: Vec<_> = rules
        .iter()
        .cloned()
        .flat_map(|rule| {
            match rule {
                TestRule::GenerateGraph {
                    clients,
                    graph,
                    commands,
                    add_command_chance,
                    sync_chance,
                } => {
                    assert!(clients > 2, "There must be at least three clients");
                    assert!(
                        add_command_chance > 0,
                        "There must be a positive command chance or it will never exit"
                    );
                    let max_syncs = 2;
                    let mut generated_actions = Vec::new();
                    let command_ceiling: u64 = add_command_chance;
                    let sync_ceiling = command_ceiling + sync_chance;
                    generated_actions.push(TestRule::IgnoreExpectations { ignore: true });
                    let mut count = 0;
                    // Randomly generate actions and syncs. This will create a graph with many branches.
                    while count < commands {
                        let client = rng.gen_range(1..clients);
                        match rng.gen_range(0..sync_ceiling) {
                            x if x < command_ceiling => {
                                generated_actions.push(TestRule::ActionSet {
                                    client,
                                    graph,
                                    key: 0,
                                    value: rng.gen_range(0..10),
                                    repeat: 1,
                                });
                                count += 1;
                            }
                            x if x < sync_ceiling => {
                                let mut from = (client + 1) % clients;
                                if from == 0 {
                                    from += 1;
                                }
                                generated_actions.push(TestRule::Sync {
                                    graph,
                                    client,
                                    from,
                                    must_send: None,
                                    must_receive: None,
                                    max_syncs: 1,
                                })
                            }
                            _ => {}
                        }
                    }
                    // Sync client 1 with all clients so client 1 has the entire graph.
                    for i in 2..clients {
                        generated_actions.push(TestRule::Sync {
                            graph,
                            client: 1,
                            from: i,
                            must_send: None,
                            must_receive: None,
                            max_syncs,
                        })
                    }
                    // Sync other clients with client 1 so all clients have the entire graph.
                    for i in 2..clients {
                        generated_actions.push(TestRule::Sync {
                            graph,
                            client: i,
                            from: 1,
                            must_send: None,
                            must_receive: None,
                            max_syncs,
                        })
                    }
                    // Sync the entire graph to client 0 at once.
                    generated_actions.push(TestRule::Sync {
                        graph,
                        client: 0,
                        from: 1,
                        must_send: None,
                        must_receive: None,
                        max_syncs: (commands / COMMAND_RESPONSE_MAX as u64) + 100,
                    });
                    // Sync other clients with client 0 so other clients have any extra merges
                    // created by client 0.
                    for i in 1..clients {
                        generated_actions.push(TestRule::Sync {
                            graph,
                            client: i,
                            from: 0,
                            must_send: None,
                            must_receive: None,
                            max_syncs,
                        })
                    }
                    // Compare all graphs to ensure they're the same after syncing.
                    for i in 1..clients {
                        generated_actions.push(TestRule::CompareGraphs {
                            clienta: 0,
                            clientb: i,
                            graph,
                            equal: true,
                        })
                    }
                    generated_actions.push(TestRule::IgnoreExpectations { ignore: false });
                    generated_actions
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
                            max_syncs: 1,
                        });
                    }
                    generated_actions
                }
                _ => vec![rule],
            }
        })
        .collect();

    let mut graphs = BTreeMap::new();
    let mut clients = BTreeMap::new();

    let mut sink = TestSink::new();
    // Store all known heads for each client.
    // BtreeMap<(graph, caching_client, cached_client) RefCell<PeerCache>>
    let mut client_heads: BTreeMap<(u64, u64, u64), RefCell<PeerCache>> = BTreeMap::new();

    for rule in actions {
        debug!(?rule);

        #[cfg(any(test, feature = "std"))]
        let start = Instant::now();

        match rule {
            TestRule::AddClient { id } => {
                let engine = TestEngine::new();
                let storage = backend.provider(id);

                let state = ClientState::new(engine, storage);
                clients.insert(id, RefCell::new(state));
            }
            TestRule::NewGraph { client, id, policy } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();
                let policy_data = policy.to_be_bytes();
                let storage_id =
                    state.new_graph(policy_data.as_slice(), TestActions::Init(0), &mut sink)?;

                graphs.insert(id, storage_id);

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
                let storage_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                let mut request_client = clients
                    .get(&client)
                    .ok_or(TestError::MissingClient)?
                    .borrow_mut();
                let mut response_client = clients
                    .get(&from)
                    .ok_or(TestError::MissingClient)?
                    .borrow_mut();

                let mut total_sent = 0;
                let mut total_received = 0;
                for _ in 0..max_syncs {
                    client_heads.entry((graph, client, from)).or_default();
                    client_heads.entry((graph, from, client)).or_default();
                    let mut request_cache = client_heads
                        .get(&(graph, client, from))
                        .assume("cache must exist")?
                        .borrow_mut();
                    let mut response_cache = client_heads
                        .get(&(graph, from, client))
                        .assume("cache must exist")?
                        .borrow_mut();
                    let (sent, received) = sync(
                        &mut request_cache,
                        &mut response_cache,
                        &mut request_client,
                        &mut response_client,
                        &mut sink,
                        *storage_id,
                    )?;
                    total_received += received;
                    total_sent += sent;
                    if received < COMMAND_RESPONSE_MAX {
                        break;
                    }
                }

                if let Some(mr) = must_receive {
                    assert_eq!(total_received, mr);
                }

                if let Some(ms) = must_send {
                    assert_eq!(total_sent, ms);
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
            } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();

                let storage_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                for _ in 0..repeat {
                    let set = TestActions::SetValue(key, value);
                    state.action(*storage_id, &mut sink, set)?;
                }

                assert_eq!(0, sink.count());
            }

            TestRule::PrintGraph { client, graph } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();

                let storage_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                let storage = state.provider().get_storage(*storage_id)?;
                let head = storage.get_head()?;
                print_graph(storage, head)?;
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

                let storage_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                let storage_a = state_a.provider().get_storage(*storage_id)?;
                let storage_b = state_b.provider().get_storage(*storage_id)?;

                let same = graph_eq(storage_a, storage_b);
                if same != equal {
                    let head_a = storage_a.get_head()?;
                    let head_b = storage_b.get_head()?;
                    debug!("Graph A");
                    print_graph(storage_a, head_a)?;
                    debug!("Graph B");
                    print_graph(storage_b, head_b)?;
                }
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
                let storage_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                let storage = state.provider().get_storage(*storage_id)?;
                let head = storage.get_head()?;
                let seg = storage.get_segment(head)?;
                let command = seg.get_command(head).assume("command must exist")?;
                assert_eq!(max_cut, command.max_cut()?);
            }
            TestRule::IgnoreExpectations { ignore } => sink.ignore_expectations(ignore),
            _ => {}
        };
        #[cfg(any(test, feature = "std"))]
        if false {
            {
                let duration = start.elapsed();
                debug!("Time elapsed in rule {:?} is: {:?}", rule, duration);
            }
        }
    }

    Ok(())
}

fn sync<SP: StorageProvider>(
    request_cache: &mut PeerCache,
    response_cache: &mut PeerCache,
    request_state: &mut ClientState<TestEngine, SP>,
    response_state: &mut ClientState<TestEngine, SP>,
    sink: &mut TestSink,
    storage_id: GraphId,
) -> Result<(usize, usize), TestError> {
    let mut request_syncer = SyncRequester::new(storage_id, &mut Rng);
    let mut response_syncer = SyncResponder::new();
    assert!(request_syncer.ready());

    let mut sent = 0;
    let mut request_trx = request_state.transaction(storage_id);

    if request_syncer.ready() {
        let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
        let (len, commands_sent) =
            request_syncer.poll(&mut buffer, request_state.provider(), request_cache)?;
        sent = commands_sent;

        response_syncer.receive(&buffer[..len])?;
    }

    let mut received = 0;
    if response_syncer.ready() {
        let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = response_syncer.poll(&mut buffer, response_state.provider(), response_cache)?;

        if len == 0 {
            return Ok((sent, received));
        }

        if let Some(cmds) = request_syncer.receive(&buffer[..len])? {
            received = request_state.add_commands(&mut request_trx, sink, &cmds, request_cache)?;
        };
    }

    request_state.commit(&mut request_trx, sink)?;

    Ok((sent, received))
}

struct Parent(Prior<Address>);

impl Display for Parent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Prior::Merge(a, b) => {
                write!(f, "Merge({}, {})", &a.id.short_b58(), &b.id.short_b58())
            }
            Prior::Single(a) => write!(f, "Single({})", &a.id.short_b58()),
            Prior::None => write!(f, "None"),
        }
    }
}

pub fn print_graph<S>(storage: &S, location: Location) -> Result<(), StorageError>
where
    S: Storage,
{
    let mut visited = BTreeSet::new();
    let mut locations = vec![location];
    while let Some(loc) = locations.pop() {
        if visited.contains(&loc.segment) {
            continue;
        }
        visited.insert(loc.segment);
        let segment = storage.get_segment(loc)?;
        let commands = segment.get_from(segment.first_location());
        for command in commands.iter().rev() {
            debug!(
                "id: {} location {:?} max_cut: {} parent: {}",
                &command.id().short_b58(),
                storage
                    .get_location(command.address()?)?
                    .assume("location must exist"),
                command.max_cut()?,
                Parent(command.parent())
            );
        }
        locations.extend(segment.prior());
    }
    Ok(())
}

/// Walk the graph and yield all visited IDs.
fn walk<S: Storage>(storage: &S) -> impl Iterator<Item = CommandId> + '_ {
    let mut visited = BTreeSet::new();
    let mut stack = vec![storage.get_head().unwrap()];
    let mut segment = None;

    iter::from_fn(move || {
        let loc = stack.pop()?;
        if visited.contains(&loc) {
            return None;
        }
        visited.insert(loc);

        let seg = segment.get_or_insert_with(|| storage.get_segment(loc).unwrap());
        let id = seg.get_command(loc).unwrap().id();

        if let Some(previous) = loc.previous() {
            // We will visit the segment again.
            stack.push(previous);
        } else {
            // We have exhausted this segment.
            stack.extend(seg.prior());
            segment = None;
        }

        Some(id)
    })
}

fn graph_eq<S: Storage>(storage_a: &S, storage_b: &S) -> bool {
    for (a, b) in iter::zip(walk(storage_a), walk(storage_b)) {
        if a != b {
            error!(a = %a.short_b58(), b = %b.short_b58(), "graph mismatch");
            return false;
        }
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
                pub fn $name<SB, F>(f: F) -> Result<(), TestError>
                where
                    SB: StorageBackend,
                    F: FnOnce() -> SB,
                {
                    const DATA: &str = include_str!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/testing/testdata/",
                        stringify!($name),
                        ".test",
                    ));
                    let rules: Vec<TestRule> = serde_json::from_str(DATA)?;
                    run_test::<SB>(f(), &rules)
                }
            )+
        }
    };
}

test_vectors! {
    empty_sync,
    two_client_merge,
    two_client_sync,
    three_client_sync,
    two_client_branch,
    three_client_branch,
    large_sync,
    three_client_compare_graphs,
    duplicate_sync_causes_failure,
    missing_parent_after_sync,
    sync_graph_larger_than_command_max,
    max_cut,
    skip_list,
    many_branches,
}

/// Used by [`test_suite`].
#[macro_export]
#[doc(hidden)]
macro_rules! test_vector {
    ($backend:expr ; $($name:ident),+ $(,)?) => {
        $(
            #[test]
            fn $name() -> ::core::result::Result<(), $crate::testing::dsl::TestError> {
                $crate::testing::dsl::vectors::$name($backend)
            }
        )*
    };
}
pub use test_vector;

/// Add all of the test vectors as Rust tests.
///
/// `$backend` should be a `FnMut() -> impl StorageBackend`.
#[macro_export]
macro_rules! test_suite {
    ($backend:expr) => {
        $crate::testing::dsl::test_vector! {
            $backend ;
            empty_sync,
            two_client_merge,
            two_client_sync,
            three_client_sync,
            two_client_branch,
            three_client_branch,
            large_sync,
            three_client_compare_graphs,
            duplicate_sync_causes_failure,
            missing_parent_after_sync,
            sync_graph_larger_than_command_max,
            max_cut,
            skip_list,
            many_branches,
        }
    };
}
pub use test_suite;
