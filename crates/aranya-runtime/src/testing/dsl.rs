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
    vec,
    vec::Vec,
};
use core::{
    cell::RefCell,
    fmt::{self, Display},
    iter,
};
#[cfg(any(test, feature = "std"))]
use std::{env, fs, time::Instant};

use aranya_crypto::{Rng, dangerous::spideroak_crypto::csprng::rand::Rng as _};
use buggy::{Bug, BugExt as _};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::{
    Address, COMMAND_RESPONSE_MAX, ClientError, ClientState, CmdId, Command as _, GraphId,
    Location, MAX_SYNC_MESSAGE_SIZE, MaxCut, PeerCache, PolicyError, Prior, Segment as _, Storage,
    StorageError, StorageProvider, SyncError, SyncRequester, SyncResponder, SyncType,
    testing::{
        protocol::{TestActions, TestEffect, TestPolicyStore, TestSink},
        short_b58,
    },
};

fn default_repeat() -> u64 {
    1
}

fn default_max_syncs() -> u64 {
    1
}

/// Dispatches the SyncType contained in data.
/// This function is only for testing using polling. In production
/// usage the syncer implementation will handle this.
pub fn dispatch(
    data: &[u8],
    target: &mut [u8],
    provider: &mut impl StorageProvider,
    response_cache: &mut PeerCache,
) -> Result<usize, SyncError> {
    let sync_type: SyncType = postcard::from_bytes(data)?;
    let len = match sync_type {
        SyncType::Poll { request } => {
            let mut response_syncer = SyncResponder::new();
            response_syncer.receive(request)?;
            assert!(response_syncer.ready());
            response_syncer.poll(target, provider, response_cache)?
        }
        SyncType::Subscribe { .. } => unimplemented!(),
        SyncType::Unsubscribe { .. } => unimplemented!(),
        SyncType::Push { .. } => unimplemented!(),
        SyncType::Hello(_) => unimplemented!(),
    };
    Ok(len)
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
        max_cut: MaxCut,
    },
    VerifyGraphIds {
        client: u64,
        ids: Vec<u64>,
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
            } => write!(
                f,
                r#"{{"ActionSet": {{ "graph": {}, "client": {}, "key": {}, "value": {}, "repeat": {} }} }},"#,
                graph, client, key, value, repeat,
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
                add_command_chance,
                sync_chance,
            } => write!(
                f,
                r#"{{"GenerateGraph": {{ "clients": {}, "graph": {}, "commands": {}, "add_command_chance": {}, "sync_chance": {} }} }},"#,
                clients, graph, commands, add_command_chance, sync_chance,
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

/// Runs a particular test.
pub fn run_test<SB>(mut backend: SB, rules: &[TestRule]) -> Result<(), TestError>
where
    SB: StorageBackend,
{
    let mut rng = Rng;
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
                    // Calculate the maximum number of syncs needed to send all commands.
                    // We add 100 to account for extra syncs needed for merge commands.
                    let max_syncs = (commands / COMMAND_RESPONSE_MAX as u64) + 100;
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
                                });
                            }
                            _ => {}
                        }
                    }
                    // Converge clients 1, 2, 3, etc. by repeatedly syncing them with each other
                    // until they all have the same graph. This is necessary because merge commands
                    // created during syncs need to propagate to all clients.
                    // We loop multiple times to ensure convergence (merge commands from one client
                    // need to be sent to others, which may create new merges, etc.)
                    for _convergence_round in 0..5 {
                        // Sync client 1 with all other clients so client 1 has the entire graph.
                        for i in 2..clients {
                            generated_actions.push(TestRule::Sync {
                                graph,
                                client: 1,
                                from: i,
                                must_send: None,
                                must_receive: None,
                                max_syncs,
                            });
                        }
                        // Sync other clients with client 1 so they get everything from client 1.
                        for i in 2..clients {
                            generated_actions.push(TestRule::Sync {
                                graph,
                                client: i,
                                from: 1,
                                must_send: None,
                                must_receive: None,
                                max_syncs,
                            });
                        }
                    }
                    // Sync the entire graph to client 0 at once.
                    generated_actions.push(TestRule::Sync {
                        graph,
                        client: 0,
                        from: 1,
                        must_send: None,
                        must_receive: None,
                        max_syncs,
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
                        });
                    }
                    // Compare all graphs to ensure they're the same after syncing.
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
        fs::write(&dump_path, json).unwrap();
        debug!("Dumped generated rules to {}", dump_path);
    }

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
                    let (sent, received) = sync::<<SB as StorageBackend>::StorageProvider>(
                        &mut request_cache,
                        &mut response_cache,
                        &mut request_client,
                        &mut response_client,
                        &mut sink,
                        *graph_id,
                    )?;
                    total_received += received;
                    total_sent += sent;
                    // Break when no commands are received, meaning the requester has caught up
                    if received == 0 {
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

                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                for _ in 0..repeat {
                    let set = TestActions::SetValue(key, value);
                    state.action(*graph_id, &mut sink, set)?;
                }

                assert_eq!(0, sink.count());
            }

            TestRule::PrintGraph { client, graph } => {
                let state = clients
                    .get_mut(&client)
                    .ok_or(TestError::MissingClient)?
                    .get_mut();

                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;
                let storage = state.provider().get_storage(*graph_id)?;
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

                let graph_id = graphs.get(&graph).ok_or(TestError::MissingGraph(graph))?;

                let storage_a = state_a.provider().get_storage(*graph_id)?;
                let storage_b = state_b.provider().get_storage(*graph_id)?;

                let same = graph_eq(storage_a, storage_b);
                if same != equal {
                    let head_a = storage_a.get_head()?;
                    let head_b = storage_b.get_head()?;
                    debug!("Graph A (client {})", clienta);
                    let cmds_a = print_graph(storage_a, head_a)?;
                    debug!("Graph B (client {})", clientb);
                    let cmds_b = print_graph(storage_b, head_b)?;

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
                let head = storage.get_head()?;
                assert_eq!(max_cut, head.max_cut);
            }
            TestRule::IgnoreExpectations { ignore } => sink.ignore_expectations(ignore),
            TestRule::VerifyGraphIds { client, ref ids } => {
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
            _ => {}
        }
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

    // Find the convergence phase which should be preserved
    // The GenerateGraph rule creates a distinctive sync with high max_syncs
    // (commands / COMMAND_RESPONSE_MAX + 100) before the verification CompareGraphs.
    // We look for a Sync with max_syncs > 10 as the start of convergence.
    let mut convergence_idx = end_idx;
    for (i, rule) in rules.iter().enumerate().skip(start_idx) {
        if let TestRule::Sync { max_syncs, .. } = rule
            && *max_syncs > 10
        {
            convergence_idx = i;
            break;
        }
    }

    // If we didn't find a high max_syncs, fall back to looking for CompareGraphs
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

fn sync<SP: StorageProvider>(
    request_cache: &mut PeerCache,
    response_cache: &mut PeerCache,
    request_state: &mut ClientState<TestPolicyStore, SP>,
    response_state: &mut ClientState<TestPolicyStore, SP>,
    sink: &mut TestSink,
    graph_id: GraphId,
) -> Result<(usize, usize), TestError> {
    let mut request_syncer = SyncRequester::new(graph_id, Rng);
    assert!(request_syncer.ready());

    let mut request_trx = request_state.transaction(graph_id);

    let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let (len, sent) = request_syncer.poll(&mut buffer, request_state.provider(), request_cache)?;

    let mut received = 0;
    let mut target = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let len = dispatch(
        &buffer[..len],
        &mut target,
        response_state.provider(),
        response_cache,
    )?;

    if len == 0 {
        return Ok((sent, received));
    }

    if let Some(cmds) = request_syncer.receive(&target[..len])? {
        received = request_state.add_commands(&mut request_trx, sink, &cmds)?;
        request_state.commit(&mut request_trx, sink)?;
        request_state.update_heads(
            graph_id,
            cmds.iter().filter_map(|cmd| cmd.address().ok()),
            request_cache,
        )?;
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

pub fn print_graph<S>(storage: &S, location: Location) -> Result<BTreeSet<CmdId>, StorageError>
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
                    .get_location(command.address()?)?
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
fn walk<S: Storage>(storage: &S) -> impl Iterator<Item = CmdId> + '_ {
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

        if let Some(previous) = seg.previous(loc) {
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
            error!(a = %short_b58(a), b = %short_b58(b), "graph mismatch");
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
    four_seventy_three_failure,
    large_sync,
    list_multiple_graph_ids,
    many_branches,
    many_clients,
    max_cut,
    missing_parent_after_sync,
    remove_graph,
    skip_list,
    sync_graph_larger_than_command_max,
    three_client_branch,
    three_client_compare_graphs,
    three_client_sync,
    two_client_branch,
    two_client_merge,
    two_client_sync,
}
