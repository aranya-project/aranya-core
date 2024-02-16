use alloc::{collections::BTreeSet, fmt};
use core::fmt::Display;
use std::{
    collections::BTreeMap,
    fs::File,
    iter,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use buggy::{Bug, BugExt};
use crypto::Rng;
use once_cell::sync::Lazy;
use quinn::{ConnectionError, ReadToEndError, ServerConfig, WriteError};
use rand::Rng as RRng;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as TMutex;
use tracing::debug;

use crate::{
    protocol::{TestActions, TestEffect, TestEngine, TestSink},
    quic_syncer::{run_syncer, QuicSyncError, Syncer},
    ClientError, ClientState, Command, EngineError, Id, Location, Prior, Segment, Storage,
    StorageError, StorageProvider, SyncRequester, COMMAND_RESPONSE_MAX,
};

static NETWORK: Lazy<TMutex<()>> = Lazy::new(TMutex::default);

fn default_repeat() -> u64 {
    1
}

fn default_max_syncs() -> u64 {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum TestRule {
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
}

impl Display for TestRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &TestRule::Sync {
                graph,
                client,
                from,
                must_receive: None,
                max_syncs,
            } => write!(
                f,
                "- !Sync {{ graph: {}, client: {}, from: {}, max_syncs: {} }}",
                graph, client, from, max_syncs,
            ),
            _ => {
                write!(f, "- !{:?}", self)
            }
        }
    }
}

#[derive(Debug)]
enum TestError {
    Storage(StorageError),
    Client(ClientError),
    Engine(EngineError),
    Io(std::io::Error),
    SerdeYaml(serde_yaml::Error),
    MissingClient,
    MissingGraph(u64),
    Sync(QuicSyncError),
    Crypto,
    Network,
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

impl From<ConnectionError> for TestError {
    fn from(_error: ConnectionError) -> Self {
        TestError::Network
    }
}

impl From<WriteError> for TestError {
    fn from(_error: WriteError) -> Self {
        TestError::Network
    }
}

impl From<ReadToEndError> for TestError {
    fn from(_error: ReadToEndError) -> Self {
        TestError::Network
    }
}

impl From<rustls::Error> for TestError {
    fn from(_err: rustls::Error) -> Self {
        TestError::Crypto
    }
}

impl From<ClientError> for TestError {
    fn from(err: ClientError) -> Self {
        TestError::Client(err)
    }
}

impl From<std::io::Error> for TestError {
    fn from(err: std::io::Error) -> Self {
        TestError::Io(err)
    }
}

impl From<serde_yaml::Error> for TestError {
    fn from(err: serde_yaml::Error) -> Self {
        TestError::SerdeYaml(err)
    }
}

impl From<EngineError> for TestError {
    fn from(err: EngineError) -> Self {
        TestError::Engine(err)
    }
}

impl From<QuicSyncError> for TestError {
    fn from(err: QuicSyncError) -> Self {
        TestError::Sync(err)
    }
}

fn read(file: &str) -> Result<Vec<TestRule>, TestError> {
    let file = File::open(file)?;
    let actions: Vec<TestRule> = serde_yaml::from_reader(file)?;
    Ok(actions)
}

/// Provides [`StorageProvider`] impls for testing.
///
/// This will probably end up replaced by the model work.
trait StorageBackend {
    type StorageProvider: StorageProvider;
    fn new() -> Self;
    fn provider(&mut self, client_id: u64) -> Self::StorageProvider;
}

async fn run<SB>(file: &str) -> Result<(), TestError>
where
    SB: StorageBackend,
    SB::StorageProvider: Send + 'static,
{
    let mut backend = SB::new();

    let mut commands = BTreeMap::new();
    let actions: Vec<TestRule> = read(file)?;
    let mut clients = BTreeMap::new();
    let mut addrs = BTreeMap::new();

    let mut sink = TestSink::new();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain: Vec<rustls::Certificate> = vec![rustls::Certificate(cert_der)];
    let syncer = Syncer::new(&cert_chain)?;

    let mut rng = rand::thread_rng();
    let actions: Vec<_> = actions
        .into_iter()
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
                            must_receive: None,
                            max_syncs,
                        })
                    }
                    // Sync the entire graph to client 0 at once.
                    generated_actions.push(TestRule::Sync {
                        graph,
                        client: 0,
                        from: 1,
                        must_receive: None,
                        max_syncs: (COMMAND_RESPONSE_MAX as u64 / commands) + 10,
                    });
                    // Sync other clients with client 0 so other clients have any extra merges
                    // created by client 0.
                    for i in 1..clients {
                        generated_actions.push(TestRule::Sync {
                            graph,
                            client: i,
                            from: 0,
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

    for rule in actions {
        debug!(?rule);
        println!("{}", rule);
        let start = Instant::now();
        match rule {
            TestRule::AddClient { id } => {
                let engine = TestEngine::new();
                let storage = backend.provider(id);

                let state = ClientState::new(engine, storage);
                clients.insert(id, Arc::new(TMutex::new(state)));
            }
            TestRule::NewGraph { client, id, policy } => {
                let storage_id;
                {
                    let Some(cell) = clients.get(&client) else {
                        return Err(TestError::MissingClient);
                    };
                    let mut state = cell.lock().await;
                    let policy_data = policy.to_be_bytes();
                    let payload = (0, 0);
                    storage_id = state.new_graph(policy_data.as_slice(), payload, &mut sink)?;

                    commands.insert(id, storage_id);
                }

                for (&id, client) in clients.iter() {
                    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
                    let mut server_config =
                        ServerConfig::with_single_cert(cert_chain.clone(), priv_key.clone())?;
                    let transport_config =
                        Arc::get_mut(&mut server_config.transport).expect("test");
                    transport_config.max_concurrent_uni_streams(0_u8.into());
                    let endpoint = quinn::Endpoint::server(server_config, server_addr).unwrap();
                    addrs.insert(id, endpoint.local_addr()?);
                    tokio::spawn(run_syncer(client.clone(), endpoint));
                }

                assert_eq!(0, sink.count());
            }
            TestRule::Sync {
                client,
                graph,
                from,
                must_receive,
                max_syncs,
            } => {
                let Some(storage_id) = commands.get(&graph) else {
                    return Err(TestError::MissingGraph(graph));
                };
                let Some(request_cell) = clients.get(&client) else {
                    return Err(TestError::MissingClient);
                };
                let mut request_client = request_cell.lock().await;
                let server_addr = *addrs.get(&from).expect("client addr registered");
                let mut total_received = 0;
                for _ in 0..max_syncs {
                    let request_syncer = SyncRequester::new(*storage_id, &mut Rng::new());
                    let commands_received = syncer
                        .sync(
                            &mut request_client,
                            request_syncer,
                            &mut sink,
                            storage_id,
                            server_addr,
                        )
                        .await?;
                    total_received += commands_received;
                    if commands_received < COMMAND_RESPONSE_MAX {
                        break;
                    }
                }

                if let Some(mr) = must_receive {
                    assert_eq!(total_received, mr);
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
                let Some(cell) = clients.get(&client) else {
                    return Err(TestError::MissingClient);
                };
                let mut state = cell.lock().await;

                let Some(storage_id) = commands.get(&graph) else {
                    return Err(TestError::MissingGraph(graph));
                };

                for _ in 0..repeat {
                    let set = TestActions::SetValue(key, value);
                    state.action(storage_id, &mut sink, set)?;
                }

                assert_eq!(0, sink.count());
            }

            TestRule::PrintGraph { client, graph } => {
                let Some(cell) = clients.get(&client) else {
                    return Err(TestError::MissingClient);
                };
                let mut state = cell.lock().await;

                let Some(storage_id) = commands.get(&graph) else {
                    return Err(TestError::MissingGraph(graph));
                };
                let storage = state.provider().get_storage(storage_id)?;
                let head = storage.get_head()?;
                print_graph(storage, head)?;
            }

            TestRule::CompareGraphs {
                clienta,
                clientb,
                graph,
                equal,
            } => {
                let Some(cell_a) = clients.get(&clienta) else {
                    return Err(TestError::MissingClient);
                };
                let mut state_a = cell_a.lock().await;

                let Some(cell_b) = clients.get(&clientb) else {
                    return Err(TestError::MissingClient);
                };
                let mut state_b = cell_b.lock().await;

                let Some(storage_id) = commands.get(&graph) else {
                    return Err(TestError::MissingGraph(graph));
                };
                let storage_a = state_a.provider().get_storage(storage_id)?;
                let storage_b = state_b.provider().get_storage(storage_id)?;
                let head_a = storage_a.get_head()?;
                let head_b = storage_b.get_head()?;

                let same = graph_eq(storage_a, storage_b);
                if same != equal {
                    println!("Graph A");
                    print_graph(storage_a, head_a)?;
                    println!("Graph B");
                    print_graph(storage_b, head_b)?;
                }
                assert_eq!(equal, same);
            }
            TestRule::IgnoreExpectations { ignore } => sink.ignore_expectations(ignore),
            _ => {}
        };
        if false {
            let duration = start.elapsed();
            println!("Time elapsed in rule {:?} is: {:?}", rule, duration);
        }
    }

    Ok(())
}

impl Display for Prior<Id> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Prior::Merge(a, b) => {
                write!(f, "Merge({}, {})", &a.short_b58(), &b.short_b58())
            }
            Prior::Single(a) => write!(f, "Single({})", &a.short_b58()),
            Prior::None => write!(f, "None"),
        }
    }
}

fn print_graph<S>(storage: &S, location: Location) -> Result<(), StorageError>
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
        let segment = storage.get_segment(&loc)?;
        let commands = segment.get_from(&segment.first_location());
        for command in commands.iter().rev() {
            println!(
                "id: {} location {:?} parent: {}",
                &command.id().short_b58(),
                storage
                    .get_location(&command.id())?
                    .assume("location must exist"),
                command.parent()
            );
        }
        locations.extend(segment.prior());
    }
    Ok(())
}

/// Walk the graph and yield all visited IDs.
fn walk<S: Storage>(storage: &S) -> impl Iterator<Item = Id> + '_ {
    let mut stack = vec![storage.get_head().unwrap()];
    let mut segment = None;

    iter::from_fn(move || {
        let mut loc = stack.pop()?;

        let seg = segment.get_or_insert_with(|| storage.get_segment(&loc).unwrap());
        let id = seg.get_command(&loc).unwrap().id();

        if loc.previous() {
            // We will visit the segment again.
            stack.push(loc);
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
            eprintln!("{} != {}", a.short_b58(), b.short_b58());
            return false;
        }
    }
    true
}

macro_rules! yaml_test {
    ($backend:ident @ $($name:ident,)*) => {
    $(
        #[test_log::test(tokio::test)]
        async fn $name() -> Result<(),TestError> {
            let test_path = format!("{}/src/tests/{}.test", env!("CARGO_MANIFEST_DIR"), stringify!($name));
            let _mutex = NETWORK.lock().await;
            run::<$backend>( &test_path ).await?;
            Ok(())
        }
    )*
    }
}

macro_rules! test_suite {
    ($backend:ident) => {
        yaml_test! {
            $backend @
            empty_sync,
            two_client_merge,
            two_client_sync,
            three_client_sync,
            two_client_branch,
            three_client_branch,
            large_sync,
            three_client_compare_graphs,
            generate_graph,
            duplicate_sync_causes_failure,
            missing_parent_after_sync,
            sync_graph_larger_than_command_max,
        }
    };
}

mod memory {
    use super::*;
    use crate::memory::MemStorageProvider;

    struct MemBackend;
    impl StorageBackend for MemBackend {
        type StorageProvider = MemStorageProvider;

        fn new() -> Self {
            Self
        }

        fn provider(&mut self, _client_id: u64) -> Self::StorageProvider {
            MemStorageProvider::new()
        }
    }

    test_suite!(MemBackend);
}

#[cfg(feature = "rustix")]
mod linear {
    // TODO(jdygert): Add in-memory linear io manager

    use tracing::info;

    use super::*;
    use crate::storage::linear::*;

    struct LinearBackend {
        tempdir: tempfile::TempDir,
    }
    impl StorageBackend for LinearBackend {
        type StorageProvider = LinearStorageProvider<rustix::FileManager>;

        fn new() -> Self {
            let tempdir = tempfile::tempdir().unwrap();
            info!(path = ?tempdir.path(), "using tempdir");
            Self { tempdir }
        }

        fn provider(&mut self, client_id: u64) -> Self::StorageProvider {
            let dir = self.tempdir.path().join(client_id.to_string());
            std::fs::create_dir(&dir).unwrap();
            let manager = rustix::FileManager::new(&dir).unwrap();
            LinearStorageProvider::new(manager)
        }
    }

    test_suite!(LinearBackend);
}
