use crate::tests::protocol::*;
use crate::*;

use std::{cell::RefCell, fs::File};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::storage::memory::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
    },
    AddExpectation(u64),
    ActionSet {
        client: u64,
        graph: u64,
        key: u64,
        value: u64,
    },
}

#[derive(Debug)]
enum TestError {
    Client(ClientError),
    Engine(EngineError),
    Io(std::io::Error),
    SerdeYaml(serde_yaml::Error),
    MissingClient,
    MissingGraph(u64),
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

fn read(file: &str) -> Result<Vec<TestRule>, TestError> {
    let file = File::open(file)?;
    let actions: Vec<TestRule> = serde_yaml::from_reader(file)?;
    Ok(actions)
}

fn run(file: &str) -> Result<(), TestError> {
    let mut commands = BTreeMap::new();
    let actions: Vec<TestRule> = read(file)?;

    let mut clients = BTreeMap::new();

    let mut sink = TestSink::new();

    for rule in actions {
        dbg!(&rule);
        match rule {
            TestRule::AddClient { id } => {
                let engine = TestEngine::new();
                let storage = MemStorageProvider::new();

                let state = ClientState::new(engine, storage);
                let value = RefCell::new(state);
                clients.insert(id, value);
            }
            TestRule::NewGraph { client, id, policy } => {
                let Some(cell) = clients.get(&client) else {
                    return Err(TestError::MissingClient);
                };
                let mut state = cell.borrow_mut();
                let policy_data = policy.to_be_bytes();
                let payload = (0, 0);
                let storage_id = state.new_graph(policy_data.as_slice(), &payload, &mut sink)?;

                commands.insert(id, storage_id);

                assert_eq!(0, sink.count());
            }
            TestRule::Sync {
                client,
                graph,
                from,
            } => {
                let Some(request_cell) = clients.get(&client) else {
                    return Err(TestError::MissingClient);
                };

                let Some(response_cell) = clients.get(&from) else {
                    return Err(TestError::MissingClient);
                };

                let Some(storage_id) = commands.get(&graph) else {
                    return Err(TestError::MissingGraph(graph));
                };

                let session_id = 7;

                let mut request_syncer = SyncRequester::new(session_id, *storage_id);
                let mut response_syncer = SyncResponder::new(session_id);

                let mut request_client = request_cell.borrow_mut();
                let mut response_client = response_cell.borrow_mut();

                assert!(request_syncer.ready());

                loop {
                    if !request_syncer.ready() && !response_syncer.ready() {
                        break;
                    }

                    if request_syncer.ready() {
                        let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
                        let target: &mut [u8] = buffer.as_mut_slice();
                        let len = request_client.sync_poll(&mut request_syncer, target)?;
                        let mut trx = response_client.transaction(storage_id);
                        response_client.sync_receive(
                            &mut trx,
                            &mut sink,
                            &mut response_syncer,
                            &target[0..len],
                        )?;
                        response_client.commit(&mut trx, &mut sink)?;
                    }

                    if response_syncer.ready() {
                        let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
                        let target = buffer.as_mut_slice();
                        let len = response_client.sync_poll(&mut response_syncer, target)?;
                        let mut trx = request_client.transaction(storage_id);
                        request_client.sync_receive(
                            &mut trx,
                            &mut sink,
                            &mut request_syncer,
                            &target[0..len],
                        )?;
                        request_client.commit(&mut trx, &mut sink)?;
                    }
                }

                assert_eq!(0, sink.count());
            }

            TestRule::AddExpectation(expectation) => {
                sink.add_expectation(TestEffect::Got(expectation));
            }

            TestRule::ActionSet {
                client,
                graph,
                key,
                value,
            } => {
                let Some(cell) = clients.get(&client) else {
                    return Err(TestError::MissingClient);
                };
                let mut state = cell.borrow_mut();

                let Some(storage_id) = commands.get(&graph) else {
                    return Err(TestError::MissingGraph(graph));
                };

                let set = TestActions::SetValue(key, value);
                state.action(storage_id, &mut sink, &set)?;

                assert_eq!(0, sink.count());
            }
        };
    }
    Ok(())
}

macro_rules! yaml_test {
    ($($name:ident,)*) => {
    $(
        #[test]
        fn $name() -> Result<(), TestError> {
            let test_path = format!("{}/src/tests/{}.test", env!("CARGO_MANIFEST_DIR"), stringify!($name));
            run(&test_path)
        }
    )*
    }
}

yaml_test! {
    two_client_merge,
    two_client_sync,
    three_client_sync,
}
