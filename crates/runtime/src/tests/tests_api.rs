use std::{
    collections::BTreeMap,
    fs::File,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use once_cell::sync::Lazy;
use quinn::{ClientConfig, ConnectionError, Endpoint, ReadToEndError, WriteError};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as TMutex;
use tokio_util::sync::CancellationToken;

use crate::{
    storage::memory::*,
    tests::{
        protocol::*,
        sync::{run_syncer, WrappedSink},
    },
    *,
};

static NETWORK: Lazy<TMutex<()>> = Lazy::new(TMutex::default);

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
    Crypto,
    Network,
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

fn read(file: &str) -> Result<Vec<TestRule>, TestError> {
    let file = File::open(file)?;
    let actions: Vec<TestRule> = serde_yaml::from_reader(file)?;
    Ok(actions)
}

async fn run(file: &str) -> Result<(), TestError> {
    let session_id = 7;
    let mut commands = BTreeMap::new();
    let actions: Vec<TestRule> = read(file)?;
    let cancel_token = CancellationToken::new();

    let mut clients = BTreeMap::new();

    let mut sink = WrappedSink {
        sink: Arc::new(Mutex::new(TestSink::new())),
    };
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain: Vec<rustls::Certificate> = vec![rustls::Certificate(cert_der)];

    for rule in actions {
        dbg!(&rule);
        match rule {
            TestRule::AddClient { id } => {
                let engine = TestEngine::new();
                let storage = MemStorageProvider::new();

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
                    storage_id = state.new_graph(policy_data.as_slice(), &payload, &mut sink)?;

                    commands.insert(id, storage_id);
                }

                for (id, client) in clients.iter() {
                    let fut = run_syncer(
                        cancel_token.clone(),
                        client.clone(),
                        storage_id,
                        cert_chain.clone(),
                        priv_key.clone(),
                        *id,
                        session_id,
                        sink.clone(),
                    );
                    tokio::spawn(async move {
                        if let Err(e) = fut.await {
                            println!("sync error: {:?}", e)
                        }
                    });
                }

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
                let request_client = request_cell.lock().await;

                let Some(storage_id) = commands.get(&graph) else {
                    return Err(TestError::MissingGraph(graph));
                };

                let request_syncer = SyncRequester::new(session_id, *storage_id);

                assert!(request_syncer.ready());

                sync(
                    request_client,
                    request_syncer,
                    cert_chain.clone(),
                    &mut sink,
                    storage_id,
                    from,
                )
                .await?;

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
                let mut state = cell.lock().await;

                let Some(storage_id) = commands.get(&graph) else {
                    return Err(TestError::MissingGraph(graph));
                };

                let set = TestActions::SetValue(key, value);
                state.action(storage_id, &mut sink, &set)?;

                assert_eq!(0, sink.count());
            }
        };
    }
    cancel_token.cancel();
    Ok(())
}

async fn sync(
    mut client: tokio::sync::MutexGuard<'_, ClientState<TestEngine, MemStorageProvider>>,
    mut syncer: SyncRequester<'_>,
    cert_chain: Vec<rustls::Certificate>,
    sink: &mut WrappedSink,
    storage_id: &Id,
    id: u64,
) -> Result<(), TestError> {
    let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let target: &mut [u8] = buffer.as_mut_slice();
    let len = client.sync_poll(&mut syncer, target)?;
    let server_addr: SocketAddr = format!("127.0.0.1:{}", 5000 + id).parse().unwrap();
    let mut certs = rustls::RootCertStore::empty();
    for cert in &cert_chain {
        certs.add(cert)?;
    }
    let client_cfg = ClientConfig::with_root_certificates(certs);
    let client_addr = "[::]:0".parse().unwrap();
    let mut endpoint = Endpoint::client(client_addr)?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await?;

    send.write_all(&target[0..len]).await?;
    send.finish().await?;
    let resp = recv.read_to_end(usize::max_value()).await?;
    let mut trx = client.transaction(storage_id);
    client.sync_receive(&mut trx, sink, &mut syncer, &resp)?;
    client.commit(&mut trx, sink)?;
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    endpoint.close(0u32.into(), b"done");
    Ok(())
}

macro_rules! yaml_test {
    ($($name:ident,)*) => {
    $(
        #[tokio::test]
        async fn $name() -> Result<(),TestError> {
            let test_path = format!("{}/src/tests/{}.test", env!("CARGO_MANIFEST_DIR"), stringify!($name));
            let _mutex = NETWORK.lock().await;
            run( &test_path ).await?;
            Ok(())
        }
    )*
    }
}

yaml_test! {
    two_client_merge,
    two_client_sync,
    three_client_sync,
}
