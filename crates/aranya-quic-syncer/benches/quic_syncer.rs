//! This is a benchmark for syncing using the quic syncer. It benchmarks the amounts of time
//! to sync a command.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use std::{
    ops::DerefMut as _,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use aranya_crypto::Rng;
use aranya_quic_syncer::{Syncer, run_syncer};
use aranya_runtime::{
    ClientState, GraphId, Sink, SyncRequester, TraversalBuffers,
    storage::linear::testing::MemStorageProvider,
    testing::protocol::{TestActions, TestEffect, TestPolicyStore},
};
use criterion::{Criterion, criterion_group, criterion_main};
use s2n_quic::Server;
use tokio::{
    runtime::Runtime,
    sync::{Mutex as TMutex, mpsc},
};

#[derive(Debug, Clone)]
/// Counts the number of effects which are consumed. Used to track the
/// number of commands which have been synced.
struct CountSink {
    count: usize,
}

impl CountSink {
    fn count(&self) -> usize {
        self.count
    }

    fn new() -> Self {
        Self { count: 0 }
    }
}

impl Sink<TestEffect> for CountSink {
    fn begin(&mut self) {
        //NOOP
    }

    fn consume(&mut self, _effect: TestEffect) {
        self.count += 1;
    }

    fn rollback(&mut self) {
        //NOOP
    }

    fn commit(&mut self) {
        //NOOP
    }
}

fn create_client() -> ClientState<TestPolicyStore, MemStorageProvider> {
    let policy_store = TestPolicyStore::new();
    let storage = MemStorageProvider::default();
    ClientState::new(policy_store, storage)
}

fn new_graph(
    client: &mut ClientState<TestPolicyStore, MemStorageProvider>,
    sink: &mut CountSink,
) -> Result<GraphId> {
    let policy_data = 0_u64.to_be_bytes();
    Ok(client
        .new_graph(policy_data.as_slice(), TestActions::Init(0), sink)
        .expect("unable to create graph"))
}

fn add_commands(
    client: &mut ClientState<TestPolicyStore, MemStorageProvider>,
    graph_id: GraphId,
    sink: &mut CountSink,
    n: u64,
) {
    for x in 0..n {
        client
            .action(graph_id, sink, TestActions::SetValue(0, x))
            .expect("unable to add command");
    }
}

fn get_server(cert: String, key: String) -> Result<Server> {
    let server = Server::builder()
        .with_tls((&cert[..], &key[..]))?
        .with_io("127.0.0.1:0")?
        .start()?;
    Ok(server)
}

// benchmark the time to sync a command.
fn sync_bench(c: &mut Criterion) {
    let rt = Runtime::new().expect("error creating runtime");

    c.bench_function("quic sync", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            // setup
            let request_sink = Arc::new(TMutex::new(CountSink::new()));
            let request_client = Arc::new(TMutex::new(create_client()));
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("error generating cert");
            let key = ck.key_pair.serialize_pem();
            let cert = ck.cert.pem();
            let server1 = get_server(cert.clone(), key.clone()).expect("error getting server");
            let (tx1, _) = mpsc::unbounded_channel();
            let syncer1 = Arc::new(TMutex::new(
                Syncer::new(
                    &*cert.clone(),
                    Arc::clone(&request_client),
                    Arc::clone(&request_sink),
                    tx1,
                    server1.local_addr().expect("error getting local addr"),
                )
                .expect("Syncer creation must succeed"),
            ));

            let response_sink = Arc::new(TMutex::new(CountSink::new()));
            let response_client = Arc::new(TMutex::new(create_client()));
            let server2 = get_server(cert.clone(), key.clone()).expect("error getting server");
            let server2_addr = server2.local_addr().expect("error getting local addr");
            let (tx2, rx2) = mpsc::unbounded_channel();
            let syncer2 = Arc::new(TMutex::new(
                Syncer::new(
                    &*cert,
                    Arc::clone(&response_client),
                    Arc::clone(&response_sink),
                    tx2,
                    server2_addr,
                )
                .expect("Syncer creation must succeed"),
            ));

            let graph_id = new_graph(
                response_client.lock().await.deref_mut(),
                response_sink.lock().await.deref_mut(),
            )
            .expect("creating graph failed");

            let task = tokio::spawn(run_syncer(Arc::clone(&syncer2), server2, rx2));
            add_commands(
                response_client.lock().await.deref_mut(),
                graph_id,
                response_sink.lock().await.deref_mut(),
                iters,
            );

            // Start timing for benchmark
            let start = Instant::now();
            while request_sink.lock().await.count() < iters.try_into().unwrap() {
                let mut buffers = TraversalBuffers::new();
                let sync_requester = SyncRequester::new(graph_id, &mut Rng::new(), &mut buffers);
                if let Err(e) = syncer1
                    .lock()
                    .await
                    .sync(
                        request_client.lock().await.deref_mut(),
                        server2_addr,
                        sync_requester,
                        request_sink.lock().await.deref_mut(),
                        graph_id,
                    )
                    .await
                {
                    println!("err: {:?}", e);
                }
            }
            let elapsed = start.elapsed();
            task.abort();
            elapsed
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(10));
    targets = sync_bench
);
criterion_main!(benches);
