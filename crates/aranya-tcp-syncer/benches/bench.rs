//! This is a benchmark for syncing using the tcp syncer. It benchmarks the amounts of time
//! to sync a command.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use std::{
    net::{Ipv4Addr, TcpListener},
    ops::DerefMut as _,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use aranya_crypto::Rng;
use aranya_runtime::{
    ClientState, GraphId, Sink, SyncRequester,
    storage::linear::testing::MemStorageProvider,
    testing::protocol::{TestActions, TestEffect, TestPolicyStore},
};
use aranya_tcp_syncer::{Syncer, run_syncer};
use criterion::{Criterion, criterion_group, criterion_main};

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

fn get_server() -> Result<TcpListener> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?)
}

// benchmark the time to sync a command.
fn sync_bench(c: &mut Criterion) {
    c.bench_function("tcp sync", |b| {
        b.iter_custom(|iters| {
            // setup
            let request_sink = Arc::new(Mutex::new(CountSink::new()));
            let request_client = Arc::new(Mutex::new(create_client()));
            let server1 = get_server().expect("error getting server");
            let (tx1, _) = mpsc::channel();
            let syncer1 = Arc::new(Mutex::new(
                Syncer::new(
                    Arc::clone(&request_client),
                    Arc::clone(&request_sink),
                    tx1,
                    server1.local_addr().expect("error getting local addr"),
                    &std::env::temp_dir(),
                )
                .expect("Syncer creation must succeed"),
            ));

            let response_sink = Arc::new(Mutex::new(CountSink::new()));
            let response_client = Arc::new(Mutex::new(create_client()));
            let server2 = get_server().expect("error getting server");
            let server2_addr = server2.local_addr().expect("error getting local addr");
            let (tx2, rx2) = mpsc::channel();
            let syncer2 = Arc::new(Mutex::new(
                Syncer::new(
                    Arc::clone(&response_client),
                    Arc::clone(&response_sink),
                    tx2,
                    server2_addr,
                    &std::env::temp_dir(),
                )
                .expect("Syncer creation must succeed"),
            ));

            let graph_id = new_graph(
                response_client.lock().unwrap().deref_mut(),
                response_sink.lock().unwrap().deref_mut(),
            )
            .expect("creating graph failed");

            let _task = thread::spawn(|| run_syncer(syncer2, server2, rx2));
            add_commands(
                response_client.lock().unwrap().deref_mut(),
                graph_id,
                response_sink.lock().unwrap().deref_mut(),
                iters,
            );

            // Start timing for benchmark
            let start = Instant::now();
            while request_sink.lock().unwrap().count() < iters.try_into().unwrap() {
                let sync_requester = SyncRequester::new(graph_id, Rng);
                syncer1
                    .lock()
                    .unwrap()
                    .sync(
                        request_client.lock().unwrap().deref_mut(),
                        server2_addr,
                        sync_requester,
                        request_sink.lock().unwrap().deref_mut(),
                        graph_id,
                    )
                    .expect("sync failed");
            }
            start.elapsed()
            // TODO(jdygert): We can't kill the thread and we can't close the socket to make the
            // thread exit normally. One fix might be exposing a way to accept only one connection.
            // It seems like this doesn't really affect the benchmark though so it's fine for now.
            // If we had a larger sample size there could be exhaustion issues.
            // task.abort();
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(10));
    targets = sync_bench
);
criterion_main!(benches);
