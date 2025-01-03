//! This is a benchmark for syncing using the quic syncer. It benchmarks the amounts of time
//! to sync a command.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    ops::DerefMut,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use aranya_crypto::Rng;
use aranya_quic_syncer::{run_syncer, Syncer};
use aranya_runtime::{
    memory::MemStorageProvider,
    protocol::{TestActions, TestEffect, TestEngine},
    ClientState, GraphId, Sink, SyncRequester,
};
use criterion::{criterion_group, criterion_main, Criterion};
use quinn::{Endpoint, ServerConfig};
use rustls::{Certificate, PrivateKey};
use tokio::{
    runtime::Runtime,
    sync::{mpsc, Mutex as TMutex},
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

    fn new() -> CountSink {
        CountSink { count: 0 }
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

fn create_client() -> ClientState<TestEngine, MemStorageProvider> {
    let engine = TestEngine::new();
    let storage = MemStorageProvider::new();
    ClientState::new(engine, storage)
}

fn new_graph(
    client: &mut ClientState<TestEngine, MemStorageProvider>,
    sink: &mut CountSink,
) -> Result<GraphId> {
    let policy_data = 0_u64.to_be_bytes();
    Ok(client
        .new_graph(policy_data.as_slice(), TestActions::Init(0), sink)
        .expect("unable to create graph"))
}

fn add_commands(
    client: &mut ClientState<TestEngine, MemStorageProvider>,
    storage_id: GraphId,
    sink: &mut CountSink,
    n: u64,
) {
    for x in 0..n {
        client
            .action(storage_id, sink, TestActions::SetValue(0, x))
            .expect("unable to add command");
    }
}

// benchmark the time to sync a command.
fn sync_bench(c: &mut Criterion) {
    let rt = Runtime::new().expect("error creating runtime");

    c.bench_function("quic sync", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            // setup
            let request_sink = Arc::new(TMutex::new(CountSink::new()));
            let request_client = Arc::new(TMutex::new(create_client()));
            let (key, cert) = certs().expect("generating certs failed");
            let server_addr1 =
                get_server_addr(key.clone(), cert.clone()).expect("getting server addr failed");
            let (tx1, _) = mpsc::unbounded_channel();
            let syncer1 = Arc::new(TMutex::new(
                Syncer::new(
                    &[cert.clone()],
                    request_client.clone(),
                    request_sink.clone(),
                    tx1,
                    server_addr1.local_addr().expect("error getting local addr"),
                )
                .expect("Syncer creation must succeed"),
            ));

            let response_sink = Arc::new(TMutex::new(CountSink::new()));
            let response_client = Arc::new(TMutex::new(create_client()));
            let server_addr2 =
                get_server_addr(key.clone(), cert.clone()).expect("getting server addr failed");
            let addr2 = server_addr2.local_addr().expect("error getting local addr");
            let (tx2, rx2) = mpsc::unbounded_channel();
            let syncer2 = Arc::new(TMutex::new(
                Syncer::new(
                    &[cert.clone()],
                    response_client.clone(),
                    response_sink.clone(),
                    tx2,
                    server_addr2.local_addr().expect("error getting local addr"),
                )
                .expect("Syncer creation must succeed"),
            ));

            let storage_id = new_graph(
                response_client.lock().await.deref_mut(),
                response_sink.lock().await.deref_mut(),
            )
            .expect("creating graph failed");

            let task = tokio::spawn(run_syncer(syncer2.clone(), server_addr2, rx2));
            add_commands(
                response_client.lock().await.deref_mut(),
                storage_id,
                response_sink.lock().await.deref_mut(),
                iters,
            );

            // Start timing for benchmark
            let start = Instant::now();
            while request_sink.lock().await.count() < iters.try_into().unwrap() {
                let sync_requester = SyncRequester::new(storage_id, &Rng::new(), addr2);
                if let Err(e) = syncer1
                    .lock()
                    .await
                    .sync(
                        request_client.lock().await.deref_mut(),
                        sync_requester,
                        request_sink.lock().await.deref_mut(),
                        storage_id,
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

fn get_server_addr(key: PrivateKey, cert: Certificate) -> Result<Endpoint> {
    let mut server_config = ServerConfig::with_single_cert(vec![cert], key)?;
    let transport_config =
        Arc::get_mut(&mut server_config.transport).context("unique transport")?;
    transport_config.max_concurrent_uni_streams(0_u8.into());
    let endpoint = Endpoint::server(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )?;
    Ok(endpoint)
}

fn certs() -> Result<(PrivateKey, Certificate)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    Ok((
        PrivateKey(cert.serialize_private_key_der()),
        Certificate(cert.serialize_der()?),
    ))
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(10));
    targets = sync_bench
);
criterion_main!(benches);
