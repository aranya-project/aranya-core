//! This is a benchmark for syncing using the quic syncer. It benchmarks the amounts of time
//! to sync a command.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    ops::DerefMut,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use criterion::{criterion_group, criterion_main, Criterion};
use quinn::{Endpoint, ServerConfig};
use runtime::{
    memory::MemStorageProvider,
    protocol::{TestActions, TestEffect, TestEngine},
    quic_syncer::{run_syncer, sync},
    ClientState, Id, LockedSink, Sink, SyncRequester,
};
use spin::Mutex;
use tokio::{runtime::Runtime, sync::Mutex as TMutex};
use tokio_util::sync::CancellationToken;

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
    sink: &mut LockedSink<CountSink>,
) -> Result<Id> {
    let policy_data = 0_u64.to_be_bytes();
    let payload = (0, 0);
    Ok(client
        .new_graph(policy_data.as_slice(), payload, sink)
        .expect("unable to create graph"))
}

fn add_commands(
    client: &mut ClientState<TestEngine, MemStorageProvider>,
    storage_id: &Id,
    sink: &mut LockedSink<CountSink>,
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
            let session_id = 7;
            let cancel_token = CancellationToken::new();
            let mut response_sink = LockedSink::new(Arc::new(Mutex::new(CountSink::new())));
            let mut request_sink = LockedSink::new(Arc::new(Mutex::new(CountSink::new())));
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_der = cert.serialize_der().unwrap();
            let priv_key = cert.serialize_private_key_der();
            let priv_key = rustls::PrivateKey(priv_key);
            let cert_chain: Vec<rustls::Certificate> = vec![rustls::Certificate(cert_der)];
            let request_client = Arc::new(TMutex::new(create_client()));
            let response_client = Arc::new(TMutex::new(create_client()));

            let storage_id =
                new_graph(response_client.lock().await.deref_mut(), &mut response_sink)
                    .expect("creating graph failed");

            let mut server_config =
                ServerConfig::with_single_cert(cert_chain.clone(), priv_key.clone())
                    .expect("error creating server config");
            let transport_config = Arc::get_mut(&mut server_config.transport)
                .expect("error creating transport config");
            transport_config.max_concurrent_uni_streams(0_u8.into());
            let endpoint = Endpoint::server(
                server_config,
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            )
            .expect("error creating endpoint");
            let Ok(listen_addr) = endpoint.local_addr() else {
                panic!("error getting listen address");
            };
            let fut = run_syncer(
                cancel_token.clone(),
                response_client.clone(),
                storage_id,
                endpoint,
                session_id,
                response_sink.clone(),
            );
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    println!("sync error: {:?}", e)
                }
            });
            add_commands(
                response_client.lock().await.deref_mut(),
                &storage_id,
                &mut response_sink,
                iters,
            );

            // Start timing for benchmark
            let start = Instant::now();
            while request_sink.sink().lock().count() < iters.try_into().unwrap() {
                let syncer = SyncRequester::new(session_id, storage_id);
                let fut = sync(
                    request_client.lock().await,
                    syncer,
                    cert_chain.clone(),
                    &mut request_sink,
                    &storage_id,
                    listen_addr,
                );
                match fut.await {
                    Ok(_) => {}
                    Err(e) => println!("err: {:?}", e),
                }
            }
            let elapsed = start.elapsed();
            cancel_token.cancel();
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
