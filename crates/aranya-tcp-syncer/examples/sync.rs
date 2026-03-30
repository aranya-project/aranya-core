//! This crate provides an example stand alone syncer.
//!
//! It creates two peers, a new graph, and Peer B syncs with Peer A and outputs the effects.
//!
//! Peer 1
//! cargo run --example sync -- --new --listen 127.0.0.1:5001 --peer 127.0.0.1:5002
//!
//! Peer 1 will print the new graph id. You will need this id for peer 2.
//!
//! Peer 2
//! cargo run --example sync -- --listen 127.0.0.1:5002 --peer 127.0.0.1:5001 --graph $GRAPH_ID

#![allow(clippy::unwrap_used)]

use std::{
    net::{SocketAddr, TcpListener},
    ops::DerefMut as _,
    sync::{Arc, Mutex, mpsc},
    thread, time,
};

use anyhow::{Context as _, Result, bail};
use aranya_crypto::Rng;
use aranya_runtime::{
    ClientState, GraphId, PolicyStore, StorageProvider, SyncRequester,
    policy::Sink,
    storage::linear::testing::MemStorageProvider,
    testing::protocol::{TestActions, TestEffect, TestPolicyStore},
};
use aranya_tcp_syncer::{Syncer, run_syncer};
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "server")]
struct Opt {
    /// whether to create a new graph
    #[clap(long = "new")]
    new_graph: bool,
    /// Address to listen on
    #[clap(long = "listen")]
    listen: SocketAddr,
    /// Address of peer to connect to
    #[clap(long = "peer")]
    peer: SocketAddr,
    /// whether to create a new graph
    #[clap(long = "graph")]
    graph_id: Option<GraphId>,
}

fn main() {
    let opt = Opt::parse();
    let code = {
        if let Err(e) = run(opt) {
            eprint!("Error: {e}");
            1
        } else {
            0
        }
    };
    std::process::exit(code);
}

fn sync_peer<PS, SP, S>(
    client: &mut ClientState<PS, SP>,
    syncer: &mut Syncer<PS, SP, S>,
    sink: &mut S,
    graph_id: GraphId,
    peer_addr: SocketAddr,
) where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
{
    let sync_requester = SyncRequester::new(graph_id, Rng);
    match syncer.sync(client, peer_addr, sync_requester, sink, graph_id) {
        Ok(_) => {}
        Err(e) => println!("err: {:?}", e),
    }
}

fn get_server(addr: SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr)?)
}

fn run(options: Opt) -> Result<()> {
    let engine = TestPolicyStore::new();
    let storage = MemStorageProvider::default();

    let client = Arc::new(Mutex::new(ClientState::new(engine, storage)));
    let sink = Arc::new(Mutex::new(PrintSink {}));
    let server = get_server(options.listen)?;
    let (tx1, _) = mpsc::channel();
    let syncer = Arc::new(Mutex::new(Syncer::new(
        Arc::clone(&client),
        Arc::clone(&sink),
        tx1,
        server.local_addr()?,
    )?));

    let graph_id;
    if options.new_graph {
        let policy_data = 0_u64.to_be_bytes();
        graph_id = client
            .lock()
            .unwrap()
            .new_graph(
                policy_data.as_slice(),
                TestActions::Init(0),
                sink.lock().unwrap().deref_mut(),
            )
            .context("sync error")?;
        println!("Graph id: {}", graph_id);
    } else if let Some(id) = options.graph_id {
        graph_id = id;
    } else {
        bail!("graph id is missing");
    }

    let (_, rx1) = mpsc::channel();
    thread::spawn({
        let syncer = Arc::clone(&syncer);
        || run_syncer(syncer, server, rx1)
    });
    // Initial sync to sync the Init command
    if !options.new_graph {
        sync_peer(
            client.lock().unwrap().deref_mut(),
            syncer.lock().unwrap().deref_mut(),
            sink.lock().unwrap().deref_mut(),
            graph_id,
            options.peer,
        );
    }

    for i in 1..6 {
        // The creator will send a message which will be read by the peer
        if options.new_graph {
            let action = TestActions::SetValue(i, i);
            client
                .lock()
                .unwrap()
                .action(graph_id, sink.lock().unwrap().deref_mut(), action)
                .context("sync error")?;
        } else {
            sync_peer(
                client.lock().unwrap().deref_mut(),
                syncer.lock().unwrap().deref_mut(),
                sink.lock().unwrap().deref_mut(),
                graph_id,
                options.peer,
            );
        }
        thread::sleep(time::Duration::from_secs(1));
    }
    thread::sleep(time::Duration::from_secs(5));
    println!("done");
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PrintSink {}

impl Sink<TestEffect> for PrintSink {
    fn begin(&mut self) {
        //NOOP
    }

    fn consume(&mut self, effect: TestEffect) {
        match effect {
            TestEffect::Got(g) => {
                println!("received {}", g);
            }
        }
    }

    fn rollback(&mut self) {
        //NOOP
    }

    fn commit(&mut self) {
        //NOOP
    }
}
