//! This crate provides an example stand alone syncer.
//!
//! It creates two peers, a new graph, and Peer B syncs with Peer A and outputs the effects.
//!
//! Peer 1
//! cargo run --example quic_syncer -- --new --listen 127.0.0.1:5001 --peer 127.0.0.1:5002
//!
//! Peer 1 will print the new graph id. You will need this id for peer 2.
//!
//! Peer 2
//! cargo run --example quic_syncer -- --listen 127.0.0.1:5002 --peer 127.0.0.1:5001 --graph $graph_id

use std::{fs, io, net::SocketAddr, ops::DerefMut as _, sync::Arc, thread, time};

use anyhow::{Context as _, Result, bail};
use aranya_crypto::Rng;
use aranya_quic_syncer::{Syncer, run_syncer};
use aranya_runtime::{
    ClientState, GraphId, PolicyStore, StorageProvider, SyncRequester,
    policy::Sink,
    storage::linear::testing::MemStorageProvider,
    testing::protocol::{TestActions, TestEffect, TestPolicyStore},
};
use clap::Parser;
use s2n_quic::Server;
use tokio::sync::{Mutex as TMutex, mpsc};

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

async fn sync_peer<PS, SP, S>(
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
    let fut = syncer.sync(client, peer_addr, sync_requester, sink, graph_id);
    match fut.await {
        Ok(_) => {}
        Err(e) => println!("err: {:?}", e),
    }
}

fn get_server(cert: String, key: String, addr: SocketAddr) -> Result<Server> {
    let server = Server::builder()
        .with_tls((&cert[..], &key[..]))?
        .with_io(addr)?
        .start()?;
    Ok(server)
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    let dirs = directories_next::ProjectDirs::from("org", "spideroak", "aranya")
        .expect("unable to load directory");
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.pem");
    let key_path = path.join("key.pem");
    let (cert, key) = match fs::read_to_string(&cert_path)
        .and_then(|cert| fs::read_to_string(&key_path).map(|key| (cert, key)))
    {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("error generating cert");
            let key = ck.key_pair.serialize_pem();
            let cert = ck.cert.pem();
            fs::create_dir_all(path).context("failed to create certificate directory")?;
            fs::write(&cert_path, &cert).context("failed to write certificate")?;
            fs::write(&key_path, &key).context("failed to write private key")?;
            (cert, key)
        }
        Err(e) => {
            bail!("failed to read certificate: {}", e);
        }
    };

    let policy_store = TestPolicyStore::new();
    let storage = MemStorageProvider::default();

    let client = Arc::new(TMutex::new(ClientState::new(policy_store, storage)));
    let sink = Arc::new(TMutex::new(PrintSink {}));
    let server = get_server(cert.clone(), key, options.listen)?;
    let (tx1, _) = mpsc::unbounded_channel();
    let syncer = Arc::new(TMutex::new(Syncer::new(
        &cert[..],
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
            .await
            .new_graph(
                policy_data.as_slice(),
                TestActions::Init(0),
                sink.lock().await.deref_mut(),
            )
            .context("sync error")?;
        println!("Graph id: {}", graph_id);
    } else if let Some(id) = options.graph_id {
        graph_id = id;
    } else {
        bail!("graph id is missing");
    }

    let (_, rx1) = mpsc::unbounded_channel();
    let task = tokio::spawn(run_syncer(Arc::clone(&syncer), server, rx1));
    // Initial sync to sync the Init command
    if !options.new_graph {
        sync_peer(
            client.lock().await.deref_mut(),
            syncer.lock().await.deref_mut(),
            sink.lock().await.deref_mut(),
            graph_id,
            options.peer,
        )
        .await;
    }

    for i in 1..6 {
        // The creator will send a message which will be read by the peer
        if options.new_graph {
            let action = TestActions::SetValue(i, i);
            client
                .lock()
                .await
                .action(graph_id, sink.lock().await.deref_mut(), action)
                .context("sync error")?;
        } else {
            sync_peer(
                client.lock().await.deref_mut(),
                syncer.lock().await.deref_mut(),
                sink.lock().await.deref_mut(),
                graph_id,
                options.peer,
            )
            .await;
        }
        thread::sleep(time::Duration::from_secs(1));
    }
    thread::sleep(time::Duration::from_secs(5));
    task.abort();
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
