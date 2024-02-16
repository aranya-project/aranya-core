//! This crate provides an example stand alone syncer.
//!
//! It creates two peers, a new graph, and Peer B syncs with Peer A and outputs the effects.
//!
//! Peer 1
//! cargo run --example quic_syncer -- --new --listen 127.0.0.1:5001 --peer 127.0.0.1:5002
//!
//! Peer 1 will print the new storage id. You will need this id for peer 2.
//!
//! Peer 2
//! cargo run --example quic_syncer -- --listen 127.0.0.1:5002 --peer 127.0.0.1:5001 --storage $STORAGE_ID

use std::{error::Error, fmt, fs, io, net::SocketAddr, ops::DerefMut, sync::Arc, thread, time};

use anyhow::{bail, Context, Result};
use clap::Parser;
use crypto::Rng;
use quinn::ServerConfig;
use runtime::{
    engine::Sink,
    protocol::{TestActions, TestEffect, TestEngine},
    quic_syncer::{run_syncer, Syncer},
    storage::memory::MemStorageProvider,
    ClientState, Id, SyncRequester,
};
use tokio::sync::Mutex as TMutex;

/// An error returned by the syncer.
#[derive(Debug)]
struct SyncError {
    error_msg: String,
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SyncError: {}", self.error_msg)
    }
}

impl Error for SyncError {
    fn description(&self) -> &str {
        &self.error_msg
    }
}

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
    #[clap(long = "storage")]
    storage_id: Option<Id>,
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

async fn sync_peer(
    client: &mut ClientState<TestEngine, MemStorageProvider>,
    syncer: &mut Syncer,
    sink: &mut PrintSink,
    storage_id: Id,
    server_addr: SocketAddr,
) {
    let sync_requester = SyncRequester::new(storage_id, &mut Rng::new());
    let fut = syncer.sync(client, sync_requester, sink, &storage_id, server_addr);
    match fut.await {
        Ok(_) => {}
        Err(e) => println!("err: {:?}", e),
    }
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    let dirs = directories_next::ProjectDirs::from("org", "spideroak", "aranya")
        .expect("unable to load directory");
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("error generating cert");
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der().expect("error serializing cert");
            fs::create_dir_all(path).context("failed to create certificate directory")?;
            fs::write(&cert_path, &cert).context("failed to write certificate")?;
            fs::write(&key_path, &key).context("failed to write private key")?;
            (cert, key)
        }
        Err(e) => {
            bail!("failed to read certificate: {}", e);
        }
    };

    let key = rustls::PrivateKey(key);
    let cert = rustls::Certificate(cert);
    let cert_chain = vec![cert];
    let mut syncer = Syncer::new(&cert_chain)?;

    let engine = TestEngine::new();
    let storage = MemStorageProvider::new();

    let client = Arc::new(TMutex::new(ClientState::new(engine, storage)));
    let mut sink = PrintSink {};
    let storage_id;
    if options.new_graph {
        let policy_data = 0_u64.to_be_bytes();
        let payload = (0, 0);
        storage_id = client
            .lock()
            .await
            .new_graph(policy_data.as_slice(), payload, &mut sink)
            .map_err(|e| SyncError {
                error_msg: e.to_string(),
            })?;
        println!("Storage id: {}", storage_id)
    } else if let Some(id) = options.storage_id {
        storage_id = id;
    } else {
        return Err(SyncError {
            error_msg: "storage id is missing".to_string(),
        }
        .into());
    }

    let mut server_config = ServerConfig::with_single_cert(cert_chain.clone(), key.clone())?;
    let transport_config =
        Arc::get_mut(&mut server_config.transport).expect("error creating transport config");
    transport_config.max_concurrent_uni_streams(0_u8.into());
    let endpoint =
        quinn::Endpoint::server(server_config, options.listen).map_err(|e| SyncError {
            error_msg: e.to_string(),
        })?;
    let task = tokio::spawn(run_syncer(client.clone(), endpoint));
    // Initial sync to sync the Init command
    if !options.new_graph {
        sync_peer(
            client.lock().await.deref_mut(),
            &mut syncer,
            &mut sink,
            storage_id,
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
                .action(&storage_id, &mut sink, action)
                .map_err(|e| SyncError {
                    error_msg: e.to_string(),
                })?;
        } else {
            sync_peer(
                client.lock().await.deref_mut(),
                &mut syncer,
                &mut sink,
                storage_id,
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
                println!("received {}", g)
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
