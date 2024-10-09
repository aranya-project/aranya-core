#![warn(missing_docs)]

//! An implementation of the syncer using QUIC.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use aranya_runtime::{
    engine::{Engine, Sink},
    storage::{GraphId, StorageProvider},
    ClientError, ClientState, PeerCache, SyncError, SyncRequester, SyncResponder,
    MAX_SYNC_MESSAGE_SIZE,
};
use quinn::{ClientConfig, ConnectError, ConnectionError, Endpoint, ReadToEndError, WriteError};
use tokio::sync::Mutex as TMutex;
use tracing::error;

/// An error running the quic sync client or server.
#[derive(thiserror::Error, Debug)]
pub enum QuicSyncError {
    /// A sync protocol error.
    #[error("sync error")]
    Sync(#[from] SyncError),
    /// An error interacting with the runtime client.
    #[error("client error")]
    Client(#[from] ClientError),
    /// A tls error from configuring certificates
    #[error("rustls error")]
    Rustls(#[from] rustls::Error),
    /// An error writing to the quic stream
    #[error("write error")]
    Write(#[from] WriteError),
    /// An error reading from the quic stream
    #[error("read error")]
    Read(#[from] ReadToEndError),
    /// An error when creating a connection
    #[error("connect error")]
    Connect(#[from] ConnectError),
    /// An error during connection
    #[error("connection error")]
    Connection(#[from] ConnectionError),
    /// An IO error binding the socket
    #[error("io error")]
    Io(#[from] std::io::Error),
}

/// Runs a server listening for sync requests from other peers.
pub async fn run_syncer<EN, SP>(client: Arc<TMutex<ClientState<EN, SP>>>, endpoint: Endpoint)
where
    EN: Engine,
    SP: StorageProvider,
{
    let mut remote_heads: BTreeMap<SocketAddr, PeerCache> = BTreeMap::new();
    while let Some(conn) = endpoint.accept().await {
        let remote = conn.remote_address();
        let heads = remote_heads.entry(remote).or_default();
        if let Err(e) = handle_connection(conn, client.clone(), heads).await {
            error!(cause = ?e, "sync error");
        }
    }
}

async fn handle_connection<EN, SP>(
    conn: quinn::Connecting,
    client: Arc<TMutex<ClientState<EN, SP>>>,
    remote_heads: &mut PeerCache,
) -> Result<(), QuicSyncError>
where
    EN: Engine,
    SP: StorageProvider,
{
    let connection = conn.await?;
    let stream = connection.accept_bi().await;
    let stream = match stream {
        Err(ConnectionError::ApplicationClosed { .. }) => {
            return Ok(());
        }
        Err(e) => {
            return Err(e.into());
        }
        Ok(s) => s,
    };
    handle_request(stream, client, remote_heads).await?;
    Ok(())
}

async fn handle_request<EN, SP>(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    client: Arc<TMutex<ClientState<EN, SP>>>,
    remote_heads: &mut PeerCache,
) -> Result<(), QuicSyncError>
where
    EN: Engine,
    SP: StorageProvider,
{
    let req = recv.read_to_end(MAX_SYNC_MESSAGE_SIZE).await?;
    let mut response_syncer = SyncResponder::new();

    let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let target = {
        let mut client = client.lock().await;
        response_syncer.receive(&req)?;

        let len = response_syncer.poll(&mut buffer, client.provider(), remote_heads)?;
        &buffer[..len]
    };

    send.write_all(target).await?;
    // Gracefully terminate the stream
    send.finish().await?;
    Ok(())
}

/// A QUIC syncer client
pub struct Syncer {
    endpoint: Endpoint,
    remote_heads: BTreeMap<SocketAddr, PeerCache>,
}

impl Syncer {
    /// Create a sync client with the given certificate chain.
    pub fn new(cert_chain: &[rustls::Certificate]) -> Result<Syncer, QuicSyncError> {
        let mut certs = rustls::RootCertStore::empty();
        for cert in cert_chain {
            certs.add(cert)?;
        }
        let client_cfg = ClientConfig::with_root_certificates(certs);
        let client_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
        let mut endpoint = Endpoint::client(client_addr)?;
        endpoint.set_default_client_config(client_cfg);
        Ok(Syncer {
            endpoint,
            remote_heads: BTreeMap::new(),
        })
    }

    /// Sync the specified graph with a peer at the given address.
    ///
    /// The sync will update your storage, not the peer's.
    pub async fn sync<S, EN, SP>(
        &mut self,
        client: &mut ClientState<EN, SP>,
        mut syncer: SyncRequester<'_>,
        sink: &mut S,
        storage_id: GraphId,
        server_addr: SocketAddr,
    ) -> Result<usize, QuicSyncError>
    where
        EN: Engine,
        SP: StorageProvider,
        S: Sink<<EN as Engine>::Effect>,
    {
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let mut received = 0;
        let heads = self.remote_heads.entry(server_addr).or_default();
        let (len, _) = syncer.poll(&mut buffer, client.provider(), heads)?;
        if len > buffer.len() {
            return Err(SyncError::SerilizeError.into());
        }

        let conn = self.endpoint.connect(server_addr, "localhost")?.await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        send.write_all(&buffer[0..len]).await?;
        send.finish().await?;
        let resp = recv.read_to_end(MAX_SYNC_MESSAGE_SIZE).await?;
        // An empty response means we're up to date and there's nothing to sync.
        if !resp.is_empty() {
            if let Some(cmds) = syncer.receive(&resp)? {
                received = cmds.len();
                let mut trx = client.transaction(storage_id);
                client.add_commands(&mut trx, sink, &cmds, heads)?;
                client.commit(&mut trx, sink)?;
            }
        }
        conn.close(0u32.into(), b"done");
        Ok(received)
    }
}
