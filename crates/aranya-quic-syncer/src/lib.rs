#![warn(missing_docs)]

//! An implementation of the syncer using QUIC.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    ops::DerefMut,
    sync::Arc,
    time::{Duration, SystemTime},
};

use aranya_buggy::{bug, Bug, BugExt};
use aranya_crypto::{Csprng, Rng};
use aranya_runtime::{
    engine::{Engine, Sink},
    storage::{GraphId, StorageProvider},
    ClientError, ClientState, PeerCache, Storage as _, StorageError, SubscribeResult, SyncError,
    SyncRequestMessage, SyncRequester, SyncResponder, SyncType, MAX_SYNC_MESSAGE_SIZE,
};
use heapless::{FnvIndexMap, Vec};
use quinn::{ClientConfig, ConnectError, ConnectionError, Endpoint, ReadToEndError, WriteError};
use tokio::{
    select,
    sync::{mpsc, Mutex as TMutex},
};
use tracing::error;

/// FNVIndexMap requires that the size be a power of 2.
const MAXIMUM_SUBSCRIPTIONS: usize = 32;

/// An error running the quic sync client or server.
#[derive(thiserror::Error, Debug)]
pub enum QuicSyncError {
    /// A sync protocol error.
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),
    /// An error interacting with the runtime client.
    #[error("client error: {0}")]
    Client(#[from] ClientError),
    /// A tls error from configuring certificates
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
    /// An error writing to the quic stream
    #[error("write error: {0}")]
    Write(#[from] WriteError),
    /// An error reading from the quic stream
    #[error("read error: {0}")]
    Read(#[from] ReadToEndError),
    /// An error when creating a connection
    #[error("connect error: {0}")]
    Connect(#[from] ConnectError),
    /// An error during connection
    #[error("connection error: {0}")]
    Connection(#[from] ConnectionError),
    /// An IO error binding the socket
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// An error using the storage
    #[error("storage error")]
    Storage(#[from] StorageError),
    /// A PostCard error
    #[error("postcard error")]
    PostCard(#[from] postcard::Error),
    /// An unexpected bug
    #[error(transparent)]
    Bug(#[from] Bug),
}

/// Runs a server listening for sync requests from other peers.
pub async fn run_syncer<EN, SP, S>(
    syncer: Arc<TMutex<Syncer<EN, SP, S>>>,
    endpoint: Endpoint,
    mut receiver: mpsc::UnboundedReceiver<GraphId>,
) where
    EN: Engine,
    SP: StorageProvider,
    S: Sink<<EN as Engine>::Effect>,
{
    loop {
        select! {
            Some(conn) = endpoint.accept() => {
                if let Err(e) = handle_connection(conn, syncer.clone()).await {
                    error!(cause = ?e, "sync error");
                }
            },
            Some(graph_id) = receiver.recv() => {
                if let Err(e) = syncer.lock().await.send_push(graph_id).await {
                    error!(cause = ?e, "send push error");
                }

            }
        }
    }
}

async fn handle_connection<EN, SP, S>(
    conn: quinn::Connecting,
    dispatcher: Arc<TMutex<Syncer<EN, SP, S>>>,
) -> Result<(), QuicSyncError>
where
    EN: Engine,
    SP: StorageProvider,
    S: Sink<<EN as Engine>::Effect>,
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
    handle_request(stream, dispatcher).await?;
    Ok(())
}

async fn handle_request<EN, SP, S>(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    syncer: Arc<TMutex<Syncer<EN, SP, S>>>,
) -> Result<(), QuicSyncError>
where
    EN: Engine,
    SP: StorageProvider,
    S: Sink<<EN as Engine>::Effect>,
{
    let req = recv.read_to_end(MAX_SYNC_MESSAGE_SIZE).await?;

    let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let target = {
        let len = syncer.lock().await.dispatch(&req, &mut buffer).await?;
        &buffer[..len]
    };

    if !target.is_empty() {
        send.write_all(target).await?;
        // Gracefully terminate the stream
        send.finish().await?;
    }
    Ok(())
}

/// A QUIC syncer client
pub struct Syncer<EN, SP, S>
where
    EN: Engine,
    SP: StorageProvider,
    S: Sink<<EN as Engine>::Effect>,
{
    endpoint: Endpoint,
    remote_heads: BTreeMap<SocketAddr, PeerCache>,
    sender: mpsc::UnboundedSender<GraphId>,
    subscriptions: FnvIndexMap<SocketAddr, Subscription, MAXIMUM_SUBSCRIPTIONS>,
    client: Arc<TMutex<ClientState<EN, SP>>>,
    sink: Arc<TMutex<S>>,
    server_addr: SocketAddr,
}

impl<EN, SP, S> Syncer<EN, SP, S>
where
    EN: Engine,
    SP: StorageProvider,
    S: Sink<<EN as Engine>::Effect>,
{
    /// Create a sync client with the given certificate chain.
    pub fn new(
        cert_chain: &[rustls::Certificate],
        client: Arc<TMutex<ClientState<EN, SP>>>,
        sink: Arc<TMutex<S>>,
        sender: mpsc::UnboundedSender<GraphId>,
        server_addr: SocketAddr,
    ) -> Result<Syncer<EN, SP, S>, QuicSyncError> {
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
            sender,
            subscriptions: FnvIndexMap::new(),
            client,
            sink,
            server_addr,
        })
    }

    /// Sync the specified graph with a peer at the given address.
    ///
    /// The sync will update your storage, not the peer's.
    pub async fn sync(
        &mut self,
        client: &mut ClientState<EN, SP>,
        mut syncer: SyncRequester<'_, SocketAddr>,
        sink: &mut S,
        storage_id: GraphId,
    ) -> Result<usize, QuicSyncError> {
        let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
        let mut received = 0;
        let heads = self.remote_heads.entry(syncer.server_addr()).or_default();
        let (len, _) = syncer.poll(&mut buffer, client.provider(), heads)?;
        if len > buffer.len() {
            bug!("length should fit in buffer");
        }

        let conn = self
            .endpoint
            .connect(syncer.server_addr(), "localhost")?
            .await?;
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
                self.push(storage_id)?;
            }
        }
        conn.close(0u32.into(), b"done");
        Ok(received)
    }

    /// Subscribe the specified graph to a peer at the given address.
    ///
    /// This will tell the peer to send new commands to us.
    pub async fn subscribe(
        &mut self,
        client: &mut ClientState<EN, SP>,
        mut sync_requester: SyncRequester<'_, SocketAddr>,
        remain_open: u64,
        max_bytes: u64,
        peer_addr: SocketAddr,
    ) -> Result<(), QuicSyncError> {
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let heads = self.remote_heads.entry(peer_addr).or_default();
        let len = sync_requester.subscribe(
            &mut buffer,
            client.provider(),
            heads,
            remain_open,
            max_bytes,
        )?;

        let conn = self.endpoint.connect(peer_addr, "localhost")?.await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        send.write_all(&buffer[0..len]).await?;
        send.finish().await?;
        let resp = recv.read_to_end(MAX_SYNC_MESSAGE_SIZE).await?;
        let result: SubscribeResult = postcard::from_bytes(&resp)?;
        conn.close(0u32.into(), b"done");
        match result {
            SubscribeResult::Success => Ok(()),
            SubscribeResult::TooManySubscriptions => bug!("TooManySubscriptions"),
        }
    }

    /// Unsubscribe the specified graph to a peer at the given address.
    pub async fn unsubscribe(
        &mut self,
        mut sync_requester: SyncRequester<'_, SocketAddr>,
        peer_addr: SocketAddr,
    ) -> Result<(), QuicSyncError> {
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = sync_requester.unsubscribe(&mut buffer)?;

        let conn = self.endpoint.connect(peer_addr, "localhost")?.await?;
        let (mut send, _) = conn.open_bi().await?;

        send.write_all(&buffer[0..len]).await?;
        send.finish().await?;
        conn.close(0u32.into(), b"done");
        Ok(())
    }

    /// Dispatch handles the sync request based on the sync type of the request
    /// and write the response to target.
    pub async fn dispatch(
        &mut self,
        data: &[u8],
        target: &mut [u8],
    ) -> Result<usize, QuicSyncError> {
        let (sync_type, remaining): (SyncType<SocketAddr>, &[u8]) =
            postcard::take_from_bytes(data)?;
        let len = match sync_type {
            SyncType::Poll { request, address } => {
                let response_cache = self.remote_heads.entry(address).or_default();
                let mut client = self.client.lock().await;
                let mut response_syncer = SyncResponder::new(self.server_addr);
                response_syncer.receive(request)?;
                assert!(response_syncer.ready());

                response_syncer.poll(target, client.provider(), response_cache)?
            }
            SyncType::Subscribe {
                remain_open,
                max_bytes,
                commands,
                address,
                storage_id,
            } => {
                self.subscriptions.retain(|_, s| !s.expired());
                match self.subscriptions.insert(
                    address,
                    Subscription {
                        close_time: SystemTime::now()
                            .checked_add(Duration::from_secs(remain_open))
                            .assume("must not overflow")?,
                        remaining_bytes: max_bytes,
                    },
                ) {
                    Ok(_) => {
                        let response_cache = self.remote_heads.entry(address).or_default();
                        let mut client = self.client.lock().await;
                        let storage = client.provider().get_storage(storage_id)?;
                        for command in commands {
                            // We only need to check commands that are a part of our graph.
                            if let Some(cmd_loc) = storage.get_location(command)? {
                                response_cache.add_command(storage, command, cmd_loc)?;
                            }
                        }
                        postcard::to_slice(&SubscribeResult::Success, target)?.len()
                    }
                    Err(_) => {
                        postcard::to_slice(&SubscribeResult::TooManySubscriptions, target)?.len()
                    }
                }
            }
            SyncType::Unsubscribe { address } => {
                self.subscriptions.remove(&address);
                0
            }
            SyncType::Push {
                message,
                storage_id,
                address,
            } => {
                let mut sync_requester = SyncRequester::new_session_id(
                    storage_id,
                    message.session_id(),
                    self.server_addr.to_string(),
                );
                if let Some(cmds) = sync_requester.get_sync_commands(message, remaining)? {
                    if !cmds.is_empty() {
                        {
                            let response_cache = self.remote_heads.entry(address).or_default();
                            let mut client = self.client.lock().await;
                            let mut trx = client.transaction(storage_id);
                            let mut sink_guard = self.sink.lock().await;
                            let sink = sink_guard.deref_mut();
                            client.add_commands(&mut trx, sink, &cmds, response_cache)?;
                            client.commit(&mut trx, sink)?;
                        }
                        self.push(storage_id)?;
                    }
                }
                0
            }
        };
        Ok(len)
    }

    /// Pushes commands to all subscribed peers.
    async fn send_push(&mut self, storage_id: GraphId) -> Result<(), QuicSyncError> {
        // Remove all expired subscriptions
        self.subscriptions.retain(|_, s| !s.expired());
        for (addr, subscription) in self.subscriptions.iter_mut() {
            let response_cache = self.remote_heads.entry(*addr).or_default();
            let mut dst = [0u8; 16];
            Rng.fill_bytes(&mut dst);
            let session_id = u128::from_le_bytes(dst);
            let mut response_syncer = SyncResponder::new(self.server_addr);
            let mut commands = Vec::new();
            commands
                .extend_from_slice(response_cache.heads())
                .expect("infallible error");
            response_syncer.receive(SyncRequestMessage::SyncRequest {
                session_id,
                storage_id,
                max_bytes: 0,
                commands,
            })?;
            assert!(response_syncer.ready());
            let mut target = [0u8; MAX_SYNC_MESSAGE_SIZE];
            let len = response_syncer.push(
                &mut target,
                self.client.lock().await.provider(),
                response_cache,
            )?;
            if len > 0 {
                if len as u64 > subscription.remaining_bytes {
                    subscription.remaining_bytes = 0;
                } else {
                    let message = &target[..len];

                    let conn = self.endpoint.connect(*addr, "localhost")?.await?;
                    let (mut send, _) = conn.open_bi().await?;
                    send.write_all(message).await?;
                    // Gracefully terminate the stream
                    send.finish().await?;
                    subscription.remaining_bytes = subscription
                        .remaining_bytes
                        .checked_sub(len as u64)
                        .assume("must not overflow")?;
                }
            }
        }
        Ok(())
    }

    /// pushes commands to all subscribed peers.
    pub fn push(&mut self, storage_id: GraphId) -> Result<(), SyncError> {
        if let Err(e) = self.sender.send(storage_id) {
            error!(cause = ?e, "push error");
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Subscription {
    // The time to close the request. The subscription should be closed when the
    // time is greater than the close time.
    // Calculated by adding remain open seconds to the time when the
    // request was made.
    close_time: SystemTime,
    // The number of remaining bytes to send. Every time a Push request is
    // sent this will be updated with the number of bytes sent.
    remaining_bytes: u64,
}

impl Subscription {
    fn expired(&self) -> bool {
        self.remaining_bytes == 0 || self.close_time < SystemTime::now()
    }
}
