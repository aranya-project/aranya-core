#![warn(missing_docs)]

//! An implementation of the syncer using QUIC.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use aranya_crypto::{Csprng, Rng};
use aranya_runtime::{
    COMMAND_RESPONSE_MAX, ClientError, ClientState, Command, MAX_SYNC_MESSAGE_SIZE, PeerCache,
    StorageError, SubscribeResult, SyncError, SyncRequestMessage, SyncRequester, SyncResponder,
    SyncType,
    engine::{Engine, Sink},
    storage::{GraphId, StorageProvider},
};
use buggy::{Bug, BugExt, bug};
use heapless::{FnvIndexMap, Vec};
use s2n_quic::{
    Client, Connection, Server,
    client::Connect,
    connection, provider,
    stream::{self, BidirectionalStream},
};
use tokio::{
    select,
    sync::{Mutex as TMutex, mpsc},
};
use tracing::error;

/// FNVIndexMap requires that the size be a power of 2.
const MAXIMUM_SUBSCRIPTIONS: usize = 32;

/// An error running the quic sync client or server.
#[derive(Debug, thiserror::Error)]
pub enum QuicSyncError {
    /// A sync protocol error.
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),
    /// An error interacting with the runtime client.
    #[error("client error: {0}")]
    Client(#[from] ClientError),
    /// An error writing to the quic stream
    #[error("connect error: {0}")]
    Connect(#[from] connection::Error),
    /// An error using a stream
    #[error("stream error: {0}")]
    Stream(#[from] stream::Error),
    /// An error using a provider
    #[error("provider start error: {0}")]
    ProviderStart(#[from] provider::StartError),
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

impl From<core::convert::Infallible> for QuicSyncError {
    fn from(value: core::convert::Infallible) -> Self {
        match value {}
    }
}

/// Runs a server listening for sync requests from other peers.
pub async fn run_syncer<EN, SP, S>(
    syncer: Arc<TMutex<Syncer<EN, SP, S>>>,
    mut server: Server,
    mut receiver: mpsc::UnboundedReceiver<GraphId>,
) where
    EN: Engine,
    SP: StorageProvider,
    S: Sink<<EN as Engine>::Effect>,
{
    loop {
        select! {
            Some(conn) = server.accept() => {
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
    mut conn: Connection,
    dispatcher: Arc<TMutex<Syncer<EN, SP, S>>>,
) -> Result<(), QuicSyncError>
where
    EN: Engine,
    SP: StorageProvider,
    S: Sink<<EN as Engine>::Effect>,
{
    let stream = conn.accept_bidirectional_stream().await;
    let stream = match stream {
        Err(connection::Error::EndpointClosing { .. }) => {
            return Ok(());
        }
        Err(e) => {
            return Err(e.into());
        }
        Ok(None) => {
            return Ok(());
        }
        Ok(Some(s)) => s,
    };
    handle_request(stream, dispatcher).await?;
    Ok(())
}

async fn handle_request<EN, SP, S>(
    mut stream: BidirectionalStream,
    syncer: Arc<TMutex<Syncer<EN, SP, S>>>,
) -> Result<(), QuicSyncError>
where
    EN: Engine,
    SP: StorageProvider,
    S: Sink<<EN as Engine>::Effect>,
{
    if let Ok(Some(req)) = stream.receive().await {
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = syncer.lock().await.dispatch(&req, &mut buffer).await?;
        buffer.truncate(len);

        if len > 0 {
            stream.send(buffer.into()).await?;
        }
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
    quic_client: Client,
    remote_heads: BTreeMap<SocketAddr, PeerCache>,
    sender: mpsc::UnboundedSender<GraphId>,
    subscriptions: FnvIndexMap<SocketAddr, Subscription, MAXIMUM_SUBSCRIPTIONS>,
    client_state: Arc<TMutex<ClientState<EN, SP>>>,
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
    pub fn new<T: provider::tls::Provider>(
        cert: T,
        client_state: Arc<TMutex<ClientState<EN, SP>>>,
        sink: Arc<TMutex<S>>,
        sender: mpsc::UnboundedSender<GraphId>,
        server_addr: SocketAddr,
    ) -> Result<Self, QuicSyncError> {
        let client = Client::builder()
            .with_tls(cert)?
            .with_io("0.0.0.0:0")?
            .start()?;
        Ok(Self {
            quic_client: client,
            remote_heads: BTreeMap::new(),
            sender,
            subscriptions: FnvIndexMap::new(),
            client_state,
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
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let mut received = 0;
        let heads = self.remote_heads.entry(syncer.server_addr()).or_default();
        let (len, _) = syncer.poll(&mut buffer, client.provider(), heads)?;
        if len > buffer.len() {
            bug!("length should fit in buffer");
        }

        let mut conn = self
            .quic_client
            .connect(Connect::new(syncer.server_addr()).with_server_name("localhost"))
            .await?;
        conn.keep_alive(true)?;
        let mut stream = conn.open_bidirectional_stream().await?;

        buffer.truncate(len);
        buffer.shrink_to_fit();
        stream.send(buffer.into()).await?;
        let mut received_data: Vec<u8, MAX_SYNC_MESSAGE_SIZE> = Vec::new();
        while let Some(chunk) = stream.receive().await? {
            received_data
                .extend_from_slice(&chunk)
                .expect("Failed to extend received data from slice");
        }
        // An empty response means we're up to date and there's nothing to sync.
        if !received_data.is_empty() {
            if let Some(cmds) = syncer.receive(&received_data)? {
                received = cmds.len();
                let mut trx = client.transaction(storage_id);
                client.add_commands(&mut trx, sink, &cmds)?;
                client.commit(&mut trx, sink)?;
                let addresses: Vec<_, COMMAND_RESPONSE_MAX> =
                    cmds.iter().filter_map(|cmd| cmd.address().ok()).collect();
                client.update_heads(storage_id, addresses, heads)?;
                self.push(storage_id)?;
            }
        }
        conn.close(0u32.into());
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

        let mut conn = self
            .quic_client
            .connect(Connect::new(peer_addr).with_server_name("localhost"))
            .await?;
        conn.keep_alive(true)?;
        let mut stream = conn.open_bidirectional_stream().await?;

        buffer.truncate(len);
        buffer.shrink_to_fit();
        stream.send(buffer.into()).await?;
        if let Some(resp) = stream.receive().await? {
            let result: SubscribeResult = postcard::from_bytes(&resp)?;
            match result {
                SubscribeResult::Success => Ok(()),
                SubscribeResult::TooManySubscriptions => bug!("TooManySubscriptions"),
            }
        } else {
            Ok(())
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

        let mut conn = self
            .quic_client
            .connect(Connect::new(peer_addr).with_server_name("localhost"))
            .await?;
        conn.keep_alive(true)?;
        let mut stream = conn.open_bidirectional_stream().await?;

        buffer.truncate(len);
        buffer.shrink_to_fit();
        stream.send(buffer.into()).await?;
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
                let mut client = self.client_state.lock().await;
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
                        self.client_state.lock().await.update_heads(
                            storage_id,
                            commands,
                            response_cache,
                        )?;
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
                            let mut client = self.client_state.lock().await;
                            let mut trx = client.transaction(storage_id);
                            let mut sink = self.sink.lock().await;
                            client.add_commands(&mut trx, &mut *sink, &cmds)?;
                            client.commit(&mut trx, &mut *sink)?;
                            drop(sink);
                            let addresses: Vec<_, COMMAND_RESPONSE_MAX> =
                                cmds.iter().filter_map(|cmd| cmd.address().ok()).collect();
                            client.update_heads(storage_id, addresses, response_cache)?;
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
        for (addr, subscription) in &mut self.subscriptions {
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
            let mut target = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
            let len =
                response_syncer.push(&mut target, self.client_state.lock().await.provider())?;
            if len > 0 {
                if len as u64 > subscription.remaining_bytes {
                    subscription.remaining_bytes = 0;
                } else {
                    target.truncate(len);

                    let mut conn = self
                        .quic_client
                        .connect(Connect::new(*addr).with_server_name("localhost"))
                        .await?;
                    conn.keep_alive(true)?;
                    let mut stream = conn.open_bidirectional_stream().await?;

                    stream.send(target.into()).await?;
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
