#![warn(missing_docs)]

//! An implementation of the syncer using QUIC.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    ops::DerefMut as _,
    sync::Arc,
    time::{Duration, SystemTime},
};

use aranya_crypto::{Csprng as _, Rng};
use aranya_runtime::{
    ClientError, ClientState, Command as _, MAX_SYNC_MESSAGE_SIZE, PeerCache, StorageError,
    SubscribeResult, SyncError, SyncRequestMessage, SyncRequester, SyncResponder, SyncType,
    policy::{PolicyStore, Sink},
    storage::{GraphId, StorageProvider},
};
use buggy::{Bug, BugExt as _, bug};
use bytes::Bytes;
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
pub async fn run_syncer<PS, SP, S>(
    syncer: Arc<TMutex<Syncer<PS, SP, S>>>,
    mut server: Server,
    mut receiver: mpsc::UnboundedReceiver<GraphId>,
) where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
{
    loop {
        select! {
            Some(conn) = server.accept() => {
                if let Err(e) = handle_connection(conn, Arc::clone(&syncer)).await {
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

async fn handle_connection<PS, SP, S>(
    mut conn: Connection,
    dispatcher: Arc<TMutex<Syncer<PS, SP, S>>>,
) -> Result<(), QuicSyncError>
where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
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

async fn handle_request<PS, SP, S>(
    mut stream: BidirectionalStream,
    syncer: Arc<TMutex<Syncer<PS, SP, S>>>,
) -> Result<(), QuicSyncError>
where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
{
    if let Ok(Some(req)) = stream.receive().await {
        let (peer_address, req) = postcard::take_from_bytes::<SocketAddr>(&req)?;
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = syncer
            .lock()
            .await
            .dispatch(peer_address, req, &mut buffer)
            .await?;
        buffer.truncate(len);

        if len > 0 {
            stream.send(buffer.into()).await?;
        }
    }
    Ok(())
}

/// A QUIC syncer client
pub struct Syncer<PS, SP, S>
where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
{
    quic_client: Client,
    remote_heads: BTreeMap<SocketAddr, PeerCache>,
    sender: mpsc::UnboundedSender<GraphId>,
    subscriptions: FnvIndexMap<SocketAddr, Subscription, MAXIMUM_SUBSCRIPTIONS>,
    client_state: Arc<TMutex<ClientState<PS, SP>>>,
    sink: Arc<TMutex<S>>,
    return_address: Bytes,
}

impl<PS, SP, S> Syncer<PS, SP, S>
where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
{
    /// Create a sync client with the given certificate chain.
    pub fn new<T: provider::tls::Provider>(
        cert: T,
        client_state: Arc<TMutex<ClientState<PS, SP>>>,
        sink: Arc<TMutex<S>>,
        sender: mpsc::UnboundedSender<GraphId>,
        return_address: SocketAddr,
    ) -> Result<Self, QuicSyncError> {
        let client = Client::builder()
            .with_tls(cert)?
            .with_io("0.0.0.0:0")?
            .start()?;
        let return_address = Bytes::from(postcard::to_allocvec(&return_address)?);
        Ok(Self {
            quic_client: client,
            remote_heads: BTreeMap::new(),
            sender,
            subscriptions: FnvIndexMap::new(),
            client_state,
            sink,
            return_address,
        })
    }

    /// Sync the specified graph with a peer at the given address.
    ///
    /// The sync will update your storage, not the peer's.
    pub async fn sync(
        &mut self,
        client: &mut ClientState<PS, SP>,
        peer_address: SocketAddr,
        mut syncer: SyncRequester,
        sink: &mut S,
        storage_id: GraphId,
    ) -> Result<usize, QuicSyncError> {
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let mut received = 0;
        let heads = self.remote_heads.entry(peer_address).or_default();
        let (len, _) = syncer.poll(&mut buffer, client.provider(), heads)?;
        if len > buffer.len() {
            bug!("length should fit in buffer");
        }

        let mut conn = self
            .quic_client
            .connect(Connect::new(peer_address).with_server_name("localhost"))
            .await?;
        conn.keep_alive(true)?;
        let mut stream = conn.open_bidirectional_stream().await?;

        buffer.truncate(len);
        buffer.shrink_to_fit();
        stream
            .send_vectored(&mut [self.return_address.clone(), buffer.into()])
            .await?;
        let mut received_data: Vec<u8, MAX_SYNC_MESSAGE_SIZE> = Vec::new();
        while let Some(chunk) = stream.receive().await? {
            received_data
                .extend_from_slice(&chunk)
                .expect("Failed to extend received data from slice");
        }
        // An empty response means we're up to date and there's nothing to sync.
        if !received_data.is_empty()
            && let Some(cmds) = syncer.receive(&received_data)?
        {
            received = cmds.len();
            let mut trx = client.transaction(storage_id);
            client.add_commands(&mut trx, sink, &cmds)?;
            client.commit(&mut trx, sink)?;
            client.update_heads(
                storage_id,
                cmds.iter().filter_map(|cmd| cmd.address().ok()),
                heads,
            )?;
            self.push(storage_id)?;
        }
        conn.close(0u32.into());
        Ok(received)
    }

    /// Subscribe the specified graph to a peer at the given address.
    ///
    /// This will tell the peer to send new commands to us.
    pub async fn subscribe(
        &mut self,
        client: &mut ClientState<PS, SP>,
        mut sync_requester: SyncRequester,
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
        stream
            .send_vectored(&mut [self.return_address.clone(), buffer.into()])
            .await?;
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
        mut sync_requester: SyncRequester,
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
        stream
            .send_vectored(&mut [self.return_address.clone(), buffer.into()])
            .await?;
        Ok(())
    }

    /// Dispatch handles the sync request based on the sync type of the request
    /// and write the response to target.
    pub async fn dispatch(
        &mut self,
        peer_address: SocketAddr,
        data: &[u8],
        target: &mut [u8],
    ) -> Result<usize, QuicSyncError> {
        let (sync_type, remaining) = postcard::take_from_bytes::<SyncType>(data)?;
        let len = match sync_type {
            SyncType::Poll { request } => {
                let response_cache = self.remote_heads.entry(peer_address).or_default();
                let mut client = self.client_state.lock().await;
                let mut response_syncer = SyncResponder::new();
                response_syncer.receive(request)?;
                assert!(response_syncer.ready());

                response_syncer.poll(target, client.provider(), response_cache)?
            }
            SyncType::Subscribe {
                remain_open,
                max_bytes,
                commands,
                storage_id,
            } => {
                self.subscriptions.retain(|_, s| !s.expired());
                match self.subscriptions.insert(
                    peer_address,
                    Subscription {
                        close_time: SystemTime::now()
                            .checked_add(Duration::from_secs(remain_open))
                            .assume("must not overflow")?,
                        remaining_bytes: max_bytes,
                    },
                ) {
                    Ok(_) => {
                        let response_cache = self.remote_heads.entry(peer_address).or_default();
                        let mut client = self.client_state.lock().await;
                        client.update_heads(
                            storage_id,
                            commands.as_slice().iter().copied(),
                            response_cache,
                        )?;
                        postcard::to_slice(&SubscribeResult::Success, target)?.len()
                    }
                    Err(_) => {
                        postcard::to_slice(&SubscribeResult::TooManySubscriptions, target)?.len()
                    }
                }
            }
            SyncType::Unsubscribe {} => {
                self.subscriptions.remove(&peer_address);
                0
            }
            SyncType::Push {
                message,
                storage_id,
            } => {
                let mut sync_requester =
                    SyncRequester::new_session_id(storage_id, message.session_id());
                if let Some(cmds) = sync_requester.get_sync_commands(message, remaining)?
                    && !cmds.is_empty()
                {
                    {
                        let response_cache = self.remote_heads.entry(peer_address).or_default();
                        let mut client = self.client_state.lock().await;
                        let mut trx = client.transaction(storage_id);
                        let mut sink_guard = self.sink.lock().await;
                        let sink = sink_guard.deref_mut();
                        client.add_commands(&mut trx, sink, &cmds)?;
                        client.commit(&mut trx, sink)?;
                        client.update_heads(
                            storage_id,
                            cmds.iter().filter_map(|cmd| cmd.address().ok()),
                            response_cache,
                        )?;
                    }
                    self.push(storage_id)?;
                }
                0
            }
            SyncType::Hello(_) => {
                // Hello messages are fire-and-forget, no response needed
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
            let mut response_syncer = SyncResponder::new();
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

                    stream
                        .send_vectored(&mut [self.return_address.clone(), target.into()])
                        .await?;
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
