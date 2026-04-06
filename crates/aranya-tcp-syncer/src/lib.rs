//! A minimal TCP syncer implementation.
//!
//! This is a simple and minimal example of syncer implementation. It does not represent best
//! practice and omits encryption and authorization.

#![warn(missing_docs)]

use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    ops::DerefMut as _,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, SystemTime},
};

use anyhow::Result;
use aranya_crypto::{Csprng as _, Rng};
use aranya_runtime::{
    ClientState, Command as _, MAX_SYNC_MESSAGE_SIZE, PeerCache, SubscribeResult, SyncError,
    SyncRequestMessage, SyncRequester, SyncResponder, SyncType, TraversalBuffers,
    policy::{PolicyStore, Sink},
    storage::{GraphId, StorageProvider},
};
use buggy::{BugExt as _, bug};
use heapless::{FnvIndexMap, Vec};
use tracing::error;

/// FNVIndexMap requires that the size be a power of 2.
const MAXIMUM_SUBSCRIPTIONS: usize = 32;

/// Runs a server listening for sync requests from other peers.
pub fn run_syncer<PS, SP, S>(
    syncer: Arc<Mutex<Syncer<PS, SP, S>>>,
    server: TcpListener,
    receiver: mpsc::Receiver<GraphId>,
) where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
    Syncer<PS, SP, S>: Send,
{
    std::thread::scope(|s| {
        let syncer = &syncer;
        s.spawn(move || {
            while let Ok(graph_id) = receiver.recv() {
                if let Err(e) = syncer.lock().expect("poisoned").send_push(graph_id) {
                    error!(cause = ?e, "send push error");
                }
            }
        });
        while let Ok((stream, addr)) = server.accept() {
            if let Err(e) = handle_request(stream, addr, Arc::clone(syncer)) {
                error!(cause = ?e, "sync error");
            }
        }
    });
}

fn handle_request<PS, SP, S>(
    mut stream: TcpStream,
    _addr: SocketAddr,
    syncer: Arc<Mutex<Syncer<PS, SP, S>>>,
) -> Result<()>
where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
{
    let mut req = std::vec::Vec::new();
    stream.read_to_end(&mut req)?;
    let (peer_address, req) = postcard::take_from_bytes::<SocketAddr>(&req)?;
    let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
    let len = syncer
        .lock()
        .expect("poisoned")
        .dispatch(peer_address, req, &mut buffer)?;
    buffer.truncate(len);
    if len > 0 {
        stream.write_all(&buffer)?;
    }
    Ok(())
}

/// A TCP syncer client
pub struct Syncer<PS, SP, S>
where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
{
    remote_heads: BTreeMap<SocketAddr, PeerCache>,
    sender: mpsc::Sender<GraphId>,
    subscriptions: FnvIndexMap<(SocketAddr, GraphId), Subscription, MAXIMUM_SUBSCRIPTIONS>,
    client_state: Arc<Mutex<ClientState<PS, SP>>>,
    sink: Arc<Mutex<S>>,
    return_address: std::vec::Vec<u8>,
    buffers: TraversalBuffers,
}

impl<PS, SP, S> Syncer<PS, SP, S>
where
    PS: PolicyStore,
    SP: StorageProvider,
    S: Sink<<PS as PolicyStore>::Effect>,
{
    /// Create a sync client with the given certificate chain.
    pub fn new(
        client_state: Arc<Mutex<ClientState<PS, SP>>>,
        sink: Arc<Mutex<S>>,
        sender: mpsc::Sender<GraphId>,
        return_address: SocketAddr,
    ) -> Result<Self> {
        let return_address = postcard::to_allocvec(&return_address)?;
        Ok(Self {
            remote_heads: BTreeMap::new(),
            sender,
            subscriptions: FnvIndexMap::new(),
            client_state,
            sink,
            return_address,
            buffers: TraversalBuffers::new(),
        })
    }

    /// Sync the specified graph with a peer at the given address.
    ///
    /// The sync will update your storage, not the peer's.
    pub fn sync(
        &mut self,
        client: &mut ClientState<PS, SP>,
        peer_address: SocketAddr,
        mut syncer: SyncRequester,
        sink: &mut S,
        graph_id: GraphId,
    ) -> Result<usize> {
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let mut received = 0;
        let heads = self.remote_heads.entry(peer_address).or_default();
        let (len, _) = syncer.poll(
            &mut buffer,
            client.provider(),
            heads,
            &mut self.buffers.primary,
        )?;
        if len > buffer.len() {
            bug!("length should fit in buffer");
        }

        let mut stream = TcpStream::connect(peer_address)?;

        buffer.truncate(len);
        buffer.shrink_to_fit();
        stream.write_all(&self.return_address)?;
        stream.write_all(&buffer)?;
        stream.shutdown(Shutdown::Write)?;
        let mut received_data = std::vec::Vec::new();
        stream.read_to_end(&mut received_data)?;
        // An empty response means we're up to date and there's nothing to sync.
        if !received_data.is_empty()
            && let Some(cmds) = syncer.receive(&received_data)?
        {
            received = cmds.len();
            let mut trx = client.transaction(graph_id);
            client.add_commands(&mut trx, sink, &cmds, &mut self.buffers.primary)?;
            client.commit(trx, sink, &mut self.buffers.primary)?;
            client.update_heads(
                graph_id,
                cmds.iter().filter_map(|cmd| cmd.address().ok()),
                heads,
                &mut self.buffers.primary,
            )?;
            self.push(graph_id)?;
        }
        Ok(received)
    }

    /// Subscribe the specified graph to a peer at the given address.
    ///
    /// This will tell the peer to send new commands to us.
    pub fn subscribe(
        &mut self,
        client: &mut ClientState<PS, SP>,
        mut sync_requester: SyncRequester,
        remain_open: u64,
        max_bytes: u64,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let heads = self.remote_heads.entry(peer_addr).or_default();
        let len = sync_requester.subscribe(
            &mut buffer,
            client.provider(),
            heads,
            remain_open,
            max_bytes,
            &mut self.buffers.primary,
        )?;

        let mut stream = TcpStream::connect(peer_addr)?;

        buffer.truncate(len);
        stream.write_all(&self.return_address)?;
        stream.write_all(&buffer)?;
        stream.shutdown(Shutdown::Write)?;

        buffer.clear();
        stream.read_to_end(&mut buffer)?;
        if buffer.is_empty() {
            return Ok(());
        }
        let result: SubscribeResult = postcard::from_bytes(&buffer)?;
        match result {
            SubscribeResult::Success => Ok(()),
            SubscribeResult::TooManySubscriptions => bug!("TooManySubscriptions"),
        }
    }

    /// Unsubscribe the specified graph to a peer at the given address.
    pub fn unsubscribe(
        &mut self,
        mut sync_requester: SyncRequester,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = sync_requester.unsubscribe(&mut buffer)?;

        let mut stream = TcpStream::connect(peer_addr)?;

        buffer.truncate(len);
        stream.write_all(&self.return_address)?;
        stream.write_all(&buffer)?;
        Ok(())
    }

    /// Dispatch handles the sync request based on the sync type of the request
    /// and write the response to target.
    pub fn dispatch(
        &mut self,
        peer_address: SocketAddr,
        data: &[u8],
        target: &mut [u8],
    ) -> Result<usize> {
        let (sync_type, remaining): (SyncType, &[u8]) = postcard::take_from_bytes(data)?;
        let len = match sync_type {
            SyncType::Poll { request } => {
                let response_cache = self.remote_heads.entry(peer_address).or_default();
                let mut client = self.client_state.lock().expect("poisoned");
                let mut response_syncer = SyncResponder::new();
                response_syncer.receive(request)?;
                assert!(response_syncer.ready());

                response_syncer.poll(
                    target,
                    client.provider(),
                    response_cache,
                    &mut self.buffers,
                )?
            }
            SyncType::Subscribe {
                remain_open,
                max_bytes,
                commands,
                graph_id,
            } => {
                self.subscriptions.retain(|_, s| !s.expired());
                match self.subscriptions.insert(
                    (peer_address, graph_id),
                    Subscription {
                        close_time: SystemTime::now()
                            .checked_add(Duration::from_secs(remain_open))
                            .assume("must not overflow")?,
                        remaining_bytes: max_bytes,
                    },
                ) {
                    Ok(_) => {
                        let response_cache = self.remote_heads.entry(peer_address).or_default();
                        let mut client = self.client_state.lock().expect("poisoned");
                        client.update_heads(
                            graph_id,
                            commands.as_slice().iter().copied(),
                            response_cache,
                            &mut self.buffers.primary,
                        )?;
                        postcard::to_slice(&SubscribeResult::Success, target)?.len()
                    }
                    Err(_) => {
                        postcard::to_slice(&SubscribeResult::TooManySubscriptions, target)?.len()
                    }
                }
            }
            SyncType::Unsubscribe { graph_id } => {
                self.subscriptions.remove(&(peer_address, graph_id));
                0
            }
            SyncType::Push { message, graph_id } => {
                let mut sync_requester =
                    SyncRequester::new_session_id(graph_id, message.session_id());
                if let Some(cmds) = sync_requester.get_sync_commands(message, remaining)?
                    && !cmds.is_empty()
                {
                    {
                        let response_cache = self.remote_heads.entry(peer_address).or_default();
                        let mut client = self.client_state.lock().expect("poisoned");
                        let mut trx = client.transaction(graph_id);
                        let mut sink_guard = self.sink.lock().expect("poisoned");
                        let sink = sink_guard.deref_mut();
                        client.add_commands(&mut trx, sink, &cmds, &mut self.buffers.primary)?;
                        client.commit(trx, sink, &mut self.buffers.primary)?;
                        client.update_heads(
                            graph_id,
                            cmds.iter().filter_map(|cmd| cmd.address().ok()),
                            response_cache,
                            &mut self.buffers.primary,
                        )?;
                    }
                    self.push(graph_id)?;
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
    fn send_push(&mut self, graph_id: GraphId) -> Result<()> {
        // Remove all expired subscriptions
        self.subscriptions.retain(|_, s| !s.expired());
        for (&(addr, sub_graph_id), subscription) in &mut self.subscriptions {
            if graph_id != sub_graph_id {
                continue;
            }
            let response_cache = self.remote_heads.entry(addr).or_default();
            let mut dst = [0u8; 16];
            Rng.fill_bytes(&mut dst);
            let session_id = u128::from_le_bytes(dst);
            let mut response_syncer = SyncResponder::new();
            let mut commands = Vec::new();
            commands.extend(response_cache.heads().iter().map(|h| h.address()));
            response_syncer.receive(SyncRequestMessage::SyncRequest {
                session_id,
                graph_id,
                max_bytes: 0,
                commands,
            })?;
            assert!(response_syncer.ready());
            let mut target = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
            let len = response_syncer.push(
                &mut target,
                self.client_state.lock().expect("poisoned").provider(),
                &mut self.buffers,
            )?;
            if len > 0 {
                if len as u64 > subscription.remaining_bytes {
                    subscription.remaining_bytes = 0;
                } else {
                    target.truncate(len);

                    let mut stream = TcpStream::connect(addr)?;
                    stream.write_all(&self.return_address)?;
                    stream.write_all(&target)?;
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
    pub fn push(&mut self, graph_id: GraphId) -> Result<(), SyncError> {
        if let Err(e) = self.sender.send(graph_id) {
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
