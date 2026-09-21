//! A sans-I/O syncer state machine; see [`Syncer`].

use alloc::vec::Vec;
use core::fmt;

use aranya_crypto::Csprng;

use crate::{
    Address, ClientError, ClientState, RuntimeBuffers, Transaction,
    command::CommandExt as _,
    policy::{PolicyStore, Sink},
    storage::{GraphId, Spill, StorageError, StorageProvider},
    sync::{
        COMMAND_RESPONSE_MAX, HelloMessage, PeerCache, SubscribeResponse, SyncError, SyncHello,
        SyncIncoming, SyncRequester, SyncResponder, wire::SyncType,
    },
};

mod config;
mod schedule;
#[cfg(test)]
mod schedule_tests;
mod slots;
#[cfg(test)]
mod tests;
mod time;

pub use config::{HelloConfig, Limits, LimitsBuilder, PeerConfig, PushConfig};
use schedule::{Due, Gate, Schedule, SubscriberLimitReached};
use slots::DueKind;
pub use slots::{FixedSlots, HeapSlots, OutOfSlots, SyncSlot, SyncSlots};
pub use time::SyncInstant;

/// What an [`Outbound`] message is.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OutboundKind {
    /// A poll request. Expects a reply: feed it to [`Syncer::handle_reply`].
    PollRequest,
    /// A push-subscribe request. Expects a [`SubscribeResponse`] reply: feed
    /// it to [`Syncer::handle_reply`].
    Subscribe,
    /// Cancels our push subscription with the peer.
    Unsubscribe,
    /// Commands pushed to a subscriber.
    Push,
    /// A hello-subscribe request. The protocol defines no reply.
    HelloSubscribe,
    /// Cancels our hello subscription with the peer.
    HelloUnsubscribe,
    /// A hello notification carrying our current head.
    Hello,
}

impl OutboundKind {
    /// Whether the peer answers this message on the same connection.
    pub fn expects_reply(self) -> bool {
        matches!(self, Self::PollRequest | Self::Subscribe)
    }
}

/// Opaque handle tying a reply or delivery outcome back to the [`Outbound`]
/// it answers. Never travels over the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token<A> {
    graph_id: GraphId,
    peer: A,
    kind: OutboundKind,
    seq: u32,
}

impl<A> Token<A> {
    /// The graph the message concerns.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    /// The peer the message is addressed to.
    pub fn peer(&self) -> &A {
        &self.peer
    }

    /// What the message is.
    pub fn kind(&self) -> OutboundKind {
        self.kind
    }
}

/// A message the caller should send, already encoded into its buffer by
/// [`Syncer::next_outbound`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outbound<A> {
    token: Token<A>,
    len: usize,
}

impl<A> Outbound<A> {
    /// The peer to send to.
    pub fn peer(&self) -> &A {
        &self.token.peer
    }

    /// The graph the message concerns.
    pub fn graph_id(&self) -> GraphId {
        self.token.graph_id
    }

    /// What the message is.
    pub fn kind(&self) -> OutboundKind {
        self.token.kind
    }

    /// Bytes written to the output buffer; send `out[..len]`.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Always false: an outbound with nothing to send is never produced.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether to read a reply and pass it to [`Syncer::handle_reply`].
    pub fn expects_reply(&self) -> bool {
        self.token.kind.expects_reply()
    }

    /// The handle to pass to [`Syncer::handle_reply`] or
    /// [`Syncer::complete`].
    pub fn token(&self) -> Token<A>
    where
        A: Clone,
    {
        self.token.clone()
    }

    /// Consumes the outbound, yielding its token.
    pub fn into_token(self) -> Token<A> {
        self.token
    }
}

/// How delivery of an [`Outbound`] went, for [`Syncer::complete`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The bytes were handed to the transport.
    Sent,
    /// The message could not be delivered, or its reply never came.
    Failed,
}

/// Result of applying an inbound message or reply.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Inbound {
    /// `out[..len]` holds a reply; send it back on the same connection. May
    /// be zero-length when the protocol has nothing to say.
    Reply { len: usize },
    /// New commands were committed to the graph.
    Committed { count: usize },
    /// State was updated; nothing to send, nothing committed.
    Handled,
    /// The peer refused our push subscription; it will be retried at the
    /// next renewal. Call [`Syncer::push_unsubscribe`] to stop trying.
    SubscribeRejected,
    /// Dropped without effect.
    Ignored(IgnoreReason),
}

/// Why an inbound message or reply was dropped.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IgnoreReason {
    /// The token does not name an outstanding request: the request timed
    /// out, was reported failed, or was answered already.
    StaleToken,
    /// A push arrived from a peer we have no active subscription with.
    NotSubscribed,
    /// A hello-subscribe was refused at the subscriber cap. The protocol
    /// has no reply to say so.
    SubscriberLimit,
    /// A push arrived for a graph with a poll session open; committing it
    /// would invalidate that session's transaction. The poll fetches the
    /// same commands.
    Busy,
}

/// Error from the syncer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncerError {
    /// A protocol primitive failed.
    #[error(transparent)]
    Sync(#[from] SyncError),
    /// Storage or policy rejected a commit.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// The caller-supplied [`SyncSlots`] are full.
    #[error("out of syncer slots")]
    OutOfSlots,
}

impl From<OutOfSlots> for SyncerError {
    fn from(OutOfSlots: OutOfSlots) -> Self {
        Self::OutOfSlots
    }
}

impl From<StorageError> for SyncerError {
    fn from(err: StorageError) -> Self {
        Self::Client(ClientError::StorageError(err))
    }
}

/// Everything a call that touches storage needs, borrowed for the call.
pub struct SyncContext<'a, PS, SP: StorageProvider, K, R, MS> {
    /// Graph storage and policy.
    pub client: &'a mut ClientState<PS, SP>,
    /// Receives the effects of committed commands.
    pub sink: &'a mut K,
    /// Scratch buffers for graph traversal and braiding.
    pub buffers: &'a mut RuntimeBuffers<SP::Segment>,
    /// Source of session ids.
    pub rng: &'a R,
    /// Creates overflow storage for a braid; see [`ClientState::commit`].
    pub make_spill: MS,
}

/// An open poll session: one transaction across however many rounds it
/// takes the peer to run out of commands.
struct PollSession<PS, SP: StorageProvider, A> {
    token: Token<A>,
    trx: Transaction<SP, PS>,
    requester: SyncRequester,
    /// Addresses received over the session, recorded in the peer's cache
    /// once committed.
    received: Vec<Address>,
    added: usize,
    /// Reported failed via [`Syncer::complete`]; settled at the next call
    /// that has storage.
    aborted: bool,
}

/// A push with more segments to send than fit in one message.
struct PushSession<A> {
    token: Token<A>,
    responder: SyncResponder,
}

/// Records `addrs` as held by the peer whose cache this is. A graph we do
/// not hold yet has nothing to record against; that is not an error.
fn record_heads<PS, SP, I>(
    client: &mut ClientState<PS, SP>,
    graph_id: GraphId,
    addrs: I,
    cache: &mut PeerCache,
    buffer: &mut crate::storage::TraversalBuffer,
) -> Result<(), SyncerError>
where
    PS: PolicyStore,
    SP: StorageProvider,
    I: IntoIterator<Item = Address>,
    I::IntoIter: DoubleEndedIterator,
{
    match client.update_heads(graph_id, addrs, cache, buffer) {
        Ok(()) | Err(ClientError::StorageError(StorageError::NoSuchStorage)) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// The cache used when a peer has no slot: always empty.
static EMPTY_CACHE: PeerCache = PeerCache::new();

/// A sans-I/O syncer state machine.
///
/// [`Syncer`] decides when to sync with which peer, tracks push and hello
/// subscriptions in both directions, runs poll sessions to convergence,
/// commits what arrives, and fans pushes and hellos out afterwards. It
/// performs no I/O and reads no clock: the caller supplies a transport (bytes
/// in, bytes out, a peer identity per connection), storage (a
/// [`ClientState`] borrowed for each call via [`SyncContext`]), and the
/// current time (any [`SyncInstant`]).
///
/// # Driving
///
/// ```ignore
/// loop {
///     let now = clock();
///     let mut cx = SyncContext { client, sink, buffers, rng, make_spill };
///
///     // Inbound: apply what peers sent; forward any reply on the same connection.
///     while let Some((peer, frame)) = transport.try_recv() {
///         if let Inbound::Reply { len } =
///             syncer.handle_incoming(peer, frame, now, &mut cx, out)?
///         {
///             transport.reply(peer, &out[..len])?;
///         }
///     }
///
///     // Outbound: send what is due; hand replies and failures back.
///     while let Some(ob) = syncer.next_outbound(now, &mut cx, out)? {
///         match transport.send(ob.peer(), &out[..ob.len()]) {
///             Err(_) => syncer.complete(ob.token(), Outcome::Failed, now),
///             Ok(()) if ob.expects_reply() => match transport.recv_reply(ob.peer(), reply) {
///                 Ok(n) => { syncer.handle_reply(ob.token(), &reply[..n], now, &mut cx)?; }
///                 Err(_) => syncer.complete(ob.token(), Outcome::Failed, now),
///             },
///             Ok(()) => syncer.complete(ob.token(), Outcome::Sent, now),
///         }
///     }
///
///     sleep_until(syncer.next_deadline(), transport.wake());
/// }
/// ```
///
/// Per-peer state lives in caller-supplied [`SyncSlots`]: [`HeapSlots`]
/// grows on demand, [`FixedSlots`] is inline and allocation-free.
/// [`Limits`] clamps every remotely supplied duration and caps how many
/// slots remote peers can occupy.
pub struct Syncer<PS, SP: StorageProvider, A, T, S = HeapSlots<A, T>> {
    schedule: Schedule<A, T, S>,
    /// At most one poll session is open at a time across all peers.
    poll_session: Option<PollSession<PS, SP, A>>,
    /// At most one multi-message push is in progress at a time.
    push_session: Option<PushSession<A>>,
    /// Cache for responding to peers that have no slot.
    scratch_cache: PeerCache,
    seq: u32,
}

impl<PS, SP, A, T, S> fmt::Debug for Syncer<PS, SP, A, T, S>
where
    SP: StorageProvider,
    A: fmt::Debug,
    T: fmt::Debug,
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Syncer")
            .field("schedule", &self.schedule)
            .field(
                "poll_session",
                &self.poll_session.as_ref().map(|s| &s.token),
            )
            .field(
                "push_session",
                &self.push_session.as_ref().map(|s| &s.token),
            )
            .finish_non_exhaustive()
    }
}

impl<PS, SP, A, T> Syncer<PS, SP, A, T>
where
    SP: StorageProvider,
    A: Clone + Eq,
    T: SyncInstant,
{
    /// Creates a syncer with [`Limits::default`], backed by [`HeapSlots`].
    #[must_use]
    pub fn new() -> Self {
        Self::new_in(HeapSlots::new())
    }

    /// Creates a syncer with the given limits, backed by [`HeapSlots`].
    #[must_use]
    pub fn with_limits(limits: Limits) -> Self {
        Self::with_limits_in(limits, HeapSlots::new())
    }
}

impl<PS, SP, A, T, S> Default for Syncer<PS, SP, A, T, S>
where
    SP: StorageProvider,
    A: Clone + Eq,
    T: SyncInstant,
    S: SyncSlots<A, T> + Default,
{
    fn default() -> Self {
        Self::new_in(S::default())
    }
}

impl<PS, SP, A, T, S> Syncer<PS, SP, A, T, S>
where
    SP: StorageProvider,
    A: Clone + Eq,
    T: SyncInstant,
    S: SyncSlots<A, T>,
{
    /// Creates a syncer with [`Limits::default`], storing per-peer state in
    /// the caller-supplied `slots`.
    #[must_use]
    pub fn new_in(slots: S) -> Self {
        Self::with_limits_in(Limits::default(), slots)
    }

    /// Creates a syncer with the given limits, storing per-peer state in the
    /// caller-supplied `slots`.
    #[must_use]
    pub fn with_limits_in(limits: Limits, slots: S) -> Self {
        Self {
            schedule: Schedule::new(limits, slots),
            poll_session: None,
            push_session: None,
            scratch_cache: PeerCache::new(),
            seq: 0,
        }
    }

    /// The limits in force (after normalization).
    pub fn limits(&self) -> &Limits {
        self.schedule.limits()
    }

    // ---- control -----------------------------------------------------

    /// Registers (or reconfigures) `peer` for polling. With
    /// [`PeerConfig::sync_now`] the first poll is due immediately; otherwise
    /// one interval from `now`, if recurring.
    pub fn add_peer(
        &mut self,
        peer: A,
        graph_id: GraphId,
        cfg: PeerConfig,
        now: T,
    ) -> Result<(), OutOfSlots> {
        self.schedule.add_peer(peer, graph_id, cfg, now)
    }

    /// Unregisters `peer` from polling. A session in flight completes and
    /// commits; its result is simply not recorded against the peer. Returns
    /// whether it was registered.
    pub fn remove_peer(&mut self, peer: &A, graph_id: GraphId) -> bool {
        self.schedule.remove_peer(peer, graph_id)
    }

    /// Schedules an immediate poll of a registered `peer`, keeping any
    /// recurring interval. During an open session the poll starts once the
    /// session ends. Returns whether the peer is registered.
    pub fn sync_now(&mut self, peer: &A, graph_id: GraphId, now: T) -> bool {
        self.schedule.sync_now(peer, graph_id, now)
    }

    /// Asks `peer` to push its updates to us. A [`OutboundKind::Subscribe`]
    /// is due immediately and renewed at half the lease until
    /// [`push_unsubscribe`](Self::push_unsubscribe). A refusal is reported as
    /// [`Inbound::SubscribeRejected`] and retried at the next renewal.
    pub fn push_subscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        cfg: PushConfig,
        now: T,
    ) -> Result<(), OutOfSlots> {
        self.schedule.push_subscribe(peer, graph_id, cfg, now)
    }

    /// Cancels our push subscription with `peer`: renewals stop and one
    /// [`OutboundKind::Unsubscribe`] is due immediately, even if nothing
    /// was tracked, so teardown is idempotent.
    pub fn push_unsubscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        now: T,
    ) -> Result<(), OutOfSlots> {
        self.schedule.push_unsubscribe(peer, graph_id, now)
    }

    /// Asks `peer` to send us hello notifications. A
    /// [`OutboundKind::HelloSubscribe`] is due immediately and renewed
    /// blindly at half the lease until
    /// [`hello_unsubscribe`](Self::hello_unsubscribe).
    pub fn hello_subscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        cfg: HelloConfig,
        now: T,
    ) -> Result<(), OutOfSlots> {
        self.schedule.hello_subscribe(peer, graph_id, cfg, now)
    }

    /// Cancels our hello subscription with `peer`; one
    /// [`OutboundKind::HelloUnsubscribe`] is due immediately.
    pub fn hello_unsubscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        now: T,
    ) -> Result<(), OutOfSlots> {
        self.schedule.hello_unsubscribe(peer, graph_id, now)
    }

    /// Tells the syncer `graph_id` changed locally (after the application's
    /// own [`ClientState::action`]): a push to every live push subscriber
    /// and a hello to every hello subscriber past its debounce become due.
    /// Changes received through sync are noticed automatically.
    pub fn notify_local_change(&mut self, graph_id: GraphId, now: T) {
        self.schedule.notify_local_change(graph_id, now);
    }

    /// Drops all state for `graph_id`: registrations, subscriptions in both
    /// directions, caches, and any open session (its transaction is
    /// discarded).
    pub fn remove_graph(&mut self, graph_id: GraphId) {
        self.schedule.remove_graph(graph_id);
        if self
            .poll_session
            .as_ref()
            .is_some_and(|s| s.token.graph_id == graph_id)
        {
            self.poll_session = None;
        }
        if self
            .push_session
            .as_ref()
            .is_some_and(|s| s.token.graph_id == graph_id)
        {
            self.push_session = None;
        }
    }

    /// Every registered poll peer with its configuration, for callers that
    /// persist registrations themselves.
    pub fn peers(&self) -> impl Iterator<Item = (GraphId, &A, PeerConfig)> {
        self.schedule.peers()
    }

    /// The earliest timer: when [`next_outbound`](Self::next_outbound) next
    /// has work. Sleep until then or until the transport has input.
    pub fn next_deadline(&self) -> Option<T> {
        self.schedule.next_deadline()
    }

    /// Reports how delivering `token`'s message went.
    ///
    /// For a message that [`expects_reply`](Outbound::expects_reply), call
    /// this only with [`Outcome::Failed`]; success is reported by
    /// [`handle_reply`](Self::handle_reply). A failed poll round backs off;
    /// a failed subscribe waits for its renewal; a failed push is retried
    /// at the next local change. Unknown or stale tokens are ignored.
    pub fn complete(&mut self, token: Token<A>, outcome: Outcome, now: T) {
        if outcome != Outcome::Failed {
            return;
        }
        match token.kind {
            OutboundKind::PollRequest => {
                if let Some(session) = &mut self.poll_session
                    && session.token == token
                {
                    session.aborted = true;
                    self.schedule
                        .poll_finished(token.graph_id, &token.peer, false, now);
                }
            }
            OutboundKind::Subscribe => {
                self.schedule
                    .push_subscribe_settled(token.graph_id, &token.peer, token.seq);
            }
            OutboundKind::Push => {
                if self.push_session.as_ref().is_some_and(|s| s.token == token) {
                    self.push_session = None;
                }
            }
            OutboundKind::Unsubscribe
            | OutboundKind::HelloSubscribe
            | OutboundKind::HelloUnsubscribe
            | OutboundKind::Hello => {}
        }
    }

    fn next_token(&mut self, graph_id: GraphId, peer: A, kind: OutboundKind) -> Token<A> {
        self.seq = self.seq.wrapping_add(1);
        Token {
            graph_id,
            peer,
            kind,
            seq: self.seq,
        }
    }

    fn gates(&self) -> (Gate<A>, Gate<A>) {
        let gate = |token: Option<&Token<A>>| match token {
            None => Gate::Open,
            Some(t) => Gate::Only(t.graph_id, t.peer.clone()),
        };
        (
            gate(self.poll_session.as_ref().map(|s| &s.token)),
            gate(self.push_session.as_ref().map(|s| &s.token)),
        )
    }

    fn reply_deadline(&self, now: T) -> T {
        now.saturating_add(self.schedule.limits().reply_timeout)
    }
}

impl<PS, SP, A, T, S> Syncer<PS, SP, A, T, S>
where
    PS: PolicyStore,
    SP: StorageProvider,
    A: Clone + Eq,
    T: SyncInstant,
    S: SyncSlots<A, T>,
{
    /// Produces the next due outbound message, encoded into `out`, or `None`
    /// when nothing is due at `now`.
    ///
    /// Drain until `None`, performing each message's I/O, then sleep until
    /// [`next_deadline`](Self::next_deadline). `out` must hold at least
    /// [`MAX_SYNC_MESSAGE_SIZE`](crate::sync::MAX_SYNC_MESSAGE_SIZE) bytes.
    ///
    /// An error is also a failed round for the peer involved and is safe to
    /// log and continue from.
    pub fn next_outbound<K, R, F, MS>(
        &mut self,
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
        out: &mut [u8],
    ) -> Result<Option<Outbound<A>>, SyncerError>
    where
        K: Sink<PS::Effect>,
        R: Csprng,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        self.settle(now, cx)?;
        loop {
            let (poll_gate, push_gate) = self.gates();
            let Some(Due {
                kind,
                graph_id,
                peer,
            }) = self.schedule.next_due(now, &poll_gate, &push_gate)
            else {
                return Ok(None);
            };
            let emitted = match kind {
                DueKind::Poll => self.start_poll_round(graph_id, peer, now, cx, out)?,
                DueKind::PollTimeout => {
                    self.abort_poll_session(graph_id, &peer, now, cx)?;
                    None
                }
                DueKind::Push => self.emit_push(graph_id, peer, now, cx, out)?,
                DueKind::ScheduledHello => Some(self.emit_hello(graph_id, peer, cx, out)?),
                DueKind::PushRenewal => self.emit_push_subscribe(graph_id, peer, now, cx, out)?,
                DueKind::PushCancel => Some(self.emit_push_unsubscribe(graph_id, peer, out)?),
                DueKind::HelloRenewal => self.emit_hello_subscribe(graph_id, peer, out)?,
                DueKind::HelloCancel => Some(self.emit_hello_unsubscribe(graph_id, peer, out)?),
                // Settled inside the schedule; never surfaces.
                DueKind::SubscribeTimeout => None,
            };
            if let Some(outbound) = emitted {
                return Ok(Some(outbound));
            }
        }
    }

    /// Applies a message received from `peer`. A reply, if the protocol
    /// calls for one, is encoded into `out`.
    ///
    /// `peer` is whatever identity the transport authenticated; the syncer
    /// keys all state by it. Decode failures leave no partial state.
    pub fn handle_incoming<K, R, F, MS>(
        &mut self,
        peer: A,
        data: &[u8],
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
        out: &mut [u8],
    ) -> Result<Inbound, SyncerError>
    where
        K: Sink<PS::Effect>,
        R: Csprng,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        self.settle(now, cx)?;
        match SyncIncoming::decode(data)? {
            SyncIncoming::Poll(poll) => {
                let graph_id = poll.graph_id();
                let mut responder = SyncResponder::new();
                responder.receive(poll)?;
                let Self {
                    schedule,
                    scratch_cache,
                    ..
                } = self;
                let cache = match graph_id.and_then(|g| schedule.cache_mut(g, &peer)) {
                    Some(cache) => cache,
                    None => {
                        *scratch_cache = PeerCache::new();
                        scratch_cache
                    }
                };
                let len = match responder.poll(
                    out,
                    cx.client.provider(),
                    cache,
                    &mut cx.buffers.traversal,
                ) {
                    Ok(len) => len,
                    Err(SyncError::Storage(StorageError::NoSuchStorage)) => 0,
                    Err(err) => return Err(err.into()),
                };
                Ok(Inbound::Reply { len })
            }
            SyncIncoming::Subscribe(sub) => {
                let graph_id = sub.graph_id();
                let response = match self.schedule.add_push_subscriber(
                    peer.clone(),
                    graph_id,
                    sub.remain_open(),
                    sub.max_bytes(),
                    now,
                ) {
                    Ok(()) => {
                        if let Some(cache) = self.schedule.cache_mut(graph_id, &peer) {
                            // The sample is authoritative: it replaces
                            // anything assumed from earlier pushes.
                            *cache = PeerCache::new();
                            record_heads(
                                cx.client,
                                graph_id,
                                sub.heads().iter(),
                                cache,
                                &mut cx.buffers.traversal.primary,
                            )?;
                        }
                        SubscribeResponse::Success
                    }
                    Err(SubscriberLimitReached) => SubscribeResponse::TooManySubscriptions,
                };
                Ok(Inbound::Reply {
                    len: response.encode_to(out)?,
                })
            }
            SyncIncoming::Unsubscribe(unsub) => {
                self.schedule
                    .remove_push_subscriber(&peer, unsub.graph_id());
                Ok(Inbound::Handled)
            }
            SyncIncoming::Push(push) => {
                let graph_id = push.graph_id();
                if !self.schedule.has_active_push_request(graph_id, &peer) {
                    return Ok(Inbound::Ignored(IgnoreReason::NotSubscribed));
                }
                if self
                    .poll_session
                    .as_ref()
                    .is_some_and(|s| s.token.graph_id == graph_id)
                {
                    return Ok(Inbound::Ignored(IgnoreReason::Busy));
                }
                let mut requester = SyncRequester::new_session_id(graph_id, push.session_id());
                let Some(cmds) = requester.receive_push(push)? else {
                    return Ok(Inbound::Handled);
                };
                if cmds.is_empty() {
                    return Ok(Inbound::Handled);
                }
                let mut trx = cx.client.transaction(graph_id);
                let added =
                    cx.client
                        .add_commands(&mut trx, cx.sink, &cmds, cx.buffers, &cx.make_spill)?;
                let new = cx.client.commit(trx, cx.sink, cx.buffers, &cx.make_spill)?;
                if let Some(cache) = self.schedule.cache_mut(graph_id, &peer) {
                    record_heads(
                        cx.client,
                        graph_id,
                        cmds.iter().filter_map(|cmd| cmd.address().ok()),
                        cache,
                        &mut cx.buffers.traversal.primary,
                    )?;
                }
                if new {
                    self.schedule.notify_local_change(graph_id, now);
                }
                Ok(Inbound::Committed { count: added })
            }
            SyncIncoming::Hello(SyncHello::Subscribe(sub)) => {
                match self.schedule.add_hello_subscriber(
                    peer,
                    sub.graph_id(),
                    sub.graph_change_delay(),
                    sub.duration(),
                    sub.schedule_delay(),
                    now,
                ) {
                    Ok(()) => Ok(Inbound::Handled),
                    Err(SubscriberLimitReached) => {
                        Ok(Inbound::Ignored(IgnoreReason::SubscriberLimit))
                    }
                }
            }
            SyncIncoming::Hello(SyncHello::Unsubscribe(unsub)) => {
                self.schedule
                    .remove_hello_subscriber(&peer, unsub.graph_id());
                Ok(Inbound::Handled)
            }
            SyncIncoming::Hello(SyncHello::Hello(hello)) => {
                let graph_id = hello.graph_id();
                if self.schedule.wants_hello_sync(graph_id, &peer)
                    && cx.client.should_sync_on_hello(
                        graph_id,
                        hello.head(),
                        &mut cx.buffers.traversal.primary,
                    )?
                {
                    self.schedule.sync_now(&peer, graph_id, now);
                }
                Ok(Inbound::Handled)
            }
        }
    }

    /// Applies the reply to an outbound that
    /// [`expects_reply`](Outbound::expects_reply).
    ///
    /// A poll reply's commands join the session's transaction; a full reply
    /// schedules another round, anything less commits the session. A
    /// transport that streams several responses per request may call this
    /// repeatedly with the same token. A subscribe reply settles the
    /// request. An error is a failed round for the peer involved.
    pub fn handle_reply<K, R, F, MS>(
        &mut self,
        token: Token<A>,
        data: &[u8],
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
    ) -> Result<Inbound, SyncerError>
    where
        K: Sink<PS::Effect>,
        R: Csprng,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        self.settle(now, cx)?;
        match token.kind {
            OutboundKind::PollRequest => {
                if !self.poll_session.as_ref().is_some_and(|s| s.token == token) {
                    return Ok(Inbound::Ignored(IgnoreReason::StaleToken));
                }
                match self.apply_poll_reply(data, now, cx) {
                    Ok(inbound) => Ok(inbound),
                    Err(err) => {
                        if let Some(session) = self.poll_session.take() {
                            self.schedule
                                .poll_finished(token.graph_id, &token.peer, false, now);
                            self.finish_failed_session(session, now, cx)?;
                        }
                        Err(err)
                    }
                }
            }
            OutboundKind::Subscribe => {
                if !self
                    .schedule
                    .push_subscribe_settled(token.graph_id, &token.peer, token.seq)
                {
                    return Ok(Inbound::Ignored(IgnoreReason::StaleToken));
                }
                Ok(match SubscribeResponse::decode(data)? {
                    SubscribeResponse::Success => Inbound::Handled,
                    SubscribeResponse::TooManySubscriptions => Inbound::SubscribeRejected,
                })
            }
            OutboundKind::Unsubscribe
            | OutboundKind::Push
            | OutboundKind::HelloSubscribe
            | OutboundKind::HelloUnsubscribe
            | OutboundKind::Hello => Ok(Inbound::Ignored(IgnoreReason::StaleToken)),
        }
    }

    // ---- poll session ------------------------------------------------

    /// Settles a session that [`complete`](Self::complete) marked failed
    /// while no storage was at hand.
    fn settle<K, R, F, MS>(
        &mut self,
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
    ) -> Result<(), SyncerError>
    where
        K: Sink<PS::Effect>,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        if self.poll_session.as_ref().is_some_and(|s| s.aborted)
            && let Some(session) = self.poll_session.take()
        {
            self.finish_failed_session(session, now, cx)?;
        }
        Ok(())
    }

    /// Ends a failed session, keeping the completed rounds when they commit
    /// cleanly and discarding them otherwise. The schedule has already
    /// applied backoff.
    fn finish_failed_session<K, R, F, MS>(
        &mut self,
        session: PollSession<PS, SP, A>,
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
    ) -> Result<(), SyncerError>
    where
        K: Sink<PS::Effect>,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        if session.added == 0 {
            return Ok(());
        }
        let graph_id = session.token.graph_id;
        let peer = session.token.peer;
        let Ok(new) = cx
            .client
            .commit(session.trx, cx.sink, cx.buffers, &cx.make_spill)
        else {
            // Partial progress that does not commit is discarded.
            return Ok(());
        };
        if let Some(cache) = self.schedule.cache_mut(graph_id, &peer) {
            record_heads(
                cx.client,
                graph_id,
                session.received,
                cache,
                &mut cx.buffers.traversal.primary,
            )?;
        }
        if new {
            self.schedule.notify_local_change(graph_id, now);
        }
        Ok(())
    }

    /// The reply timeout fired: the schedule has applied backoff; end the
    /// session.
    fn abort_poll_session<K, R, F, MS>(
        &mut self,
        graph_id: GraphId,
        peer: &A,
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
    ) -> Result<(), SyncerError>
    where
        K: Sink<PS::Effect>,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        if self
            .poll_session
            .as_ref()
            .is_some_and(|s| s.token.graph_id == graph_id && s.token.peer == *peer)
            && let Some(session) = self.poll_session.take()
        {
            self.finish_failed_session(session, now, cx)?;
        }
        Ok(())
    }

    /// Opens a session, or continues the open one with a follow-up round,
    /// and encodes the poll request.
    fn start_poll_round<K, R, F, MS>(
        &mut self,
        graph_id: GraphId,
        peer: A,
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
        out: &mut [u8],
    ) -> Result<Option<Outbound<A>>, SyncerError>
    where
        K: Sink<PS::Effect>,
        R: Csprng,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        let (mut session, follow_up) = match self.poll_session.take() {
            Some(session) if session.token.graph_id == graph_id && session.token.peer == peer => {
                (session, true)
            }
            Some(other) => {
                // The gate keeps this from happening; be safe anyway.
                self.poll_session = Some(other);
                return Ok(None);
            }
            None => (
                PollSession {
                    token: self.next_token(graph_id, peer.clone(), OutboundKind::PollRequest),
                    trx: cx.client.transaction(graph_id),
                    requester: SyncRequester::new(graph_id, cx.rng),
                    received: Vec::new(),
                    added: 0,
                    aborted: false,
                },
                false,
            ),
        };
        if follow_up {
            // A follow-up round gets a fresh requester and token; replies to
            // the previous round are stale from here on.
            session.token = self.next_token(graph_id, peer.clone(), OutboundKind::PollRequest);
            session.requester = SyncRequester::new(graph_id, cx.rng);
        }
        let encoded = {
            let cache = self.schedule.cache(graph_id, &peer).unwrap_or(&EMPTY_CACHE);
            let heads = session.trx.session_heads(cache);
            session.requester.poll(
                out,
                cx.client.provider(),
                &heads,
                &mut cx.buffers.traversal.primary,
            )
        };
        match encoded {
            Ok((len, _)) => {
                let timeout_at = self.reply_deadline(now);
                self.schedule.poll_round_sent(graph_id, &peer, timeout_at);
                let token = session.token.clone();
                self.poll_session = Some(session);
                Ok(Some(Outbound { token, len }))
            }
            Err(err) => {
                self.schedule.poll_finished(graph_id, &peer, false, now);
                self.finish_failed_session(session, now, cx)?;
                Err(err.into())
            }
        }
    }

    /// Feeds one reply into the open session and decides whether it needs
    /// another round or has converged.
    fn apply_poll_reply<K, R, F, MS>(
        &mut self,
        data: &[u8],
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
    ) -> Result<Inbound, SyncerError>
    where
        K: Sink<PS::Effect>,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        let Some(session) = self.poll_session.as_mut() else {
            return Ok(Inbound::Ignored(IgnoreReason::StaleToken));
        };
        let graph_id = session.token.graph_id;
        let peer = session.token.peer.clone();

        let mut follow_up = false;
        if !data.is_empty()
            && let Some(cmds) = session.requester.receive(data)?
            && !cmds.is_empty()
        {
            let added = cx.client.add_commands(
                &mut session.trx,
                cx.sink,
                &cmds,
                cx.buffers,
                &cx.make_spill,
            )?;
            session.added = session.added.saturating_add(added);
            // Make the next round's advertised frontier include this one.
            let storage = cx.client.provider().get_storage(graph_id)?;
            session.trx.flush(storage)?;
            session
                .received
                .extend(cmds.iter().filter_map(|cmd| cmd.address().ok()));
            // A full response means the peer has more.
            follow_up = cmds.len() >= COMMAND_RESPONSE_MAX;
        }
        if follow_up {
            self.schedule.poll_follow_up(graph_id, &peer, now);
            return Ok(Inbound::Handled);
        }

        // Converged.
        let Some(session) = self.poll_session.take() else {
            return Ok(Inbound::Ignored(IgnoreReason::StaleToken));
        };
        // An empty transaction has nothing to commit, and committing it
        // against a graph we do not hold yet would fail.
        let new = if session.added == 0 {
            false
        } else {
            match cx
                .client
                .commit(session.trx, cx.sink, cx.buffers, &cx.make_spill)
            {
                Ok(new) => new,
                Err(err) => {
                    self.schedule.poll_finished(graph_id, &peer, false, now);
                    return Err(err.into());
                }
            }
        };
        self.schedule.poll_finished(graph_id, &peer, true, now);
        if new {
            self.schedule.notify_local_change(graph_id, now);
        }
        if let Some(cache) = self.schedule.cache_mut(graph_id, &peer) {
            record_heads(
                cx.client,
                graph_id,
                session.received,
                cache,
                &mut cx.buffers.traversal.primary,
            )?;
        }
        Ok(if session.added > 0 {
            Inbound::Committed {
                count: session.added,
            }
        } else {
            Inbound::Handled
        })
    }

    // ---- push ----------------------------------------------------------

    /// Encodes a push to a subscriber: the next message of the push in
    /// progress, or the first of a new one. Nothing is emitted when the
    /// subscriber is up to date or out of budget.
    fn emit_push<K, R, MS>(
        &mut self,
        graph_id: GraphId,
        peer: A,
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
        out: &mut [u8],
    ) -> Result<Option<Outbound<A>>, SyncerError>
    where
        R: Csprng,
    {
        let Some(remaining) = self.schedule.push_budget(graph_id, &peer, now) else {
            return Ok(None);
        };
        let mut session = match self.push_session.take() {
            Some(session) if session.token.graph_id == graph_id && session.token.peer == peer => {
                session
            }
            Some(other) => {
                self.push_session = Some(other);
                return Ok(None);
            }
            None => {
                let token = self.next_token(graph_id, peer.clone(), OutboundKind::Push);
                let mut id = [0u8; 16];
                cx.rng.fill_bytes(&mut id);
                let mut responder = SyncResponder::new();
                let heads = self
                    .schedule
                    .cache(graph_id, &peer)
                    .map_or(&[][..], PeerCache::heads);
                responder.start_session(
                    u128::from_le_bytes(id),
                    graph_id,
                    remaining,
                    heads.iter().map(|h| h.address()),
                )?;
                PushSession { token, responder }
            }
        };
        let len = match session
            .responder
            .push(out, cx.client.provider(), &mut cx.buffers.traversal)
        {
            Ok(len) => len,
            Err(SyncError::Storage(StorageError::NoSuchStorage)) => 0,
            Err(err) => return Err(err.into()),
        };
        if len == 0 {
            return Ok(None);
        }
        let bytes = u64::try_from(len).unwrap_or(u64::MAX);
        if bytes > remaining {
            // A hard cap: a message that would overrun it ends the
            // subscription instead of being sent.
            self.schedule.remove_push_subscriber(&peer, graph_id);
            return Ok(None);
        }
        self.schedule.record_push(graph_id, &peer, bytes);
        // What was pushed counts as held by the peer from here on, so the
        // next push (or the next session, when this one's segment list was
        // capped) continues past it. A push that is lost stays hidden until
        // the subscriber's next heads sample resets the cache.
        if let Some(cache) = self.schedule.cache_mut(graph_id, &peer) {
            record_heads(
                cx.client,
                graph_id,
                session.responder.pushed().iter().copied(),
                cache,
                &mut cx.buffers.traversal.primary,
            )?;
        }
        let token = session.token.clone();
        let same_session = session.responder.has_more();
        let new_session = !same_session && session.responder.segments_at_capacity();
        if (same_session || new_session)
            && self.schedule.push_budget(graph_id, &peer, now).is_some()
        {
            self.schedule.requeue_push(graph_id, &peer, now);
            if same_session {
                self.push_session = Some(session);
            }
        }
        Ok(Some(Outbound { token, len }))
    }

    // ---- subscription control and hello --------------------------------

    fn emit_push_subscribe<K, R, MS>(
        &mut self,
        graph_id: GraphId,
        peer: A,
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
        out: &mut [u8],
    ) -> Result<Option<Outbound<A>>, SyncerError>
    where
        R: Csprng,
    {
        let Some((remain_open_secs, max_bytes)) =
            self.schedule.push_request_params(graph_id, &peer)
        else {
            return Ok(None);
        };
        let token = self.next_token(graph_id, peer.clone(), OutboundKind::Subscribe);
        let cache = self.schedule.cache(graph_id, &peer).unwrap_or(&EMPTY_CACHE);
        let len = SyncRequester::new(graph_id, cx.rng).subscribe(
            out,
            cx.client.provider(),
            &cache.session_heads(),
            remain_open_secs,
            max_bytes,
            &mut cx.buffers.traversal.primary,
        )?;
        let timeout_at = self.reply_deadline(now);
        self.schedule
            .push_subscribe_sent(graph_id, &peer, token.seq, timeout_at);
        Ok(Some(Outbound { token, len }))
    }

    fn emit_push_unsubscribe(
        &mut self,
        graph_id: GraphId,
        peer: A,
        out: &mut [u8],
    ) -> Result<Outbound<A>, SyncerError> {
        let len = postcard::to_slice(&SyncType::Unsubscribe { graph_id }, out)
            .map_err(SyncError::from)?
            .len();
        Ok(Outbound {
            token: self.next_token(graph_id, peer, OutboundKind::Unsubscribe),
            len,
        })
    }

    fn emit_hello_subscribe(
        &mut self,
        graph_id: GraphId,
        peer: A,
        out: &mut [u8],
    ) -> Result<Option<Outbound<A>>, SyncerError> {
        let Some(cfg) = self.schedule.hello_request_params(graph_id, &peer) else {
            return Ok(None);
        };
        let len = HelloMessage::subscribe(
            out,
            graph_id,
            cfg.graph_change_delay,
            cfg.duration,
            cfg.schedule_delay,
        )?;
        Ok(Some(Outbound {
            token: self.next_token(graph_id, peer, OutboundKind::HelloSubscribe),
            len,
        }))
    }

    fn emit_hello_unsubscribe(
        &mut self,
        graph_id: GraphId,
        peer: A,
        out: &mut [u8],
    ) -> Result<Outbound<A>, SyncerError> {
        let len = HelloMessage::unsubscribe(out, graph_id)?;
        Ok(Outbound {
            token: self.next_token(graph_id, peer, OutboundKind::HelloUnsubscribe),
            len,
        })
    }

    fn emit_hello<K, R, MS>(
        &mut self,
        graph_id: GraphId,
        peer: A,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
        out: &mut [u8],
    ) -> Result<Outbound<A>, SyncerError> {
        let head = cx.client.hello_head(graph_id)?;
        let len = HelloMessage::notification(out, graph_id, head)?;
        Ok(Outbound {
            token: self.next_token(graph_id, peer, OutboundKind::Hello),
            len,
        })
    }
}
