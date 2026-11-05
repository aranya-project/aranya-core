//! A sans-I/O syncer state machine; see [`Syncer`].

use core::fmt;

use aranya_crypto::Csprng;
use buggy::Bug;

use crate::{
    Address, ClientError, ClientState, RuntimeBuffers,
    policy::{PolicyStore, Sink},
    storage::{GraphId, Spill, StorageError, StorageProvider},
    sync::{PeerCache, SyncError, SyncIncoming, SyncRequester, SyncResponder},
};

mod config;
mod schedule;
#[cfg(test)]
mod schedule_tests;
mod slots;
#[cfg(test)]
mod tests;
mod time;

pub use config::{Limits, LimitsBuilder, PeerConfig};
use schedule::{Due, PollResult, Schedule};
use slots::Inflight;
pub use slots::{FixedSlots, HeapSlots, OutOfSlots, SyncSlot, SyncSlots};
pub use time::SyncInstant;

/// What an [`Outbound`] message is.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutboundKind {
    /// A poll request. Expects a reply: feed it to [`Syncer::handle_reply`].
    PollRequest,
}

impl OutboundKind {
    /// Whether the peer answers this message on the same connection.
    pub fn expects_reply(self) -> bool {
        match self {
            Self::PollRequest => true,
        }
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
    /// Dropped without effect.
    Ignored(IgnoreReason),
}

/// Why an inbound message or reply was dropped.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IgnoreReason {
    /// The token does not name a request awaiting its reply: the request
    /// timed out, was reported failed, was answered already, or its peer
    /// was removed.
    StaleToken,
    /// A message kind the syncer does not handle yet.
    Unsupported,
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
    /// Source of session ids and cache eviction.
    pub rng: &'a R,
    /// Creates overflow storage for a braid; see [`ClientState::commit`].
    pub make_spill: MS,
}

/// Records in `cache` that the peer holds `addrs`. A graph we do not hold
/// yet has nothing to record against; that is not an error.
fn record_heads<PS, SP, I>(
    client: &mut ClientState<PS, SP>,
    graph_id: GraphId,
    addrs: I,
    cache: &mut PeerCache,
    buffer: &mut crate::storage::TraversalBuffer,
    rng: &impl Csprng,
) -> Result<(), SyncerError>
where
    PS: PolicyStore,
    SP: StorageProvider,
    I: IntoIterator<Item = Address>,
    I::IntoIter: DoubleEndedIterator,
{
    match client.update_heads(graph_id, addrs, cache, buffer, rng) {
        Ok(()) | Err(ClientError::StorageError(StorageError::NoSuchStorage)) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Answers a poll with a cache that is dropped afterwards, for when the
/// slots are full. Kept out of line so the common path's stack frame does
/// not hold a [`PeerCache`].
#[inline(never)]
fn answer_with_fresh_cache<PS, SP: StorageProvider, K, R: Csprng, MS>(
    responder: &mut SyncResponder,
    out: &mut [u8],
    cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
) -> Result<usize, SyncError> {
    responder.poll(
        out,
        cx.client.provider(),
        &mut PeerCache::new(),
        &mut cx.buffers.traversal,
        cx.rng,
    )
}

/// A sans-I/O syncer state machine.
///
/// [`Syncer`] decides when to poll which peer, sends poll requests, commits
/// what the replies carry, and answers peers' polls. It performs no I/O and
/// reads no clock: the caller supplies a transport (bytes in, bytes out, a
/// peer identity per connection), storage (a [`ClientState`] borrowed for
/// each call via [`SyncContext`]), and the current time (any
/// [`SyncInstant`]).
///
/// Each reply is committed as it arrives. When the peer had more to send
/// than fit, its reply carries a sample of its graph and the next poll of
/// that peer is due at once, so a large catch-up runs as back-to-back
/// exchanges. Several peers can be polled at once, up to
/// [`LimitsBuilder::max_inflight_polls`].
///
/// # Driving
///
/// ```ignore
/// loop {
///     let now = clock();
///     let mut cx = SyncContext { client, sink, buffers, rng, make_spill };
///
///     // Inbound: answer what peers sent on the same connection.
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
///         match transport.request(ob.peer(), &out[..ob.len()], reply) {
///             Ok(n) => { syncer.handle_reply(ob.token(), &reply[..n], now, &mut cx)?; }
///             Err(_) => syncer.complete(ob.token(), Outcome::Failed, now),
///         }
///     }
///
///     sleep_until(syncer.next_deadline(), transport.wake());
/// }
/// ```
///
/// A transport that waits for replies asynchronously instead hands each
/// one to [`handle_reply`](Self::handle_reply) when it arrives; a request
/// whose reply never comes fails after [`LimitsBuilder::reply_timeout`].
///
/// Per-peer state lives in caller-supplied [`SyncSlots`]: [`HeapSlots`]
/// grows on demand, [`FixedSlots`] is inline and allocation-free.
pub struct Syncer<A, T, S = HeapSlots<A, T>> {
    schedule: Schedule<A, T, S>,
    seq: u32,
}

impl<A, T, S> fmt::Debug for Syncer<A, T, S>
where
    A: fmt::Debug,
    T: fmt::Debug,
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Syncer")
            .field("schedule", &self.schedule)
            .finish_non_exhaustive()
    }
}

impl<A, T> Syncer<A, T>
where
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

impl<A, T, S> Default for Syncer<A, T, S>
where
    A: Clone + Eq,
    T: SyncInstant,
    S: SyncSlots<A, T> + Default,
{
    fn default() -> Self {
        Self::new_in(S::default())
    }
}

impl<A, T, S> Syncer<A, T, S>
where
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

    /// Forgets `peer`: its polling, its cache, and any request in flight,
    /// whose reply is then ignored as [`IgnoreReason::StaleToken`]. Returns
    /// whether it was registered for polling.
    pub fn remove_peer(&mut self, peer: &A, graph_id: GraphId) -> bool {
        self.schedule.remove_peer(peer, graph_id)
    }

    /// Schedules an immediate poll of `peer`. A registered peer keeps its
    /// recurring interval, and with a request in flight the poll follows
    /// its reply. An unregistered peer is registered to be polled once, as
    /// with [`PeerConfig::immediate`].
    pub fn sync_now(&mut self, peer: &A, graph_id: GraphId, now: T) -> Result<(), OutOfSlots> {
        if !self.schedule.sync_now(peer, graph_id, now) {
            self.schedule
                .add_peer(peer.clone(), graph_id, PeerConfig::immediate(), now)?;
        }
        Ok(())
    }

    /// The [`PeerCache`] recording what `peer` is known to hold of
    /// `graph_id`, kept until [`remove_peer`](Self::remove_peer) or
    /// [`remove_graph`](Self::remove_graph).
    ///
    /// Polls in both directions use this cache, and code that exchanges
    /// other messages with the peer (subscribe, push) should use it too.
    pub fn peer_cache(
        &mut self,
        graph_id: GraphId,
        peer: &A,
    ) -> Result<&mut PeerCache, OutOfSlots> {
        self.schedule.pinned_cache(graph_id, peer)
    }

    /// Drops all state for `graph_id`: registrations, caches, and requests
    /// in flight.
    pub fn remove_graph(&mut self, graph_id: GraphId) {
        self.schedule.remove_graph(graph_id);
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
    /// [`handle_reply`](Self::handle_reply). A failed poll backs off.
    /// Unknown or stale tokens are ignored.
    pub fn complete(&mut self, token: Token<A>, outcome: Outcome, now: T) {
        if outcome != Outcome::Failed {
            return;
        }
        match token.kind {
            OutboundKind::PollRequest => {
                self.schedule
                    .fail_inflight(token.graph_id, &token.peer, token.seq, now);
            }
        }
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn reply_deadline(&self, now: T) -> T {
        now.saturating_add(self.schedule.limits().reply_timeout)
    }
}

impl<A, T, S> Syncer<A, T, S>
where
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
    /// An error is also a failed poll for the peer involved and is safe to
    /// log and continue from.
    pub fn next_outbound<PS, SP, K, R, MS>(
        &mut self,
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
        out: &mut [u8],
    ) -> Result<Option<Outbound<A>>, SyncerError>
    where
        SP: StorageProvider,
        R: Csprng,
    {
        let Some(Due { graph_id, peer }) = self.schedule.next_due(now) else {
            return Ok(None);
        };
        self.start_poll(graph_id, peer, now, cx, out).map(Some)
    }

    /// Applies a message received from `peer`. A reply, if the protocol
    /// calls for one, is encoded into `out`.
    ///
    /// `peer` is whatever identity the transport authenticated; the syncer
    /// keys all state by it. Decode failures leave no partial state.
    ///
    /// Answering a poll for a graph we hold keeps a cache for `peer` (see
    /// [`peer_cache`](Self::peer_cache)), so later replies skip what it is
    /// known to hold. When the slots are full, the reply is built from a
    /// fresh cache instead.
    pub fn handle_incoming<PS, SP, K, R, MS>(
        &mut self,
        peer: A,
        data: &[u8],
        _now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
        out: &mut [u8],
    ) -> Result<Inbound, SyncerError>
    where
        SP: StorageProvider,
        R: Csprng,
    {
        match SyncIncoming::decode(data)? {
            SyncIncoming::Poll(poll) => {
                // Only a session-opening request names a graph, and the
                // syncer's polls always open one.
                let Some(graph_id) = poll.graph_id() else {
                    return Ok(Inbound::Ignored(IgnoreReason::Unsupported));
                };
                // We do not hold the graph: an empty reply says so. Checked
                // first so a peer cannot make us keep state for any graph id.
                if let Err(StorageError::NoSuchStorage) = cx.client.provider().get_storage(graph_id)
                {
                    return Ok(Inbound::Reply { len: 0 });
                }
                let mut responder = SyncResponder::new();
                responder.receive(poll)?;
                let len = match self.schedule.pinned_cache(graph_id, &peer) {
                    Ok(cache) => responder.poll(
                        out,
                        cx.client.provider(),
                        cache,
                        &mut cx.buffers.traversal,
                        cx.rng,
                    )?,
                    Err(OutOfSlots) => answer_with_fresh_cache(&mut responder, out, cx)?,
                };
                Ok(Inbound::Reply { len })
            }
            SyncIncoming::Subscribe(_)
            | SyncIncoming::Unsubscribe(_)
            | SyncIncoming::Push(_)
            | SyncIncoming::Hello(_) => Ok(Inbound::Ignored(IgnoreReason::Unsupported)),
        }
    }

    /// Applies the reply to an outbound that
    /// [`expects_reply`](Outbound::expects_reply).
    ///
    /// A poll reply's commands are committed. When the peer had more to
    /// send, its next poll is due at once. An error is a failed poll for the
    /// peer involved.
    pub fn handle_reply<PS, SP, K, R, F, MS>(
        &mut self,
        token: Token<A>,
        data: &[u8],
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
    ) -> Result<Inbound, SyncerError>
    where
        PS: PolicyStore,
        SP: StorageProvider,
        K: Sink<PS::Effect>,
        R: Csprng,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        let Token {
            graph_id,
            peer,
            kind: OutboundKind::PollRequest,
            seq,
        } = token;
        let Some(mut requester) = self.schedule.take_inflight(graph_id, &peer, seq) else {
            return Ok(Inbound::Ignored(IgnoreReason::StaleToken));
        };
        match self.apply_poll_reply(&mut requester, graph_id, &peer, data, cx) {
            Ok((count, more)) => {
                // Asking again after a reply that added nothing would send
                // the same request, so a peer that keeps claiming more
                // without sending anything new cannot keep us polling.
                let result = if more && count > 0 {
                    PollResult::More
                } else {
                    PollResult::Done
                };
                self.schedule.poll_finished(graph_id, &peer, result, now);
                Ok(if count > 0 {
                    Inbound::Committed { count }
                } else {
                    Inbound::Handled
                })
            }
            Err(err) => {
                self.schedule
                    .poll_finished(graph_id, &peer, PollResult::Failed, now);
                Err(err)
            }
        }
    }

    // ---- poll ----------------------------------------------------------

    /// Encodes a poll request to `peer` and marks it in flight.
    fn start_poll<PS, SP, K, R, MS>(
        &mut self,
        graph_id: GraphId,
        peer: A,
        now: T,
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
        out: &mut [u8],
    ) -> Result<Outbound<A>, SyncerError>
    where
        SP: StorageProvider,
        R: Csprng,
    {
        let mut requester = SyncRequester::new(graph_id, cx.rng);
        let encoded = match self.schedule.cache(graph_id, &peer) {
            Some(cache) => requester.poll(out, cx.client.provider(), cache.session_heads(), cx.rng),
            // A poll only comes due from a slot, which holds the cache.
            None => Err(Bug::new("a due poll has a slot").into()),
        };
        let len = match encoded {
            Ok((len, _)) => len,
            Err(err) => {
                self.schedule
                    .poll_finished(graph_id, &peer, PollResult::Failed, now);
                return Err(err.into());
            }
        };
        let seq = self.next_seq();
        let timeout_at = self.reply_deadline(now);
        self.schedule.poll_sent(
            graph_id,
            &peer,
            Inflight {
                requester,
                seq,
                timeout_at,
            },
        );
        Ok(Outbound {
            token: Token {
                graph_id,
                peer,
                kind: OutboundKind::PollRequest,
                seq,
            },
            len,
        })
    }

    /// Commits one poll reply and records what it shows the peer holds.
    /// Returns the number of commands added and whether the peer has more.
    fn apply_poll_reply<PS, SP, K, R, F, MS>(
        &mut self,
        requester: &mut SyncRequester,
        graph_id: GraphId,
        peer: &A,
        data: &[u8],
        cx: &mut SyncContext<'_, PS, SP, K, R, MS>,
    ) -> Result<(usize, bool), SyncerError>
    where
        PS: PolicyStore,
        SP: StorageProvider,
        K: Sink<PS::Effect>,
        R: Csprng,
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        // The peer does not hold the graph.
        if data.is_empty() {
            return Ok((0, false));
        }
        let Some(cache) = self.schedule.cache_mut(graph_id, peer) else {
            // The slot outlives its in-flight request, so this is
            // unreachable; a reply with nowhere to record it is stale.
            return Ok((0, false));
        };
        let Some(reply) = requester.receive(data, cache)? else {
            return Ok((0, false));
        };
        let more = !reply.sample().is_empty();
        let mut added = 0;
        if !reply.commands().is_empty() {
            let mut trx = cx.client.transaction(graph_id);
            added = match cx.client.add_commands(
                &mut trx,
                cx.sink,
                reply.commands(),
                cx.buffers,
                &cx.make_spill,
            ) {
                Ok(added) => added,
                Err(err) => {
                    if matches!(err, ClientError::NoSuchParent(_)) {
                        cache.saw_missing_parent();
                    }
                    return Err(err.into());
                }
            };
            cx.client.commit(trx, cx.sink, cx.buffers, &cx.make_spill)?;
        }
        record_heads(
            cx.client,
            graph_id,
            reply.addresses(),
            cache,
            &mut cx.buffers.traversal.primary,
            cx.rng,
        )?;
        Ok((added, more))
    }
}
