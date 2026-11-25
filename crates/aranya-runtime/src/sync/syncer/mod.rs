//! A sans-I/O syncer state machine; see [`Syncer`].

#![allow(dead_code)]

use core::fmt;

use crate::{
    ClientError, ClientState, RuntimeBuffers,
    storage::{GraphId, StorageError, StorageProvider},
    sync::{PeerCache, SyncError},
};

mod config;
mod schedule;
#[cfg(test)]
mod schedule_tests;
mod slots;
mod time;

pub use config::{Limits, LimitsBuilder, PeerConfig};
use schedule::Schedule;
pub use slots::{FixedSlots, HeapSlots, OutOfSlots, SyncSlot, SyncSlots};
pub use time::SyncInstant;

/// Opaque handle tying a reply or failure back to the poll request
/// ([`Outbound`]) it answers. Never travels over the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token<A> {
    graph_id: GraphId,
    peer: A,
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
///             syncer.handle_incoming(peer, frame, &mut cx, out)?
///         {
///             transport.reply(peer, &out[..len])?;
///         }
///     }
///
///     // Outbound: send what is due; hand replies and failures back.
///     while let Some(ob) = syncer.next_outbound(now, &mut cx, out)? {
///         match transport.request(ob.peer(), &out[..ob.len()], reply) {
///             Ok(n) => { syncer.handle_reply(ob.token(), &reply[..n], now, &mut cx)?; }
///             Err(_) => syncer.fail(ob.token(), now),
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
    /// whose reply is then ignored as [`IgnoreReason::StaleToken`].
    pub fn remove_peer(&mut self, peer: &A, graph_id: GraphId) {
        self.schedule.remove_peer(peer, graph_id);
    }

    /// Schedules an immediate poll of `peer`, keeping any recurring
    /// interval. With a request in flight, the poll follows its reply. An
    /// unknown peer is polled once, as with [`PeerConfig::immediate`].
    pub fn sync_now(&mut self, peer: &A, graph_id: GraphId, now: T) -> Result<(), OutOfSlots> {
        self.schedule.sync_now(peer, graph_id, now)
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
        self.schedule.cache_or_insert(graph_id, peer)
    }

    /// Drops all state for `graph_id`: registrations, caches, and requests
    /// in flight.
    pub fn remove_graph(&mut self, graph_id: GraphId) {
        self.schedule.remove_graph(graph_id);
    }

    /// Every peer with state in the syncer and its configuration, for
    /// callers that persist registrations themselves. Peers known only
    /// through [`peer_cache`](Self::peer_cache) or by polling us have
    /// [`PeerConfig::default`].
    pub fn peers(&self) -> impl Iterator<Item = (GraphId, &A, PeerConfig)> {
        self.schedule.peers()
    }

    /// The earliest timer: when [`next_outbound`](Self::next_outbound) next
    /// has work. Sleep until then or until the transport has input.
    pub fn next_deadline(&self) -> Option<T> {
        self.schedule.next_deadline()
    }

    /// Reports that `token`'s poll request could not be sent or its reply
    /// never came; the peer backs off. Unknown or stale tokens are ignored.
    pub fn fail(&mut self, token: Token<A>, now: T) {
        self.schedule
            .fail_inflight(token.graph_id, &token.peer, token.seq, now);
    }
}
