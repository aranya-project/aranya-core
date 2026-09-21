//! Per-peer sync state and the caller-supplied storage it lives in.

use alloc::vec::Vec;
use core::time::Duration;

use super::{HelloConfig, PeerConfig, SyncInstant};
use crate::{storage::GraphId, sync::PeerCache};

/// The caller-supplied [`SyncSlots`] have no room for another peer-graph
/// pair. Free a slot or supply larger storage; never returned through
/// [`HeapSlots`], which grows on demand.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("out of syncer slots")]
pub struct OutOfSlots;

/// A poll round or subscribe that is waiting on the caller.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Inflight<T> {
    /// A request is out and its reply has not arrived. While set, the poll
    /// timer is disarmed and the timeout timer is armed.
    pub(crate) awaiting_reply: bool,
    /// When the outstanding request counts as failed.
    pub(crate) timeout_at: T,
}

/// A peer we poll: its schedule, `sync_on_hello` registration, and
/// in-flight state.
#[derive(Clone, Debug)]
pub(crate) struct PollTarget<T> {
    pub(crate) config: PeerConfig,
    pub(crate) next_at: Option<T>,
    /// Consecutive failed rounds; drives backoff. Reset on success.
    pub(crate) failures: u8,
    /// `Some` for the whole life of a poll session on this peer.
    pub(crate) inflight: Option<Inflight<T>>,
}

impl<T: Copy> PollTarget<T> {
    /// Whether a request is out awaiting its reply.
    pub(crate) fn awaiting_reply(&self) -> bool {
        self.inflight.is_some_and(|i| i.awaiting_reply)
    }
}

/// A peer we push to (they subscribed to us).
#[derive(Clone, Debug)]
pub(crate) struct PushSubscriber<T> {
    pub(crate) expires_at: T,
    pub(crate) remaining_bytes: u64,
    /// A push is queued for this instant; emitted (and cleared) by a drain.
    pub(crate) push_due: Option<T>,
}

impl<T: SyncInstant> PushSubscriber<T> {
    pub(crate) fn is_live(&self, now: T) -> bool {
        self.expires_at > now && self.remaining_bytes > 0
    }
}

/// A peer we send hellos to (they subscribed to us).
#[derive(Clone, Debug)]
pub(crate) struct HelloSubscriber<T> {
    pub(crate) debounce: Duration,
    pub(crate) schedule_delay: Duration,
    /// Change-triggered hellos are suppressed before this instant. `None`:
    /// never notified, so the first local change always fires.
    pub(crate) next_change_allowed: Option<T>,
    pub(crate) expires_at: T,
    pub(crate) next_hello: T,
}

/// A subscribe we sent that is waiting for its [`SubscribeResponse`].
///
/// [`SubscribeResponse`]: crate::sync::SubscribeResponse
#[derive(Copy, Clone, Debug)]
pub(crate) struct SubscribeInflight<T> {
    pub(crate) seq: u32,
    pub(crate) timeout_at: T,
}

/// A push subscription we requested from a peer.
#[derive(Clone, Debug)]
pub(crate) enum PushRequest<T> {
    /// Renewed at half-life until unsubscribed.
    Active {
        remain_open_secs: u64,
        max_bytes: u64,
        renew_at: T,
        inflight: Option<SubscribeInflight<T>>,
    },
    /// Torn down: emit one `Unsubscribe` at `due`, then drop the record.
    Cancel { due: T },
}

/// A hello subscription we requested from a peer.
#[derive(Clone, Debug)]
pub(crate) enum HelloRequest<T> {
    /// Renewed at half-life until unsubscribed.
    Active { cfg: HelloConfig, renew_at: T },
    /// Torn down: emit one `HelloUnsubscribe` at `due`, then drop the record.
    Cancel { due: T },
}

/// Which timer fired.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum DueKind {
    Poll,
    PollTimeout,
    Push,
    ScheduledHello,
    PushRenewal,
    SubscribeTimeout,
    PushCancel,
    HelloRenewal,
    HelloCancel,
}

/// One peer-graph pair's sync state: an entry in the caller-supplied
/// [`SyncSlots`].
///
/// A slot bundles every role the pair can hold at once (polled peer, push
/// and hello subscriber, our outbound push and hello requests) plus the
/// [`PeerCache`] recording what the peer is known to hold. The contents are
/// private; [`SyncSlots`] implementations only construct empty slots
/// ([`new`](Self::new)) and key them by [`graph_id`](Self::graph_id) and
/// [`peer`](Self::peer).
#[derive(Debug)]
pub struct SyncSlot<A, T> {
    graph_id: GraphId,
    peer: A,
    pub(crate) poll: Option<PollTarget<T>>,
    pub(crate) push_sub: Option<PushSubscriber<T>>,
    pub(crate) hello_sub: Option<HelloSubscriber<T>>,
    pub(crate) push_req: Option<PushRequest<T>>,
    pub(crate) hello_req: Option<HelloRequest<T>>,
    pub(crate) cache: PeerCache,
    /// Cached minimum of every armed timer; kept current by
    /// [`refresh`](Self::refresh).
    next_deadline: Option<T>,
}

impl<A, T> SyncSlot<A, T> {
    /// Creates an empty slot for `(graph_id, peer)`, which is what
    /// [`SyncSlots::get_or_insert`] implementations insert on a miss.
    #[must_use]
    pub fn new(graph_id: GraphId, peer: A) -> Self {
        Self {
            graph_id,
            peer,
            poll: None,
            push_sub: None,
            hello_sub: None,
            push_req: None,
            hello_req: None,
            cache: PeerCache::new(),
            next_deadline: None,
        }
    }

    /// Returns the graph this slot tracks.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    /// Returns the peer this slot tracks.
    pub fn peer(&self) -> &A {
        &self.peer
    }

    /// Returns whether no role is active. The syncer removes a slot as soon
    /// as it becomes empty, so implementations never accumulate dead
    /// entries.
    pub fn is_empty(&self) -> bool {
        self.poll.is_none()
            && self.push_sub.is_none()
            && self.hello_sub.is_none()
            && self.push_req.is_none()
            && self.hello_req.is_none()
    }

    /// The earliest armed timer, as of the last [`refresh`](Self::refresh).
    pub(crate) fn deadline(&self) -> Option<T>
    where
        T: Copy,
    {
        self.next_deadline
    }

    /// Recomputes the cached deadline. Called after every mutation.
    pub(crate) fn refresh(&mut self)
    where
        T: Copy + Ord,
    {
        let mut min: Option<T> = None;
        self.for_each_deadline(|at, _| {
            if min.is_none_or(|m| at < m) {
                min = Some(at);
            }
        });
        self.next_deadline = min;
    }

    /// Visits every armed timer as an `(instant, kind)` pair, in a fixed
    /// role order so exact ties break deterministically.
    pub(crate) fn for_each_deadline(&self, mut consider: impl FnMut(T, DueKind))
    where
        T: Copy,
    {
        if let Some(poll) = &self.poll {
            match poll.inflight {
                Some(inflight) if inflight.awaiting_reply => {
                    consider(inflight.timeout_at, DueKind::PollTimeout);
                }
                _ => {
                    if let Some(at) = poll.next_at {
                        consider(at, DueKind::Poll);
                    }
                }
            }
        }
        if let Some(at) = self.push_sub.as_ref().and_then(|sub| sub.push_due) {
            consider(at, DueKind::Push);
        }
        if let Some(sub) = &self.hello_sub {
            consider(sub.next_hello, DueKind::ScheduledHello);
        }
        match &self.push_req {
            Some(PushRequest::Active {
                inflight: Some(inflight),
                ..
            }) => consider(inflight.timeout_at, DueKind::SubscribeTimeout),
            Some(PushRequest::Active { renew_at, .. }) => {
                consider(*renew_at, DueKind::PushRenewal);
            }
            Some(PushRequest::Cancel { due }) => consider(*due, DueKind::PushCancel),
            None => {}
        }
        match &self.hello_req {
            Some(HelloRequest::Active { renew_at, .. }) => {
                consider(*renew_at, DueKind::HelloRenewal);
            }
            Some(HelloRequest::Cancel { due }) => consider(*due, DueKind::HelloCancel),
            None => {}
        }
    }
}

/// Backing memory for a [`Syncer`](super::Syncer)'s per-peer state, supplied
/// by the caller: one [`SyncSlot`] per peer-graph pair. Use [`FixedSlots`]
/// for inline storage without a heap, [`HeapSlots`] to grow on demand, or
/// implement the trait for your own storage.
///
/// # Contract
///
/// - At most one slot per `(graph_id, peer)` pair.
/// - [`iter`](Self::iter) and [`retain`](Self::retain) visit slots in a
///   stable, deterministic order; equal deadlines fire in visit order.
/// - [`get_or_insert`](Self::get_or_insert) inserts [`SyncSlot::new`] on a
///   miss and fails with [`OutOfSlots`] only when no space remains.
pub trait SyncSlots<A, T> {
    /// Returns the slot for `(graph_id, peer)`, if present.
    fn get(&self, graph_id: GraphId, peer: &A) -> Option<&SyncSlot<A, T>>;

    /// Returns the slot for `(graph_id, peer)` mutably, if present.
    fn get_mut(&mut self, graph_id: GraphId, peer: &A) -> Option<&mut SyncSlot<A, T>>;

    /// Returns the slot for `(graph_id, peer)`, inserting an empty one
    /// ([`SyncSlot::new`]) if absent.
    fn get_or_insert(
        &mut self,
        graph_id: GraphId,
        peer: &A,
    ) -> Result<&mut SyncSlot<A, T>, OutOfSlots>;

    /// Removes the slot for `(graph_id, peer)`, if present.
    fn remove(&mut self, graph_id: GraphId, peer: &A);

    /// Visits every slot in the table's stable order.
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a SyncSlot<A, T>>
    where
        A: 'a,
        T: 'a;

    /// Visits every slot mutably in the table's stable order, removing those
    /// for which `f` returns `false`.
    fn retain(&mut self, f: impl FnMut(&mut SyncSlot<A, T>) -> bool);
}

/// Locates `(graph_id, peer)` in a slice of slots.
///
/// A linear scan: the table holds one graph and tens of peers in practice,
/// so ordering it for binary search would cost more than it saves.
fn search_slots<A: Eq, T>(slots: &[SyncSlot<A, T>], graph_id: GraphId, peer: &A) -> Option<usize> {
    slots
        .iter()
        .position(|slot| slot.graph_id == graph_id && slot.peer == *peer)
}

/// [`SyncSlots`] with capacity for `N` peer-graph pairs, stored inline with
/// no allocation, for `no_std` callers without a heap. Slots are kept in
/// insertion order and looked up by linear scan.
///
/// Size `N` for the distinct `(graph_id, peer)` pairs in play at once; a
/// pair occupies one slot however many roles it holds. When full,
/// slot-creating calls fail with [`OutOfSlots`], and a remote subscribe is
/// refused as `TooManySubscriptions`.
#[derive(Debug)]
pub struct FixedSlots<A, T, const N: usize> {
    slots: heapless::Vec<SyncSlot<A, T>, N>,
}

impl<A, T, const N: usize> FixedSlots<A, T, N> {
    /// Creates an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: heapless::Vec::new(),
        }
    }
}

impl<A, T, const N: usize> Default for FixedSlots<A, T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Clone + Eq, T, const N: usize> SyncSlots<A, T> for FixedSlots<A, T, N> {
    fn get(&self, graph_id: GraphId, peer: &A) -> Option<&SyncSlot<A, T>> {
        let at = search_slots(&self.slots, graph_id, peer)?;
        self.slots.get(at)
    }

    fn get_mut(&mut self, graph_id: GraphId, peer: &A) -> Option<&mut SyncSlot<A, T>> {
        let at = search_slots(&self.slots, graph_id, peer)?;
        self.slots.get_mut(at)
    }

    fn get_or_insert(
        &mut self,
        graph_id: GraphId,
        peer: &A,
    ) -> Result<&mut SyncSlot<A, T>, OutOfSlots> {
        if let Some(at) = search_slots(&self.slots, graph_id, peer) {
            return self.slots.get_mut(at).ok_or(OutOfSlots);
        }
        self.slots
            .push(SyncSlot::new(graph_id, peer.clone()))
            .map_err(|_| OutOfSlots)?;
        self.slots.last_mut().ok_or(OutOfSlots)
    }

    fn remove(&mut self, graph_id: GraphId, peer: &A) {
        if let Some(at) = search_slots(&self.slots, graph_id, peer) {
            self.slots.remove(at);
        }
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a SyncSlot<A, T>>
    where
        A: 'a,
        T: 'a,
    {
        self.slots.iter()
    }

    fn retain(&mut self, f: impl FnMut(&mut SyncSlot<A, T>) -> bool) {
        self.slots.retain_mut(f);
    }
}

/// [`SyncSlots`] that grow on demand (requires `alloc`), the default
/// storage; never [`OutOfSlots`]. Slots are kept in insertion order and
/// looked up by linear scan.
///
/// Remote peers cannot grow it unboundedly: the subscriber tables are capped
/// by [`Limits`](super::Limits), and every other slot is created by a local
/// call.
#[derive(Debug)]
pub struct HeapSlots<A, T> {
    slots: Vec<SyncSlot<A, T>>,
}

impl<A, T> HeapSlots<A, T> {
    /// Creates an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }
}

impl<A, T> Default for HeapSlots<A, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Clone + Eq, T> SyncSlots<A, T> for HeapSlots<A, T> {
    fn get(&self, graph_id: GraphId, peer: &A) -> Option<&SyncSlot<A, T>> {
        let at = search_slots(&self.slots, graph_id, peer)?;
        self.slots.get(at)
    }

    fn get_mut(&mut self, graph_id: GraphId, peer: &A) -> Option<&mut SyncSlot<A, T>> {
        let at = search_slots(&self.slots, graph_id, peer)?;
        self.slots.get_mut(at)
    }

    fn get_or_insert(
        &mut self,
        graph_id: GraphId,
        peer: &A,
    ) -> Result<&mut SyncSlot<A, T>, OutOfSlots> {
        if let Some(at) = search_slots(&self.slots, graph_id, peer) {
            return self.slots.get_mut(at).ok_or(OutOfSlots);
        }
        self.slots.push(SyncSlot::new(graph_id, peer.clone()));
        self.slots.last_mut().ok_or(OutOfSlots)
    }

    fn remove(&mut self, graph_id: GraphId, peer: &A) {
        if let Some(at) = search_slots(&self.slots, graph_id, peer) {
            self.slots.remove(at);
        }
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a SyncSlot<A, T>>
    where
        A: 'a,
        T: 'a,
    {
        self.slots.iter()
    }

    fn retain(&mut self, f: impl FnMut(&mut SyncSlot<A, T>) -> bool) {
        self.slots.retain_mut(f);
    }
}
