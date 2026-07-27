//! Per-peer sync state and the caller-supplied storage it lives in.

use alloc::vec::Vec;
use core::time::Duration;

use super::{OutOfSlots, PeerConfig, SyncInstant};
use crate::storage::GraphId;

/// Poll schedule and `sync_on_hello` registration for one peer.
#[derive(Clone, Debug)]
pub(super) struct PollState<T> {
    pub(super) config: PeerConfig,
    pub(super) next_sync: Option<T>,
}

/// A peer we push to (they subscribed to us).
#[derive(Clone, Debug)]
pub(super) struct PushSub<T> {
    pub(super) expires_at: T,
    pub(super) remaining_bytes: u64,
    /// A local change queued a push at this instant; emitted (and cleared)
    /// by the next drain. Transient — not persisted.
    pub(super) push_due: Option<T>,
}

impl<T: SyncInstant> PushSub<T> {
    pub(super) fn is_live(&self, now: T) -> bool {
        self.expires_at > now && self.remaining_bytes > 0
    }
}

/// A peer we send hellos to (they subscribed to us).
#[derive(Clone, Debug)]
pub(super) struct HelloSub<T> {
    pub(super) graph_change_debounce: Duration,
    pub(super) schedule_delay: Duration,
    /// The instant before which change-triggered hellos are suppressed.
    /// `None` = never notified, so the first local change always fires.
    pub(super) next_change_allowed: Option<T>,
    pub(super) expires_at: T,
    pub(super) next_hello: T,
}

/// A push subscription we requested from a peer.
#[derive(Clone, Debug)]
pub(super) enum PushReq<T> {
    /// Renewed until unsubscribed.
    Active {
        remain_open_secs: u64,
        max_bytes: u64,
        renew_at: T,
    },
    /// Torn down: emit one [`SyncAction::Unsubscribe`] at `due`, then drop
    /// the record. Transient — not persisted.
    ///
    /// [`SyncAction::Unsubscribe`]: super::SyncAction::Unsubscribe
    Cancel { due: T },
}

/// A hello subscription we requested from a peer.
#[derive(Clone, Debug)]
pub(super) enum HelloReq<T> {
    /// Renewed until unsubscribed.
    Active {
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
        renew_at: T,
    },
    /// Torn down: emit one [`SyncAction::HelloUnsubscribe`] at `due`, then
    /// drop the record. Transient — not persisted.
    ///
    /// [`SyncAction::HelloUnsubscribe`]: super::SyncAction::HelloUnsubscribe
    Cancel { due: T },
}

/// Which timer the earliest-due scheduled item came from.
#[derive(Copy, Clone, Debug)]
pub(super) enum DueKind {
    Poll,
    Push,
    ScheduledHello,
    PushRenewal,
    PushCancel,
    HelloRenewal,
    HelloCancel,
}

/// One peer-graph pair's sync state: an entry in the caller-supplied
/// [`SyncSlots`].
///
/// A slot bundles every role the pair can hold at once — polled peer, push
/// and hello subscriber, and our outbound push/hello requests to it. The
/// contents are private; [`SyncSlots`] implementations only construct empty
/// slots ([`new`](Self::new)) and key them by [`graph_id`](Self::graph_id)
/// and [`peer`](Self::peer).
#[derive(Clone, Debug)]
pub struct SyncSlot<A, T> {
    pub(super) graph_id: GraphId,
    pub(super) peer: A,
    pub(super) poll: Option<PollState<T>>,
    pub(super) push_sub: Option<PushSub<T>>,
    pub(super) hello_sub: Option<HelloSub<T>>,
    pub(super) push_req: Option<PushReq<T>>,
    pub(super) hello_req: Option<HelloReq<T>>,
}

impl<A, T> SyncSlot<A, T> {
    /// Creates an empty slot for `(graph_id, peer)` — what
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
    /// as it becomes empty, so implementations never accumulate dead entries.
    pub fn is_empty(&self) -> bool {
        self.poll.is_none()
            && self.push_sub.is_none()
            && self.hello_sub.is_none()
            && self.push_req.is_none()
            && self.hello_req.is_none()
    }

    /// Visits every armed timer on this slot as an `(instant, kind)` pair,
    /// in a fixed role order that breaks exact ties for callers keeping the
    /// first-seen earliest instant.
    pub(super) fn for_each_deadline(&self, mut consider: impl FnMut(T, DueKind))
    where
        T: Copy,
    {
        if let Some(at) = self.poll.as_ref().and_then(|state| state.next_sync) {
            consider(at, DueKind::Poll);
        }
        if let Some(at) = self.push_sub.as_ref().and_then(|sub| sub.push_due) {
            consider(at, DueKind::Push);
        }
        if let Some(sub) = &self.hello_sub {
            consider(sub.next_hello, DueKind::ScheduledHello);
        }
        match &self.push_req {
            Some(PushReq::Active { renew_at, .. }) => consider(*renew_at, DueKind::PushRenewal),
            Some(PushReq::Cancel { due }) => consider(*due, DueKind::PushCancel),
            None => {}
        }
        match &self.hello_req {
            Some(HelloReq::Active { renew_at, .. }) => consider(*renew_at, DueKind::HelloRenewal),
            Some(HelloReq::Cancel { due }) => consider(*due, DueKind::HelloCancel),
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
/// - [`for_each`](Self::for_each) and [`retain`](Self::retain) visit slots
///   in a stable, deterministic order; equal deadlines fire in visit order.
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
    fn for_each(&self, f: impl FnMut(&SyncSlot<A, T>));

    /// Visits every slot mutably in the table's stable order, removing those
    /// for which `f` returns `false`.
    fn retain(&mut self, f: impl FnMut(&mut SyncSlot<A, T>) -> bool);
}

/// Locates `(graph_id, peer)` in a slice of slots sorted graph-first.
fn search_slots<A: Ord, T>(
    slots: &[SyncSlot<A, T>],
    graph_id: GraphId,
    peer: &A,
) -> Result<usize, usize> {
    slots.binary_search_by(|slot| {
        slot.graph_id
            .cmp(&graph_id)
            .then_with(|| slot.peer.cmp(peer))
    })
}

/// [`SyncSlots`] with capacity for `N` peer-graph pairs, stored inline — no
/// allocation, for `no_std` callers without a heap. Kept sorted graph-first,
/// then by peer.
///
/// Size `N` for the distinct `(graph_id, peer)` pairs in play at once; a
/// pair occupies one slot however many roles it holds. When full,
/// slot-creating calls fail ([`OutOfSlots`], or
/// [`SubscriberLimitReached`](super::SubscriberLimitReached) for the
/// remote-driven subscriber adds).
///
/// ```
/// use core::time::Duration;
///
/// use aranya_runtime::{FixedSlots, Syncer};
///
/// // Eight peer-graph pairs, no allocation.
/// let syncer: Syncer<&str, Duration, FixedSlots<&str, Duration, 8>> =
///     Syncer::new_in(FixedSlots::new());
/// # let _ = syncer;
/// ```
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

impl<A: Clone + Ord, T, const N: usize> SyncSlots<A, T> for FixedSlots<A, T, N> {
    fn get(&self, graph_id: GraphId, peer: &A) -> Option<&SyncSlot<A, T>> {
        let at = search_slots(&self.slots, graph_id, peer).ok()?;
        self.slots.get(at)
    }

    fn get_mut(&mut self, graph_id: GraphId, peer: &A) -> Option<&mut SyncSlot<A, T>> {
        let at = search_slots(&self.slots, graph_id, peer).ok()?;
        self.slots.get_mut(at)
    }

    fn get_or_insert(
        &mut self,
        graph_id: GraphId,
        peer: &A,
    ) -> Result<&mut SyncSlot<A, T>, OutOfSlots> {
        let at = match search_slots(&self.slots, graph_id, peer) {
            Ok(at) => at,
            Err(at) => {
                self.slots
                    .insert(at, SyncSlot::new(graph_id, peer.clone()))
                    .map_err(|_| OutOfSlots)?;
                at
            }
        };
        self.slots.get_mut(at).ok_or(OutOfSlots)
    }

    fn remove(&mut self, graph_id: GraphId, peer: &A) {
        if let Ok(at) = search_slots(&self.slots, graph_id, peer) {
            self.slots.remove(at);
        }
    }

    fn for_each(&self, mut f: impl FnMut(&SyncSlot<A, T>)) {
        for slot in &self.slots {
            f(slot);
        }
    }

    fn retain(&mut self, f: impl FnMut(&mut SyncSlot<A, T>) -> bool) {
        self.slots.retain_mut(f);
    }
}

/// [`SyncSlots`] that grow on demand (requires `alloc`) — the default
/// storage, never [`OutOfSlots`]. Kept sorted graph-first, then by peer.
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

impl<A: Clone + Ord, T> SyncSlots<A, T> for HeapSlots<A, T> {
    fn get(&self, graph_id: GraphId, peer: &A) -> Option<&SyncSlot<A, T>> {
        let at = search_slots(&self.slots, graph_id, peer).ok()?;
        self.slots.get(at)
    }

    fn get_mut(&mut self, graph_id: GraphId, peer: &A) -> Option<&mut SyncSlot<A, T>> {
        let at = search_slots(&self.slots, graph_id, peer).ok()?;
        self.slots.get_mut(at)
    }

    fn get_or_insert(
        &mut self,
        graph_id: GraphId,
        peer: &A,
    ) -> Result<&mut SyncSlot<A, T>, OutOfSlots> {
        let at = match search_slots(&self.slots, graph_id, peer) {
            Ok(at) => at,
            Err(at) => {
                self.slots.insert(at, SyncSlot::new(graph_id, peer.clone()));
                at
            }
        };
        self.slots.get_mut(at).ok_or(OutOfSlots)
    }

    fn remove(&mut self, graph_id: GraphId, peer: &A) {
        if let Ok(at) = search_slots(&self.slots, graph_id, peer) {
            self.slots.remove(at);
        }
    }

    fn for_each(&self, mut f: impl FnMut(&SyncSlot<A, T>)) {
        for slot in &self.slots {
            f(slot);
        }
    }

    fn retain(&mut self, f: impl FnMut(&mut SyncSlot<A, T>) -> bool) {
        self.slots.retain_mut(f);
    }
}
