//! Per-peer sync state and the caller-supplied storage it lives in.

use alloc::vec::Vec;

use super::PeerConfig;
use crate::{
    storage::GraphId,
    sync::{PeerCache, SyncRequester},
};

/// The caller-supplied [`SyncSlots`] have no room for another peer-graph
/// pair. Free a slot or supply larger storage; never returned through
/// [`HeapSlots`], which grows on demand.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("out of syncer slots")]
pub struct OutOfSlots;

/// A poll request awaiting its reply.
#[derive(Debug)]
pub(crate) struct Inflight<T> {
    /// Decodes the reply.
    pub(crate) requester: SyncRequester,
    /// Matches the reply's [`Token`](super::Token) to this request.
    pub(crate) seq: u32,
    /// When the request counts as failed.
    pub(crate) timeout_at: T,
}

/// Which timer fired.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum DueKind {
    Poll,
    PollTimeout,
}

/// One peer-graph pair's sync state: an entry in the caller-supplied
/// [`SyncSlots`].
///
/// A slot holds the pair's poll schedule and the [`PeerCache`] recording
/// what the peer is known to hold. A slot with nothing scheduled and no
/// request in flight is not polled. The contents are private; [`SyncSlots`]
/// implementations only construct empty slots ([`new`](Self::new)) and key
/// them by [`graph_id`](Self::graph_id) and [`peer`](Self::peer).
#[derive(Debug)]
pub struct SyncSlot<A, T> {
    graph_id: GraphId,
    peer: A,
    pub(crate) cache: PeerCache,
    pub(crate) config: PeerConfig,
    /// When the next poll is due. Disarmed while a request is in flight.
    pub(crate) next_at: Option<T>,
    /// Consecutive failed polls; drives backoff. Reset on success.
    pub(crate) failures: u8,
    pub(crate) inflight: Option<Inflight<T>>,
}

impl<A, T> SyncSlot<A, T> {
    /// Creates an empty slot for `(graph_id, peer)`, which is what
    /// [`SyncSlots::get_or_insert`] implementations insert on a miss.
    #[must_use]
    pub fn new(graph_id: GraphId, peer: A) -> Self {
        Self {
            graph_id,
            peer,
            cache: PeerCache::new(),
            config: PeerConfig::default(),
            next_at: None,
            failures: 0,
            inflight: None,
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

    /// Whether a poll request is awaiting its reply.
    pub(crate) fn is_inflight(&self) -> bool {
        self.inflight.is_some()
    }

    /// The slot's armed timer, if any: the reply timeout while a request is
    /// in flight, otherwise the next scheduled poll.
    pub(crate) fn timer(&self) -> Option<(T, DueKind)>
    where
        T: Copy,
    {
        match &self.inflight {
            Some(inflight) => Some((inflight.timeout_at, DueKind::PollTimeout)),
            None => self.next_at.map(|at| (at, DueKind::Poll)),
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
/// When full, slot-creating calls fail with [`OutOfSlots`].
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
/// Every slot is created by a local call, so remote peers cannot grow it.
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
