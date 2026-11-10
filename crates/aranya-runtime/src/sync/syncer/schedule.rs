//! Timer bookkeeping over the slot table.
//!
//! The schedule knows nothing about storage or the wire format. It owns the
//! slots, decides which timer fires next, and reschedules or clears every
//! timer it fires *before* reporting it, so a drain at a fixed `now`
//! terminates. The [`Syncer`](super::Syncer) drives it and does the
//! protocol work each [`Due`] item calls for.

use core::marker::PhantomData;

use super::{
    Limits, OutOfSlots, PeerConfig, SyncInstant, SyncSlot, SyncSlots,
    slots::{DueKind, Inflight},
};
use crate::{
    storage::GraphId,
    sync::{PeerCache, SyncRequester},
};

/// A poll that is due: the caller should send a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Due<A> {
    pub(crate) graph_id: GraphId,
    pub(crate) peer: A,
}

/// How a poll exchange ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PollResult {
    /// The peer has nothing more for us.
    Done,
    /// The peer had more than fit in its reply; poll again now.
    More,
    /// The request or its reply failed.
    Failed,
}

/// Applies one failed poll to `slot`: bumps the failure count and
/// reschedules with backoff, or stops polling a one-shot peer that is out
/// of retries.
fn fail_poll<A, T: SyncInstant>(slot: &mut SyncSlot<A, T>, limits: &Limits, now: T) {
    slot.inflight = None;
    slot.failures = slot.failures.saturating_add(1);
    if slot.config.interval.is_none() && slot.failures > limits.max_one_shot_retries {
        slot.failures = 0;
        slot.next_at = None;
        return;
    }
    slot.next_at = Some(now.saturating_add(limits.backoff(slot.failures, slot.config.interval)));
}

#[derive(Debug)]
pub(crate) struct Schedule<A, T, S> {
    slots: S,
    limits: Limits,
    marker: PhantomData<(A, T)>,
}

impl<A, T, S> Schedule<A, T, S>
where
    A: Clone + Eq,
    T: SyncInstant,
    S: SyncSlots<A, T>,
{
    pub(crate) fn new(limits: Limits, slots: S) -> Self {
        Self {
            slots,
            limits: limits.normalized(),
            marker: PhantomData,
        }
    }

    pub(crate) fn limits(&self) -> &Limits {
        &self.limits
    }

    // ---- slot plumbing ---------------------------------------------------

    fn slot(&self, graph_id: GraphId, peer: &A) -> Option<&SyncSlot<A, T>> {
        self.slots.get(graph_id, peer)
    }

    // ---- polling ---------------------------------------------------------

    /// Registers (or reconfigures) `peer` for polling. A request already in
    /// flight on the pair is kept.
    pub(crate) fn add_peer(
        &mut self,
        peer: A,
        graph_id: GraphId,
        cfg: PeerConfig,
        now: T,
    ) -> Result<(), OutOfSlots> {
        let config = PeerConfig {
            interval: cfg.interval.map(|iv| self.limits.clamp_delay(iv)),
            ..cfg
        };
        let next_at = if config.sync_now {
            Some(now)
        } else {
            config.interval.map(|iv| now.saturating_add(iv))
        };
        let slot = self.slots.get_or_insert(graph_id, &peer)?;
        slot.config = config;
        slot.next_at = next_at;
        slot.failures = 0;
        Ok(())
    }

    /// Forgets `peer`: its schedule, any request in flight, and its cache.
    pub(crate) fn remove_peer(&mut self, peer: &A, graph_id: GraphId) {
        self.slots.remove(graph_id, peer);
    }

    /// Schedules an immediate poll, keeping any recurring interval and
    /// creating the slot on a miss. With a request in flight, the poll
    /// follows its reply.
    pub(crate) fn sync_now(
        &mut self,
        peer: &A,
        graph_id: GraphId,
        now: T,
    ) -> Result<(), OutOfSlots> {
        self.slots.get_or_insert(graph_id, peer)?.next_at = Some(now);
        Ok(())
    }

    /// A poll request went out; `inflight` awaits its reply.
    pub(crate) fn poll_sent(&mut self, graph_id: GraphId, peer: &A, inflight: Inflight<T>) {
        if let Some(slot) = self.slots.get_mut(graph_id, peer) {
            slot.inflight = Some(inflight);
        }
    }

    /// Takes the requester of the request `seq` names, if it is still the
    /// one in flight. The poll timer stays disarmed until
    /// [`poll_finished`](Self::poll_finished).
    pub(crate) fn take_inflight(
        &mut self,
        graph_id: GraphId,
        peer: &A,
        seq: u32,
    ) -> Option<SyncRequester> {
        let slot = self.slots.get_mut(graph_id, peer)?;
        if slot.inflight.as_ref().is_none_or(|i| i.seq != seq) {
            return None;
        }
        slot.inflight.take().map(|i| i.requester)
    }

    /// Fails the request `seq` names, if it is still the one in flight.
    /// Returns whether it was.
    pub(crate) fn fail_inflight(&mut self, graph_id: GraphId, peer: &A, seq: u32, now: T) -> bool {
        let limits = self.limits;
        let Some(slot) = self.slots.get_mut(graph_id, peer) else {
            return false;
        };
        let matches = slot.inflight.as_ref().is_some_and(|i| i.seq == seq);
        if matches {
            fail_poll(slot, &limits, now);
        }
        matches
    }

    /// Records how a poll exchange ended. Success resets backoff and keeps
    /// the interval reschedule made when the poll fired; `More` makes the
    /// next poll due now; failure applies backoff.
    pub(crate) fn poll_finished(
        &mut self,
        graph_id: GraphId,
        peer: &A,
        result: PollResult,
        now: T,
    ) {
        let limits = self.limits;
        let Some(slot) = self.slots.get_mut(graph_id, peer) else {
            return;
        };
        match result {
            PollResult::Done | PollResult::More => {
                slot.inflight = None;
                slot.failures = 0;
                if result == PollResult::More {
                    slot.next_at = Some(now);
                }
            }
            PollResult::Failed => fail_poll(slot, &limits, now),
        }
    }

    // ---- graph-wide ------------------------------------------------------

    /// Drops every slot of `graph_id`.
    pub(crate) fn remove_graph(&mut self, graph_id: GraphId) {
        self.slots.retain(|slot| slot.graph_id() != graph_id);
    }

    /// Every peer with a slot, and its configuration.
    pub(crate) fn peers(&self) -> impl Iterator<Item = (GraphId, &A, PeerConfig)> {
        self.slots
            .iter()
            .map(|slot| (slot.graph_id(), slot.peer(), slot.config))
    }

    pub(crate) fn cache(&self, graph_id: GraphId, peer: &A) -> Option<&PeerCache> {
        self.slot(graph_id, peer).map(|slot| &slot.cache)
    }

    pub(crate) fn cache_mut(&mut self, graph_id: GraphId, peer: &A) -> Option<&mut PeerCache> {
        self.slots
            .get_mut(graph_id, peer)
            .map(|slot| &mut slot.cache)
    }

    /// The cache for `(graph_id, peer)`, creating its slot on a miss.
    pub(crate) fn cache_or_insert(
        &mut self,
        graph_id: GraphId,
        peer: &A,
    ) -> Result<&mut PeerCache, OutOfSlots> {
        Ok(&mut self.slots.get_or_insert(graph_id, peer)?.cache)
    }

    // ---- timers ----------------------------------------------------------

    /// Whether the in-flight cap holds back due polls.
    fn at_inflight_cap(&self) -> bool {
        self.slots.iter().filter(|slot| slot.is_inflight()).count()
            >= self.limits.max_inflight_polls
    }

    /// The earliest timer that can fire. While the in-flight cap is
    /// reached, poll timers are skipped: they wait on a reply or timeout,
    /// not on the clock.
    pub(crate) fn next_deadline(&self) -> Option<T> {
        let polls_allowed = !self.at_inflight_cap();
        self.slots
            .iter()
            .filter_map(SyncSlot::timer)
            .filter(|&(_, kind)| polls_allowed || kind != DueKind::Poll)
            .map(|(at, _)| at)
            .min()
    }

    /// Returns the earliest poll due at `now`, having rescheduled it.
    /// Timeouts due at `now` are applied along the way.
    pub(crate) fn next_due(&mut self, now: T) -> Option<Due<A>> {
        loop {
            let (kind, graph_id, peer) = self.select(now)?;
            if let Some(due) = self.fire(kind, graph_id, peer, now) {
                return Some(due);
            }
        }
    }

    /// Finds the earliest timer at or before `now` that may fire. Slot
    /// order breaks exact ties.
    fn select(&self, now: T) -> Option<(DueKind, GraphId, A)> {
        let polls_allowed = !self.at_inflight_cap();
        let mut best: Option<(T, DueKind, GraphId, A)> = None;
        for slot in self.slots.iter() {
            let Some((at, kind)) = slot.timer() else {
                continue;
            };
            if at > now || (kind == DueKind::Poll && !polls_allowed) {
                continue;
            }
            if best.as_ref().is_none_or(|&(b, ..)| at < b) {
                best = Some((at, kind, slot.graph_id(), slot.peer().clone()));
            }
        }
        best.map(|(_, kind, graph_id, peer)| (kind, graph_id, peer))
    }

    /// Reschedules or clears the fired timer. Returns the poll to send, or
    /// `None` for a timer settled here (a timeout), which is also gone so a
    /// rescan cannot select it again.
    fn fire(&mut self, kind: DueKind, graph_id: GraphId, peer: A, now: T) -> Option<Due<A>> {
        let limits = self.limits;
        let slot = self.slots.get_mut(graph_id, &peer)?;
        match kind {
            DueKind::Poll => {
                slot.next_at = slot.config.interval.map(|iv| now.saturating_add(iv));
                Some(Due { graph_id, peer })
            }
            DueKind::PollTimeout => {
                fail_poll(slot, &limits, now);
                None
            }
        }
    }

    /// Number of slots in the table.
    #[cfg(test)]
    pub(crate) fn slot_count(&self) -> usize {
        self.slots.iter().count()
    }

    /// Number of requests awaiting a reply.
    #[cfg(test)]
    pub(crate) fn inflight_count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_inflight()).count()
    }
}
