//! Timer and role bookkeeping over the slot table.
//!
//! The schedule knows nothing about storage or the wire format. It owns the
//! slots, decides which timer fires next, and reschedules or clears every
//! timer it fires *before* reporting it, so a drain at a fixed `now`
//! terminates. The [`Syncer`](super::Syncer) drives it and does the
//! protocol work each [`Due`] item calls for.

use core::marker::PhantomData;

use super::{
    Limits, OutOfSlots, PeerConfig, SyncInstant, SyncSlot, SyncSlots,
    slots::{DueKind, Inflight, PollTarget},
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

/// Applies one failed poll to `role`: bumps the failure count and
/// reschedules with backoff, or drops a one-shot peer that is out of
/// retries.
fn fail_poll<T: SyncInstant>(role: &mut Option<PollTarget<T>>, limits: &Limits, now: T) {
    let Some(poll) = role.as_mut() else {
        return;
    };
    poll.inflight = None;
    poll.failures = poll.failures.saturating_add(1);
    if poll.config.interval.is_none() && poll.failures > limits.max_one_shot_retries {
        *role = None;
        return;
    }
    poll.next_at = Some(now.saturating_add(limits.backoff(poll.failures, poll.config.interval)));
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

    /// Runs `f` on an existing slot, then refreshes its deadline and drops
    /// it if it ended up empty.
    fn modify<R>(
        &mut self,
        graph_id: GraphId,
        peer: &A,
        f: impl FnOnce(&mut SyncSlot<A, T>) -> R,
    ) -> Option<R> {
        let slot = self.slots.get_mut(graph_id, peer)?;
        let r = f(slot);
        slot.refresh();
        self.drop_if_empty(graph_id, peer);
        Some(r)
    }

    /// Like [`modify`](Self::modify) but creates the slot on a miss.
    fn upsert<R>(
        &mut self,
        graph_id: GraphId,
        peer: &A,
        f: impl FnOnce(&mut SyncSlot<A, T>) -> R,
    ) -> Result<R, OutOfSlots> {
        let slot = self.slots.get_or_insert(graph_id, peer)?;
        let r = f(slot);
        slot.refresh();
        self.drop_if_empty(graph_id, peer);
        Ok(r)
    }

    fn drop_if_empty(&mut self, graph_id: GraphId, peer: &A) {
        if self
            .slots
            .get(graph_id, peer)
            .is_some_and(SyncSlot::is_empty)
        {
            self.slots.remove(graph_id, peer);
        }
    }

    fn slot(&self, graph_id: GraphId, peer: &A) -> Option<&SyncSlot<A, T>> {
        self.slots.get(graph_id, peer)
    }

    // ---- poll role -------------------------------------------------------

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
        self.upsert(graph_id, &peer, |slot| {
            let inflight = slot.poll.take().and_then(|p| p.inflight);
            slot.poll = Some(PollTarget {
                config,
                next_at,
                failures: 0,
                inflight,
            });
        })
    }

    /// Forgets `peer`: its poll role, any request in flight, and its cache.
    /// Returns whether it was registered for polling.
    pub(crate) fn remove_peer(&mut self, peer: &A, graph_id: GraphId) -> bool {
        self.modify(graph_id, peer, |slot| {
            slot.pinned = false;
            slot.poll.take().is_some()
        })
        .unwrap_or(false)
    }

    /// Schedules an immediate poll, keeping any recurring interval. With a
    /// request in flight, the poll follows its reply. Returns whether the
    /// peer is registered.
    pub(crate) fn sync_now(&mut self, peer: &A, graph_id: GraphId, now: T) -> bool {
        self.modify(graph_id, peer, |slot| match &mut slot.poll {
            Some(poll) => {
                poll.next_at = Some(now);
                true
            }
            None => false,
        })
        .unwrap_or(false)
    }

    /// A poll request went out; `inflight` awaits its reply.
    pub(crate) fn poll_sent(&mut self, graph_id: GraphId, peer: &A, inflight: Inflight<T>) {
        self.modify(graph_id, peer, |slot| {
            if let Some(poll) = &mut slot.poll {
                poll.inflight = Some(inflight);
            }
        });
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
        self.modify(graph_id, peer, |slot| {
            let poll = slot.poll.as_mut()?;
            if poll.inflight.as_ref().is_none_or(|i| i.seq != seq) {
                return None;
            }
            poll.inflight.take().map(|i| i.requester)
        })
        .flatten()
    }

    /// Fails the request `seq` names, if it is still the one in flight.
    /// Returns whether it was.
    pub(crate) fn fail_inflight(&mut self, graph_id: GraphId, peer: &A, seq: u32, now: T) -> bool {
        let limits = self.limits;
        self.modify(graph_id, peer, |slot| {
            let matches = slot
                .poll
                .as_ref()
                .and_then(|poll| poll.inflight.as_ref())
                .is_some_and(|i| i.seq == seq);
            if matches {
                fail_poll(&mut slot.poll, &limits, now);
            }
            matches
        })
        .unwrap_or(false)
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
        self.modify(graph_id, peer, |slot| match result {
            PollResult::Done | PollResult::More => {
                if let Some(poll) = &mut slot.poll {
                    poll.inflight = None;
                    poll.failures = 0;
                    if result == PollResult::More {
                        poll.next_at = Some(now);
                    }
                }
            }
            PollResult::Failed => fail_poll(&mut slot.poll, &limits, now),
        });
    }

    // ---- graph-wide ------------------------------------------------------

    /// Drops every slot of `graph_id`.
    pub(crate) fn remove_graph(&mut self, graph_id: GraphId) {
        self.slots.retain(|slot| slot.graph_id() != graph_id);
    }

    /// Every registered poll peer.
    pub(crate) fn peers(&self) -> impl Iterator<Item = (GraphId, &A, PeerConfig)> {
        self.slots.iter().filter_map(|slot| {
            slot.poll
                .as_ref()
                .map(|poll| (slot.graph_id(), slot.peer(), poll.config))
        })
    }

    pub(crate) fn cache(&self, graph_id: GraphId, peer: &A) -> Option<&PeerCache> {
        self.slot(graph_id, peer).map(|slot| &slot.cache)
    }

    pub(crate) fn cache_mut(&mut self, graph_id: GraphId, peer: &A) -> Option<&mut PeerCache> {
        self.slots
            .get_mut(graph_id, peer)
            .map(|slot| &mut slot.cache)
    }

    /// The cache for `(graph_id, peer)`, creating and pinning its slot so
    /// the cache outlives any poll role.
    pub(crate) fn pinned_cache(
        &mut self,
        graph_id: GraphId,
        peer: &A,
    ) -> Result<&mut PeerCache, OutOfSlots> {
        let slot = self.slots.get_or_insert(graph_id, peer)?;
        slot.pinned = true;
        Ok(&mut slot.cache)
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
        if !self.at_inflight_cap() {
            return self.slots.iter().filter_map(SyncSlot::deadline).min();
        }
        let mut min: Option<T> = None;
        for slot in self.slots.iter() {
            slot.for_each_deadline(|at, kind| {
                if kind != DueKind::Poll && min.is_none_or(|m| at < m) {
                    min = Some(at);
                }
            });
        }
        min
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
    /// order, then the slot's fixed timer order, break exact ties.
    fn select(&self, now: T) -> Option<(DueKind, GraphId, A)> {
        let polls_allowed = !self.at_inflight_cap();
        let mut best: Option<(T, DueKind, GraphId, A)> = None;
        for slot in self.slots.iter() {
            if slot.deadline().is_none_or(|at| at > now) {
                continue;
            }
            slot.for_each_deadline(|at, kind| {
                if at > now || (kind == DueKind::Poll && !polls_allowed) {
                    return;
                }
                if best.as_ref().is_none_or(|&(b, ..)| at < b) {
                    best = Some((at, kind, slot.graph_id(), slot.peer().clone()));
                }
            });
        }
        best.map(|(_, kind, graph_id, peer)| (kind, graph_id, peer))
    }

    /// Reschedules or clears the fired timer. Returns the poll to send, or
    /// `None` for a timer settled here (a timeout), which is also gone so a
    /// rescan cannot select it again.
    fn fire(&mut self, kind: DueKind, graph_id: GraphId, peer: A, now: T) -> Option<Due<A>> {
        let limits = self.limits;
        let fired = self.modify(graph_id, &peer, |slot| match kind {
            DueKind::Poll => {
                let poll = slot.poll.as_mut()?;
                poll.next_at = poll.config.interval.map(|iv| now.saturating_add(iv));
                Some(())
            }
            DueKind::PollTimeout => {
                fail_poll(&mut slot.poll, &limits, now);
                None
            }
        });
        fired.flatten().map(|()| Due { graph_id, peer })
    }

    /// Whether every slot's cached deadline matches a fresh computation.
    #[cfg(test)]
    pub(crate) fn deadline_cache_is_consistent(&self) -> bool {
        self.slots.iter().all(|slot| {
            let mut min: Option<T> = None;
            slot.for_each_deadline(|at, _| {
                if min.is_none_or(|m| at < m) {
                    min = Some(at);
                }
            });
            min == slot.deadline()
        })
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
