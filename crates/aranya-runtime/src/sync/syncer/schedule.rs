//! Timer and role bookkeeping over the slot table.
//!
//! The schedule knows nothing about storage or the wire format. It owns the
//! slots, decides which timer fires next, and reschedules or clears every
//! timer it fires *before* reporting it, so a drain at a fixed `now`
//! terminates. The [`Syncer`](super::Syncer) drives it and does the
//! protocol work each [`Due`] item calls for.

use core::{marker::PhantomData, time::Duration};

use super::{
    HelloConfig, Limits, OutOfSlots, PeerConfig, PushConfig, SyncInstant, SyncSlot, SyncSlots,
    slots::{
        DueKind, HelloRequest, HelloSubscriber, Inflight, PollTarget, PushRequest, PushSubscriber,
        SubscribeInflight,
    },
};
use crate::{storage::GraphId, sync::PeerCache};

/// A subscribe or hello-subscribe was refused: at the subscriber cap or out
/// of slots.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct SubscriberLimitReached;

/// A timer that fired, already rescheduled or cleared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Due<A> {
    pub(crate) kind: DueKind,
    pub(crate) graph_id: GraphId,
    pub(crate) peer: A,
}

/// Which slots may fire a given timer kind: any, or only the one that owns
/// the active session.
#[derive(Clone, Debug)]
pub(crate) enum Gate<A> {
    Open,
    Only(GraphId, A),
}

impl<A: PartialEq> Gate<A> {
    fn allows(&self, graph_id: GraphId, peer: &A) -> bool {
        match self {
            Self::Open => true,
            Self::Only(g, p) => *g == graph_id && p == peer,
        }
    }
}

/// Renewal cadence for an outbound subscription: half its lifetime, floored
/// at `min_delay`.
fn renew_period(lifetime: Duration, min_delay: Duration) -> Duration {
    lifetime
        .checked_div(2)
        .unwrap_or(Duration::ZERO)
        .max(min_delay)
}

/// Applies one failed poll round to `role`: bumps the failure count and
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

    /// Runs `f` on every slot, refreshing deadlines and dropping empties.
    fn for_each_slot(&mut self, mut f: impl FnMut(&mut SyncSlot<A, T>)) {
        self.slots.retain(|slot| {
            f(slot);
            slot.refresh();
            !slot.is_empty()
        });
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

    /// Registers (or reconfigures) `peer` for polling. A session already in
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

    /// Unregisters `peer` from polling. Returns whether it was registered.
    pub(crate) fn remove_peer(&mut self, peer: &A, graph_id: GraphId) -> bool {
        self.modify(graph_id, peer, |slot| slot.poll.take().is_some())
            .unwrap_or(false)
    }

    /// Schedules an immediate poll, keeping any recurring interval. Returns
    /// whether the peer is registered.
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

    /// Whether a hello from `peer` for a head we lack should trigger a poll.
    pub(crate) fn wants_hello_sync(&self, graph_id: GraphId, peer: &A) -> bool {
        self.slot(graph_id, peer)
            .and_then(|slot| slot.poll.as_ref())
            .is_some_and(|poll| poll.config.sync_on_hello)
    }

    /// A poll request went out; its reply is due by `timeout_at`.
    pub(crate) fn poll_round_sent(&mut self, graph_id: GraphId, peer: &A, timeout_at: T) {
        self.modify(graph_id, peer, |slot| {
            if let Some(poll) = &mut slot.poll {
                poll.inflight = Some(Inflight {
                    awaiting_reply: true,
                    timeout_at,
                });
            }
        });
    }

    /// The reply asked for another round: keep the session, disarm the
    /// timeout, and make the poll timer due now.
    pub(crate) fn poll_follow_up(&mut self, graph_id: GraphId, peer: &A, now: T) {
        self.modify(graph_id, peer, |slot| {
            if let Some(poll) = &mut slot.poll {
                if let Some(inflight) = &mut poll.inflight {
                    inflight.awaiting_reply = false;
                }
                poll.next_at = Some(now);
            }
        });
    }

    /// The poll session ended. Success resets backoff; failure applies it.
    pub(crate) fn poll_finished(&mut self, graph_id: GraphId, peer: &A, ok: bool, now: T) {
        let limits = self.limits;
        self.modify(graph_id, peer, |slot| {
            if ok {
                if let Some(poll) = &mut slot.poll {
                    poll.inflight = None;
                    poll.failures = 0;
                }
            } else {
                fail_poll(&mut slot.poll, &limits, now);
            }
        });
    }

    // ---- outbound push request -------------------------------------------

    /// Asks `peer` to push to us; the first `Subscribe` is due immediately.
    pub(crate) fn push_subscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        cfg: PushConfig,
        now: T,
    ) -> Result<(), OutOfSlots> {
        let remain_open_secs = self.limits.clamp_remain_open_secs(cfg.remain_open);
        self.upsert(graph_id, &peer, |slot| {
            slot.push_req = Some(PushRequest::Active {
                remain_open_secs,
                max_bytes: cfg.max_bytes,
                renew_at: now,
                inflight: None,
            });
        })
    }

    /// Cancels our push subscription; one `Unsubscribe` is due immediately
    /// even if nothing was tracked.
    pub(crate) fn push_unsubscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        now: T,
    ) -> Result<(), OutOfSlots> {
        self.upsert(graph_id, &peer, |slot| {
            slot.push_req = Some(PushRequest::Cancel { due: now });
        })
    }

    pub(crate) fn has_active_push_request(&self, graph_id: GraphId, peer: &A) -> bool {
        matches!(
            self.slot(graph_id, peer).and_then(|s| s.push_req.as_ref()),
            Some(PushRequest::Active { .. })
        )
    }

    /// `(remain_open_secs, max_bytes)` of the active request, if any.
    pub(crate) fn push_request_params(&self, graph_id: GraphId, peer: &A) -> Option<(u64, u64)> {
        match self.slot(graph_id, peer)?.push_req.as_ref()? {
            PushRequest::Active {
                remain_open_secs,
                max_bytes,
                ..
            } => Some((*remain_open_secs, *max_bytes)),
            PushRequest::Cancel { .. } => None,
        }
    }

    /// A `Subscribe` with `seq` went out; its reply is due by `timeout_at`.
    pub(crate) fn push_subscribe_sent(
        &mut self,
        graph_id: GraphId,
        peer: &A,
        seq: u32,
        timeout_at: T,
    ) {
        self.modify(graph_id, peer, |slot| {
            if let Some(PushRequest::Active { inflight, .. }) = &mut slot.push_req {
                *inflight = Some(SubscribeInflight { seq, timeout_at });
            }
        });
    }

    /// Clears the in-flight subscribe if `seq` matches. Returns whether it
    /// did.
    pub(crate) fn push_subscribe_settled(&mut self, graph_id: GraphId, peer: &A, seq: u32) -> bool {
        self.modify(graph_id, peer, |slot| {
            if let Some(PushRequest::Active { inflight, .. }) = &mut slot.push_req
                && inflight.is_some_and(|i| i.seq == seq)
            {
                *inflight = None;
                return true;
            }
            false
        })
        .unwrap_or(false)
    }

    // ---- outbound hello request ------------------------------------------

    /// Asks `peer` to send us hellos; the first `HelloSubscribe` is due
    /// immediately.
    pub(crate) fn hello_subscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        cfg: HelloConfig,
        now: T,
    ) -> Result<(), OutOfSlots> {
        let cfg = HelloConfig {
            graph_change_delay: self.limits.clamp_delay(cfg.graph_change_delay),
            duration: self.limits.clamp_lifetime(cfg.duration),
            schedule_delay: self.limits.clamp_delay(cfg.schedule_delay),
        };
        self.upsert(graph_id, &peer, |slot| {
            slot.hello_req = Some(HelloRequest::Active { cfg, renew_at: now });
        })
    }

    /// Cancels our hello subscription; one `HelloUnsubscribe` is due
    /// immediately even if nothing was tracked.
    pub(crate) fn hello_unsubscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        now: T,
    ) -> Result<(), OutOfSlots> {
        self.upsert(graph_id, &peer, |slot| {
            slot.hello_req = Some(HelloRequest::Cancel { due: now });
        })
    }

    pub(crate) fn hello_request_params(&self, graph_id: GraphId, peer: &A) -> Option<HelloConfig> {
        match self.slot(graph_id, peer)?.hello_req.as_ref()? {
            HelloRequest::Active { cfg, .. } => Some(*cfg),
            HelloRequest::Cancel { .. } => None,
        }
    }

    // ---- inbound push subscriber -----------------------------------------

    /// Registers `peer` as a push subscriber (re-subscribing replaces). A
    /// push is queued immediately so a new subscriber catches up without
    /// polling first.
    pub(crate) fn add_push_subscriber(
        &mut self,
        peer: A,
        graph_id: GraphId,
        remain_open: Duration,
        max_bytes: u64,
        now: T,
    ) -> Result<(), SubscriberLimitReached> {
        self.prune(now);
        let replacing = self
            .slot(graph_id, &peer)
            .is_some_and(|slot| slot.push_sub.is_some());
        if !replacing && self.count_push_subs() >= self.limits.max_push_subs {
            return Err(SubscriberLimitReached);
        }
        let expires_at = now.saturating_add(self.limits.clamp_lifetime(remain_open));
        self.upsert(graph_id, &peer, |slot| {
            let queued = slot.push_sub.take().and_then(|sub| sub.push_due);
            slot.push_sub = Some(PushSubscriber {
                expires_at,
                remaining_bytes: max_bytes,
                push_due: Some(queued.map_or(now, |at| at.min(now))),
            });
        })
        .map_err(|OutOfSlots| SubscriberLimitReached)
    }

    /// Removes `peer`'s push subscription. Returns whether one was present.
    pub(crate) fn remove_push_subscriber(&mut self, peer: &A, graph_id: GraphId) -> bool {
        self.modify(graph_id, peer, |slot| slot.push_sub.take().is_some())
            .unwrap_or(false)
    }

    /// Remaining byte budget of a live push subscriber, if any.
    pub(crate) fn push_budget(&self, graph_id: GraphId, peer: &A, now: T) -> Option<u64> {
        let sub = self.slot(graph_id, peer)?.push_sub.as_ref()?;
        sub.is_live(now).then_some(sub.remaining_bytes)
    }

    /// Consumes `bytes` of the subscriber's budget; drops it at zero.
    pub(crate) fn record_push(&mut self, graph_id: GraphId, peer: &A, bytes: u64) {
        self.modify(graph_id, peer, |slot| {
            if let Some(sub) = &mut slot.push_sub {
                sub.remaining_bytes = sub.remaining_bytes.saturating_sub(bytes);
                if sub.remaining_bytes == 0 {
                    slot.push_sub = None;
                }
            }
        });
    }

    /// Queues another push at `now`: a multi-message push continues on the
    /// next drain.
    pub(crate) fn requeue_push(&mut self, graph_id: GraphId, peer: &A, now: T) {
        self.modify(graph_id, peer, |slot| {
            if let Some(sub) = &mut slot.push_sub {
                sub.push_due = Some(now);
            }
        });
    }

    // ---- inbound hello subscriber ----------------------------------------

    /// Registers `peer` as a hello subscriber (re-subscribing replaces and
    /// resets its schedule). The first scheduled hello is one
    /// `schedule_delay` out; the first local change always notifies.
    pub(crate) fn add_hello_subscriber(
        &mut self,
        peer: A,
        graph_id: GraphId,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
        now: T,
    ) -> Result<(), SubscriberLimitReached> {
        self.prune(now);
        let replacing = self
            .slot(graph_id, &peer)
            .is_some_and(|slot| slot.hello_sub.is_some());
        if !replacing && self.count_hello_subs() >= self.limits.max_hello_subs {
            return Err(SubscriberLimitReached);
        }
        let debounce = self.limits.clamp_delay(graph_change_delay);
        let schedule_delay = self.limits.clamp_delay(schedule_delay);
        let expires_at = now.saturating_add(self.limits.clamp_lifetime(duration));
        let next_hello = now.saturating_add(schedule_delay);
        self.upsert(graph_id, &peer, |slot| {
            slot.hello_sub = Some(HelloSubscriber {
                debounce,
                schedule_delay,
                next_change_allowed: None,
                expires_at,
                next_hello,
            });
        })
        .map_err(|OutOfSlots| SubscriberLimitReached)
    }

    /// Removes `peer`'s hello subscription. Returns whether one was present.
    pub(crate) fn remove_hello_subscriber(&mut self, peer: &A, graph_id: GraphId) -> bool {
        self.modify(graph_id, peer, |slot| slot.hello_sub.take().is_some())
            .unwrap_or(false)
    }

    // ---- graph-wide events -----------------------------------------------

    /// A local change of `graph_id`: queue a push to every live push
    /// subscriber and pull forward the hello of every subscriber past its
    /// debounce. Repeating before a drain is idempotent.
    pub(crate) fn notify_local_change(&mut self, graph_id: GraphId, now: T) {
        self.for_each_slot(|slot| {
            prune_slot(slot, now);
            if slot.graph_id() != graph_id {
                return;
            }
            if let Some(sub) = &mut slot.push_sub {
                sub.push_due.get_or_insert(now);
            }
            if let Some(sub) = &mut slot.hello_sub
                && sub.next_change_allowed.is_none_or(|at| at <= now)
            {
                sub.next_hello = sub.next_hello.min(now);
            }
        });
    }

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

    // ---- timers ----------------------------------------------------------

    /// The earliest armed timer across all slots.
    pub(crate) fn next_deadline(&self) -> Option<T> {
        self.slots.iter().filter_map(SyncSlot::deadline).min()
    }

    /// Fires the earliest timer due at `now` that the gates allow, having
    /// rescheduled or cleared it. Timers whose subject died in the meantime
    /// are cleared silently and the scan continues.
    pub(crate) fn next_due(
        &mut self,
        now: T,
        poll_gate: &Gate<A>,
        push_gate: &Gate<A>,
    ) -> Option<Due<A>> {
        loop {
            let (kind, graph_id, peer) = self.select(now, poll_gate, push_gate)?;
            if let Some(due) = self.fire(kind, graph_id, peer, now) {
                return Some(due);
            }
        }
    }

    /// Finds the earliest allowed timer at or before `now`. Slot order, then
    /// the slot's fixed role order, break exact ties.
    fn select(
        &self,
        now: T,
        poll_gate: &Gate<A>,
        push_gate: &Gate<A>,
    ) -> Option<(DueKind, GraphId, A)> {
        let mut best: Option<(T, DueKind, GraphId, A)> = None;
        for slot in self.slots.iter() {
            if slot.deadline().is_none_or(|at| at > now) {
                continue;
            }
            slot.for_each_deadline(|at, kind| {
                if at > now {
                    return;
                }
                let allowed = match kind {
                    DueKind::Poll => poll_gate.allows(slot.graph_id(), slot.peer()),
                    DueKind::Push => push_gate.allows(slot.graph_id(), slot.peer()),
                    DueKind::PollTimeout
                    | DueKind::ScheduledHello
                    | DueKind::PushRenewal
                    | DueKind::SubscribeTimeout
                    | DueKind::PushCancel
                    | DueKind::HelloRenewal
                    | DueKind::HelloCancel => true,
                };
                if allowed && best.as_ref().is_none_or(|&(b, ..)| at < b) {
                    best = Some((at, kind, slot.graph_id(), slot.peer().clone()));
                }
            });
        }
        best.map(|(_, kind, graph_id, peer)| (kind, graph_id, peer))
    }

    /// Reschedules or clears the fired timer. Returns `None` when the item
    /// went stale (its role is gone or dead), in which case the timer is
    /// also gone so a rescan cannot select it again.
    fn fire(&mut self, kind: DueKind, graph_id: GraphId, peer: A, now: T) -> Option<Due<A>> {
        let limits = self.limits;
        let fired = self.modify(graph_id, &peer, |slot| match kind {
            DueKind::Poll => {
                let poll = slot.poll.as_mut()?;
                poll.next_at = poll.config.interval.map(|iv| now.saturating_add(iv));
                Some(kind)
            }
            DueKind::PollTimeout => {
                if !slot.poll.as_ref().is_some_and(PollTarget::awaiting_reply) {
                    return None;
                }
                fail_poll(&mut slot.poll, &limits, now);
                Some(kind)
            }
            DueKind::Push => {
                let sub = slot.push_sub.as_mut()?;
                sub.push_due = None;
                if sub.is_live(now) {
                    Some(kind)
                } else {
                    slot.push_sub = None;
                    None
                }
            }
            DueKind::ScheduledHello => {
                let sub = slot.hello_sub.as_mut()?;
                if sub.expires_at <= now {
                    // No farewell hello.
                    slot.hello_sub = None;
                    return None;
                }
                // Any sent hello satisfies the keepalive too, so both
                // timers reset.
                sub.next_change_allowed = Some(now.saturating_add(sub.debounce));
                sub.next_hello = now.saturating_add(sub.schedule_delay);
                Some(kind)
            }
            DueKind::PushRenewal => match &mut slot.push_req {
                Some(PushRequest::Active {
                    remain_open_secs,
                    renew_at,
                    inflight: None,
                    ..
                }) => {
                    *renew_at = now.saturating_add(renew_period(
                        Duration::from_secs(*remain_open_secs),
                        limits.min_delay,
                    ));
                    Some(kind)
                }
                _ => None,
            },
            DueKind::SubscribeTimeout => {
                if let Some(PushRequest::Active { inflight, .. }) = &mut slot.push_req {
                    *inflight = None;
                }
                None
            }
            DueKind::PushCancel => match slot.push_req {
                Some(PushRequest::Cancel { .. }) => {
                    slot.push_req = None;
                    Some(kind)
                }
                _ => None,
            },
            DueKind::HelloRenewal => match &mut slot.hello_req {
                Some(HelloRequest::Active { cfg, renew_at }) => {
                    *renew_at = now.saturating_add(renew_period(cfg.duration, limits.min_delay));
                    Some(kind)
                }
                _ => None,
            },
            DueKind::HelloCancel => match slot.hello_req {
                Some(HelloRequest::Cancel { .. }) => {
                    slot.hello_req = None;
                    Some(kind)
                }
                _ => None,
            },
        });
        fired.flatten().map(|kind| Due {
            kind,
            graph_id,
            peer,
        })
    }

    /// Clears expired subscriber roles, dropping slots that end up empty.
    fn prune(&mut self, now: T) {
        self.for_each_slot(|slot| prune_slot(slot, now));
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

    fn count_push_subs(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.push_sub.is_some())
            .count()
    }

    fn count_hello_subs(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.hello_sub.is_some())
            .count()
    }
}

/// Clears dead subscriber roles on one slot.
fn prune_slot<A, T: SyncInstant>(slot: &mut SyncSlot<A, T>, now: T) {
    if slot.push_sub.as_ref().is_some_and(|sub| !sub.is_live(now)) {
        slot.push_sub = None;
    }
    if slot
        .hello_sub
        .as_ref()
        .is_some_and(|sub| sub.expires_at <= now)
    {
        slot.hello_sub = None;
    }
}
