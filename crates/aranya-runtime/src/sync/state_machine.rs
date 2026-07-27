//! A sans-I/O syncer state machine.
//!
//! [`Syncer`] owns the *stateful* parts of the three sync mechanisms — poll
//! schedules, subscriber tables in both directions, outbound-subscription
//! renewal, debounce/expiry/budget, remote input clamping — and emits a
//! [`SyncAction`] for every outbound message, leaving I/O, clocks, storage,
//! and crypto to the caller. Like time ([`SyncInstant`]), memory is a trait
//! boundary: all per-peer state lives in caller-supplied [`SyncSlots`].

use core::{marker::PhantomData, time::Duration};

use super::SubscribeResponse;
use crate::storage::GraphId;

mod action;
mod config;
mod slots;
mod snapshot;
mod tests;

pub use action::{OutOfSlots, SubscriberLimitReached, SyncAction};
pub use config::{
    DEFAULT_MAX_SUB_DURATION, DEFAULT_MAX_SUBSCRIBERS, DEFAULT_MIN_DELAY, Limits, LimitsBuilder,
    PeerConfig,
};
pub use slots::{FixedSlots, HeapSlots, SyncSlot, SyncSlots};
pub use snapshot::SnapshotError;

use slots::{DueKind, HelloReq, HelloSub, PollState, PushReq, PushSub};

/// A monotonic point in time supplied by the caller.
///
/// The syncer only orders instants and does saturating [`Duration`]
/// arithmetic with them; it never reads a clock. The crate implements this
/// for [`Duration`] (a duration-since-epoch instant), so a `std` caller can
/// keep a `base: std::time::Instant` and pass `now = base.elapsed()`, and a
/// `no_std` caller can pass whatever monotonic tick its platform exposes.
pub trait SyncInstant: Copy + Ord {
    /// Returns `self + d`, saturating at the type's maximum.
    #[must_use]
    fn saturating_add(self, d: Duration) -> Self;

    /// Returns `self - earlier`, saturating at [`Duration::ZERO`] when
    /// `earlier > self`.
    #[must_use]
    fn saturating_duration_since(self, earlier: Self) -> Duration;
}

impl SyncInstant for Duration {
    fn saturating_add(self, d: Duration) -> Self {
        // Resolves to the inherent method, not this impl.
        Self::saturating_add(self, d)
    }

    fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.saturating_sub(earlier)
    }
}

/// Renewal cadence for an outbound subscription: half its lifetime, floored
/// at `min_delay` so it stays timely without busy-looping.
fn renew_period(lifetime: Duration, min_delay: Duration) -> Duration {
    lifetime
        .checked_div(2)
        .unwrap_or(Duration::ZERO)
        .max(min_delay)
}

/// A sans-I/O, transport-, clock-, and memory-agnostic syncer state machine.
///
/// `Syncer` is the orchestration layer above the sync protocol primitives
/// ([`SyncRequester`], [`SyncResponder`], [`SyncIncoming`]): it decides
/// *when to sync with which peer* across poll, push, and hello, in both the
/// requester and responder roles, including the requester-side subscription
/// lifecycle (request, renew, tear down).
///
/// It performs no I/O, reads no clock, and allocates no memory: the caller
/// feeds *events* and the current *time*, drains [`SyncAction`]s — each
/// names the primitive call to make — and sleeps until
/// [`next_deadline`](Self::next_deadline). Time is a trait boundary
/// ([`SyncInstant`]), the peer-address type `A` is generic, and per-peer
/// state lives in caller-supplied [`SyncSlots`] (`S`, default
/// [`HeapSlots`]). Every duration a peer supplies is clamped into
/// [`Limits`], so a hostile peer cannot stall or flood the machine.
/// Answering an inbound poll is stateless and stays with the caller.
///
/// [`SyncRequester`]: super::SyncRequester
/// [`SyncResponder`]: super::SyncResponder
/// [`SyncIncoming`]: super::SyncIncoming
///
/// # Driving
///
/// React to whatever woke you → feed the event → drain
/// [`poll_action`](Self::poll_action) until `None`, performing each action's
/// I/O → sleep until [`next_deadline`](Self::next_deadline) or the next
/// event.
///
/// ```
/// use core::time::Duration;
///
/// use aranya_runtime::{GraphId, PeerConfig, SyncAction, Syncer};
///
/// // `Duration` as duration-since-start; any `SyncInstant` type works.
/// let mut syncer: Syncer<&str, Duration> = Syncer::new();
/// let graph_id = GraphId::default();
/// let mut now = Duration::ZERO;
///
/// syncer
///     .add_peer(
///         "peer-a",
///         graph_id,
///         PeerConfig::periodic(Duration::from_secs(30)),
///         now,
///     )
///     .expect("HeapSlots never runs out");
///
/// // Drain due actions, performing each one's I/O.
/// while let Some(action) = syncer.poll_action(now) {
///     match action {
///         SyncAction::Poll { peer, graph_id } => { /* SyncRequester::poll + receive + commit */ }
///         _ => { /* subscribe/unsubscribe/push/hello I/O */ }
///     }
/// }
///
/// // Sleep until the next timer (or the next event), then repeat.
/// now = syncer
///     .next_deadline()
///     .expect("a recurring poll is scheduled");
/// assert!(matches!(
///     syncer.poll_action(now),
///     Some(SyncAction::Poll { .. })
/// ));
/// ```
#[derive(Debug)]
pub struct Syncer<A, T, S = HeapSlots<A, T>> {
    /// One slot per peer-graph pair, holding every role and timer.
    slots: S,
    limits: Limits,
    marker: PhantomData<(A, T)>,
}

impl<A: Clone + Ord, T: SyncInstant> Syncer<A, T> {
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

impl<A: Clone + Ord, T: SyncInstant, S: SyncSlots<A, T> + Default> Default for Syncer<A, T, S> {
    fn default() -> Self {
        Self::new_in(S::default())
    }
}

impl<A: Clone + Ord, T: SyncInstant, S: SyncSlots<A, T>> Syncer<A, T, S> {
    /// Creates a syncer with [`Limits::default`], storing its state in the
    /// caller-supplied `slots`.
    #[must_use]
    pub fn new_in(slots: S) -> Self {
        Self::with_limits_in(Limits::default(), slots)
    }

    /// Creates a syncer with the given limits, storing its state in the
    /// caller-supplied `slots`.
    ///
    /// `min_delay` is floored at 1 ns so the drain-termination guarantee
    /// cannot be configured away.
    #[must_use]
    pub fn with_limits_in(mut limits: Limits, slots: S) -> Self {
        limits.min_delay = limits.min_delay.max(Duration::from_nanos(1));
        Self {
            slots,
            limits,
            marker: PhantomData,
        }
    }

    /// Registers (or reconfigures) `peer` for poll scheduling.
    ///
    /// A recurring `interval` is floored at `min_delay`. With
    /// [`sync_now`](PeerConfig::sync_now) the first poll is due immediately;
    /// otherwise one interval from `now` (if recurring).
    pub fn add_peer(
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
        let next_sync = if config.sync_now {
            Some(now)
        } else {
            config.interval.map(|iv| now.saturating_add(iv))
        };
        let slot = self.slots.get_or_insert(graph_id, &peer)?;
        slot.poll = Some(PollState { config, next_sync });
        Ok(())
    }

    /// Unregisters `peer` from poll scheduling. Returns whether it was
    /// registered.
    pub fn remove_peer(&mut self, peer: &A, graph_id: GraphId) -> bool {
        let Some(slot) = self.slots.get_mut(graph_id, peer) else {
            return false;
        };
        let removed = slot.poll.take().is_some();
        self.drop_if_empty(graph_id, peer);
        removed
    }

    /// Schedules an immediate poll of `peer`, keeping any recurring
    /// interval. Returns whether the peer is registered.
    pub fn sync_now(&mut self, peer: &A, graph_id: GraphId, now: T) -> bool {
        let Some(slot) = self.slots.get_mut(graph_id, peer) else {
            return false;
        };
        match &mut slot.poll {
            Some(state) => {
                state.next_sync = Some(now);
                true
            }
            None => false,
        }
    }

    /// Asks `peer` to push updates to us, and tracks the request so the
    /// emitted [`SyncAction::Subscribe`] is re-emitted at half the
    /// subscription's lifetime until [`unsubscribe`](Self::unsubscribe).
    ///
    /// `remain_open` is rounded up to whole wire seconds (minimum 1 s) and
    /// capped at `max_sub_duration`. The initial [`SyncAction::Subscribe`]
    /// is due immediately; feed the peer's reply to
    /// [`on_subscribe_response`](Self::on_subscribe_response).
    pub fn subscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        remain_open: Duration,
        max_bytes: u64,
        now: T,
    ) -> Result<(), OutOfSlots> {
        let remain_open_secs = self.limits.clamp_remain_open_secs(remain_open);
        let slot = self.slots.get_or_insert(graph_id, &peer)?;
        slot.push_req = Some(PushReq::Active {
            remain_open_secs,
            max_bytes,
            renew_at: now,
        });
        Ok(())
    }

    /// Cancels our push subscription with `peer`: renewals stop and a
    /// [`SyncAction::Unsubscribe`] is due immediately — even if untracked,
    /// for idempotent teardown (which is when a free slot may be needed).
    pub fn unsubscribe(&mut self, peer: A, graph_id: GraphId, now: T) -> Result<(), OutOfSlots> {
        let slot = self.slots.get_or_insert(graph_id, &peer)?;
        slot.push_req = Some(PushReq::Cancel { due: now });
        Ok(())
    }

    /// Feeds the peer's reply to our [`SyncAction::Subscribe`] back in.
    ///
    /// `Success` confirms (a no-op); `TooManySubscriptions` drops the
    /// tracked request so renewals stop. Re-[`subscribe`](Self::subscribe)
    /// later to retry.
    pub fn on_subscribe_response(
        &mut self,
        peer: &A,
        graph_id: GraphId,
        response: SubscribeResponse,
    ) {
        match response {
            SubscribeResponse::Success => {}
            SubscribeResponse::TooManySubscriptions => {
                let Some(slot) = self.slots.get_mut(graph_id, peer) else {
                    return;
                };
                if matches!(slot.push_req, Some(PushReq::Active { .. })) {
                    slot.push_req = None;
                    self.drop_if_empty(graph_id, peer);
                }
            }
        }
    }

    /// Registers `peer` as a push subscriber, from a decoded
    /// [`SyncIncoming::Subscribe`](super::SyncIncoming::Subscribe).
    /// Re-subscribing replaces the existing entry.
    ///
    /// `remain_open` is capped at `max_sub_duration`; `max_bytes` is the
    /// push byte budget. Errors if a new entry would exceed `max_push_subs`
    /// or the slots are full — map to
    /// [`SubscribeResponse::TooManySubscriptions`].
    pub fn add_push_subscriber(
        &mut self,
        peer: A,
        graph_id: GraphId,
        remain_open: Duration,
        max_bytes: u64,
        now: T,
    ) -> Result<(), SubscriberLimitReached> {
        self.prune(now);
        let replacing = self
            .slots
            .get(graph_id, &peer)
            .is_some_and(|slot| slot.push_sub.is_some());
        if !replacing && self.count_push_subs() >= self.limits.max_push_subs {
            return Err(SubscriberLimitReached);
        }
        let expires_at = now.saturating_add(self.limits.clamp_lifetime(remain_open));
        let slot = self
            .slots
            .get_or_insert(graph_id, &peer)
            .map_err(|OutOfSlots| SubscriberLimitReached)?;
        // A queued-but-undrained push survives the replacement, like any
        // other pending action whose subscription is still live at drain.
        let push_due = slot.push_sub.take().and_then(|sub| sub.push_due);
        slot.push_sub = Some(PushSub {
            expires_at,
            remaining_bytes: max_bytes,
            push_due,
        });
        Ok(())
    }

    /// Removes `peer`'s push subscription, from a decoded
    /// [`SyncIncoming::Unsubscribe`](super::SyncIncoming::Unsubscribe).
    /// Returns whether one was present.
    pub fn remove_push_subscriber(&mut self, peer: &A, graph_id: GraphId) -> bool {
        let Some(slot) = self.slots.get_mut(graph_id, peer) else {
            return false;
        };
        let removed = slot.push_sub.take().is_some();
        self.drop_if_empty(graph_id, peer);
        removed
    }

    /// Records `bytes` pushed to subscriber `peer`, consuming its budget.
    /// The subscription is dropped when the budget reaches zero.
    pub fn record_push(&mut self, peer: &A, graph_id: GraphId, bytes: u64) {
        let Some(slot) = self.slots.get_mut(graph_id, peer) else {
            return;
        };
        let exhausted = match &mut slot.push_sub {
            Some(sub) => {
                sub.remaining_bytes = sub.remaining_bytes.saturating_sub(bytes);
                sub.remaining_bytes == 0
            }
            None => false,
        };
        if exhausted {
            slot.push_sub = None;
            self.drop_if_empty(graph_id, peer);
        }
    }

    /// Asks `peer` to send us hello notifications, and tracks the request so
    /// the emitted [`SyncAction::HelloSubscribe`] is re-emitted at half the
    /// subscription's lifetime until
    /// [`hello_unsubscribe`](Self::hello_unsubscribe). Renewal is blind —
    /// the protocol defines no reply to a hello subscribe.
    ///
    /// The delays are floored at `min_delay` and `duration` is capped at
    /// `max_sub_duration`, keeping the request inside what a
    /// same-configured peer would grant so half-life renewal stays timely.
    /// The initial [`SyncAction::HelloSubscribe`] is due immediately.
    pub fn hello_subscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
        now: T,
    ) -> Result<(), OutOfSlots> {
        let graph_change_delay = self.limits.clamp_delay(graph_change_delay);
        let schedule_delay = self.limits.clamp_delay(schedule_delay);
        let duration = self.limits.clamp_lifetime(duration);
        let slot = self.slots.get_or_insert(graph_id, &peer)?;
        slot.hello_req = Some(HelloReq::Active {
            graph_change_delay,
            duration,
            schedule_delay,
            renew_at: now,
        });
        Ok(())
    }

    /// Cancels our hello subscription with `peer`: renewals stop and a
    /// [`SyncAction::HelloUnsubscribe`] is due immediately — even if
    /// untracked, for idempotent teardown (which is when a free slot may be
    /// needed).
    pub fn hello_unsubscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        now: T,
    ) -> Result<(), OutOfSlots> {
        let slot = self.slots.get_or_insert(graph_id, &peer)?;
        slot.hello_req = Some(HelloReq::Cancel { due: now });
        Ok(())
    }

    /// Handles a hello from `peer` for a head we lack: if the peer is
    /// registered with [`PeerConfig::sync_on_hello`], schedules an immediate
    /// poll. Returns whether one was scheduled. The caller does the "do I
    /// already have this head?" storage check first.
    pub fn on_hello(&mut self, peer: &A, graph_id: GraphId, now: T) -> bool {
        let Some(slot) = self.slots.get_mut(graph_id, peer) else {
            return false;
        };
        match &mut slot.poll {
            Some(state) if state.config.sync_on_hello => {
                state.next_sync = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Registers `peer` as a hello subscriber, from a decoded
    /// [`SyncHello::Subscribe`](super::SyncHello::Subscribe). Re-subscribing
    /// replaces the existing entry (and resets its hello schedule).
    ///
    /// The delays are floored at `min_delay` and `duration` is capped at
    /// `max_sub_duration`. The first scheduled hello is due one
    /// `schedule_delay` from `now`; the first local change always notifies.
    /// Errors if a new entry would exceed `max_hello_subs` or the slots are
    /// full.
    pub fn add_hello_subscriber(
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
            .slots
            .get(graph_id, &peer)
            .is_some_and(|slot| slot.hello_sub.is_some());
        if !replacing && self.count_hello_subs() >= self.limits.max_hello_subs {
            return Err(SubscriberLimitReached);
        }
        let graph_change_debounce = self.limits.clamp_delay(graph_change_delay);
        let schedule_delay = self.limits.clamp_delay(schedule_delay);
        let expires_at = now.saturating_add(self.limits.clamp_lifetime(duration));
        let next_hello = now.saturating_add(schedule_delay);
        let slot = self
            .slots
            .get_or_insert(graph_id, &peer)
            .map_err(|OutOfSlots| SubscriberLimitReached)?;
        slot.hello_sub = Some(HelloSub {
            graph_change_debounce,
            schedule_delay,
            next_change_allowed: None,
            expires_at,
            next_hello,
        });
        Ok(())
    }

    /// Removes `peer`'s hello subscription, from a decoded
    /// [`SyncHello::Unsubscribe`](super::SyncHello::Unsubscribe). Returns
    /// whether one was present.
    pub fn remove_hello_subscriber(&mut self, peer: &A, graph_id: GraphId) -> bool {
        let Some(slot) = self.slots.get_mut(graph_id, peer) else {
            return false;
        };
        let removed = slot.hello_sub.take().is_some();
        self.drop_if_empty(graph_id, peer);
        removed
    }

    /// Reacts to a local change of `graph_id`: a [`SyncAction::Push`] to
    /// every live push subscriber of the graph and a
    /// [`SyncAction::SendHello`] to every hello subscriber past its debounce
    /// become due immediately. Re-notifying before a drain is idempotent —
    /// one action per subscriber, however many changes accumulated.
    pub fn notify_local_change(&mut self, graph_id: GraphId, now: T) {
        self.slots.retain(|slot| {
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
            if slot.graph_id() == graph_id {
                if let Some(sub) = &mut slot.push_sub {
                    // Keep the earliest queued instant; a burst of changes
                    // collapses into one push.
                    sub.push_due.get_or_insert(now);
                }
                if let Some(sub) = &mut slot.hello_sub
                    && sub.next_change_allowed.is_none_or(|at| at <= now)
                {
                    // Pull the scheduled hello forward to fire at the
                    // drain; the sent-hello reset happens there.
                    sub.next_hello = sub.next_hello.min(now);
                }
            }
            !slot.is_empty()
        });
    }

    /// Drops all state for `graph_id`: poll schedule, subscriptions in both
    /// directions, tracked outbound requests, and due actions.
    pub fn remove_graph(&mut self, graph_id: GraphId) {
        self.slots.retain(|slot| slot.graph_id() != graph_id);
    }

    /// Returns the next action the caller should perform, or `None` when
    /// nothing is due at `now`. Drain until `None` after feeding events,
    /// then sleep until [`next_deadline`](Self::next_deadline).
    ///
    /// The earliest-due timer fires first; recurring work and one-shots
    /// share one schedule, and exact ties fire in the slot table's order.
    /// Each item is rescheduled (or cleared) *before* it is returned, so —
    /// with the enforced `min_delay` floor — an item fires at most once per
    /// drain and the drain terminates. A `Push` or `SendHello` whose
    /// subscription expired, ran out of budget, or was removed since it was
    /// queued is dropped silently.
    pub fn poll_action(&mut self, now: T) -> Option<SyncAction<A>> {
        loop {
            let (kind, graph_id, peer) = self.next_due(now)?;
            // A stale item yields no action but clears its timer, so the
            // rescan makes progress.
            if let Some(action) = self.fire_due(kind, graph_id, peer, now) {
                return Some(action);
            }
        }
    }

    /// Finds the earliest item due at or before `now`. The slot table's
    /// stable order and the slot's fixed role order break exact ties.
    fn next_due(&self, now: T) -> Option<(DueKind, GraphId, A)> {
        let mut due: Option<(T, DueKind, GraphId, A)> = None;
        self.slots.for_each(|slot| {
            slot.for_each_deadline(|at, kind| {
                if at <= now && due.as_ref().is_none_or(|&(best, ..)| at < best) {
                    due = Some((at, kind, slot.graph_id(), slot.peer().clone()));
                }
            });
        });
        due.map(|(_, kind, graph_id, peer)| (kind, graph_id, peer))
    }

    /// Fires one due item: reschedules or clears its timer, then returns the
    /// action to perform. Returns `None` when the item went stale between
    /// scan and firing — in every such case the timer is also gone, so a
    /// rescan cannot select it again.
    fn fire_due(
        &mut self,
        kind: DueKind,
        graph_id: GraphId,
        peer: A,
        now: T,
    ) -> Option<SyncAction<A>> {
        let min_delay = self.limits.min_delay;
        let slot = self.slots.get_mut(graph_id, &peer)?;
        match kind {
            DueKind::Poll => {
                let state = slot.poll.as_mut()?;
                state.next_sync = state.config.interval.map(|iv| now.saturating_add(iv));
                Some(SyncAction::Poll { peer, graph_id })
            }
            DueKind::Push => {
                if slot.push_sub.as_ref().is_some_and(|sub| sub.is_live(now)) {
                    if let Some(sub) = &mut slot.push_sub {
                        sub.push_due = None;
                    }
                    return Some(SyncAction::Push { peer, graph_id });
                }
                // Died between queue and drain: drop silently.
                slot.push_sub = None;
                self.drop_if_empty(graph_id, &peer);
                None
            }
            DueKind::ScheduledHello => {
                let expired = slot
                    .hello_sub
                    .as_ref()
                    .is_none_or(|sub| sub.expires_at <= now);
                if expired {
                    // No farewell hello; the scan continues.
                    slot.hello_sub = None;
                    self.drop_if_empty(graph_id, &peer);
                    return None;
                }
                if let Some(sub) = &mut slot.hello_sub {
                    // Any sent hello also satisfies the keepalive, so both
                    // timers reset: the next scheduled hello waits a full
                    // period instead of re-sending the same head.
                    sub.next_change_allowed = Some(now.saturating_add(sub.graph_change_debounce));
                    sub.next_hello = now.saturating_add(sub.schedule_delay);
                }
                Some(SyncAction::SendHello { peer, graph_id })
            }
            DueKind::PushRenewal => {
                let Some(PushReq::Active {
                    remain_open_secs,
                    max_bytes,
                    renew_at,
                }) = &mut slot.push_req
                else {
                    return None;
                };
                let (remain_open_secs, max_bytes) = (*remain_open_secs, *max_bytes);
                *renew_at = now.saturating_add(renew_period(
                    Duration::from_secs(remain_open_secs),
                    min_delay,
                ));
                Some(SyncAction::Subscribe {
                    peer,
                    graph_id,
                    remain_open_secs,
                    max_bytes,
                })
            }
            DueKind::PushCancel => {
                if !matches!(slot.push_req, Some(PushReq::Cancel { .. })) {
                    return None;
                }
                slot.push_req = None;
                self.drop_if_empty(graph_id, &peer);
                Some(SyncAction::Unsubscribe { peer, graph_id })
            }
            DueKind::HelloRenewal => {
                let Some(HelloReq::Active {
                    graph_change_delay,
                    duration,
                    schedule_delay,
                    renew_at,
                }) = &mut slot.hello_req
                else {
                    return None;
                };
                let (graph_change_delay, duration, schedule_delay) =
                    (*graph_change_delay, *duration, *schedule_delay);
                *renew_at = now.saturating_add(renew_period(duration, min_delay));
                Some(SyncAction::HelloSubscribe {
                    peer,
                    graph_id,
                    graph_change_delay,
                    duration,
                    schedule_delay,
                })
            }
            DueKind::HelloCancel => {
                if !matches!(slot.hello_req, Some(HelloReq::Cancel { .. })) {
                    return None;
                }
                slot.hello_req = None;
                self.drop_if_empty(graph_id, &peer);
                Some(SyncAction::HelloUnsubscribe { peer, graph_id })
            }
        }
    }

    /// Returns the earliest timer — i.e. when
    /// [`poll_action`](Self::poll_action) next has work. Sleep until then
    /// (or until the next event).
    pub fn next_deadline(&self) -> Option<T> {
        let mut deadline: Option<T> = None;
        self.slots.for_each(|slot| {
            slot.for_each_deadline(|at, _| {
                if deadline.is_none_or(|best| at < best) {
                    deadline = Some(at);
                }
            });
        });
        deadline
    }

    /// Clears expired push and hello subscriber roles, dropping slots that
    /// end up empty.
    fn prune(&mut self, now: T) {
        self.slots.retain(|slot| {
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
            !slot.is_empty()
        });
    }

    /// Removes the slot for `(graph_id, peer)` once no role remains, so
    /// empty slots never pin storage.
    fn drop_if_empty(&mut self, graph_id: GraphId, peer: &A) {
        if self
            .slots
            .get(graph_id, peer)
            .is_some_and(SyncSlot::is_empty)
        {
            self.slots.remove(graph_id, peer);
        }
    }

    /// Counts slots holding a push-subscriber role.
    fn count_push_subs(&self) -> usize {
        let mut n: usize = 0;
        self.slots.for_each(|slot| {
            if slot.push_sub.is_some() {
                n = n.saturating_add(1);
            }
        });
        n
    }

    /// Counts slots holding a hello-subscriber role.
    fn count_hello_subs(&self) -> usize {
        let mut n: usize = 0;
        self.slots.for_each(|slot| {
            if slot.hello_sub.is_some() {
                n = n.saturating_add(1);
            }
        });
        n
    }
}
