//! A sans-I/O syncer state machine.
//!
//! [`Syncer`] (see its docs for the model) owns the *stateful* parts of the
//! three sync mechanisms — poll schedules, subscriber tables in both
//! directions, outbound-subscription renewal, debounce/expiry/budget, remote
//! input clamping — and emits a [`SyncAction`] for every outbound message,
//! leaving I/O, clocks, storage, and crypto to the caller.

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use core::{fmt, time::Duration};

use rkyv::{
    api::high::{HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    de::Pool,
    rancor::{Error as RancorError, Source as _, Strategy},
    ser::allocator::ArenaHandle,
    util::AlignedVec,
};

use super::SubscribeResponse;
use crate::storage::GraphId;

/// A monotonic point in time supplied by the caller.
///
/// The syncer only orders instants and does saturating [`Duration`]
/// arithmetic with them; it never reads a clock. Any `Copy + Ord` type with
/// saturating arithmetic qualifies. The crate provides a blanket
/// implementation for [`Duration`] (a duration-since-epoch instant), so a
/// `std` caller can keep a `base: std::time::Instant` and pass
/// `now = base.elapsed()`, and a `no_std` caller can pass whatever monotonic
/// tick its platform exposes.
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

/// How a scheduled peer should be polled.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerConfig {
    /// Recurring poll interval, floored at [`LimitsBuilder::min_delay`].
    ///
    /// `None` = do not poll on a schedule.
    pub interval: Option<Duration>,
    /// Poll immediately on registration.
    pub sync_now: bool,
    /// When a hello for a head we lack arrives from this peer, poll it.
    ///
    /// Only consulted for peers registered via [`Syncer::add_peer`]: a
    /// [`Syncer::hello_subscribe`] alone does not arm hello-triggered
    /// polling — register the peer here with this flag as well.
    pub sync_on_hello: bool,
}

impl PeerConfig {
    /// Polls immediately, then every `interval`.
    #[must_use]
    pub const fn periodic(interval: Duration) -> Self {
        Self {
            interval: Some(interval),
            sync_now: true,
            sync_on_hello: false,
        }
    }

    /// Polls once, immediately, with no recurring schedule.
    #[must_use]
    pub const fn immediate() -> Self {
        Self {
            interval: None,
            sync_now: true,
            sync_on_hello: false,
        }
    }
}

/// Default cap on live push and hello subscribers.
pub const DEFAULT_MAX_SUBSCRIBERS: usize = 32;

/// Default floor for recurring and debounce delays.
pub const DEFAULT_MIN_DELAY: Duration = Duration::from_secs(1);

/// Default ceiling on subscription lifetimes.
pub const DEFAULT_MAX_SUB_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Caps and clamps on subscription state.
///
/// Every duration a peer supplies — and the local ones that drive timers — is
/// clamped into these bounds before use, so remote input can never stall or
/// flood the machine:
///
/// - Recurring and debounce delays (poll `interval`, hello `schedule_delay`
///   and `graph_change_delay`, renewal periods) are floored at
///   [`min_delay`](LimitsBuilder::min_delay).
/// - Subscription lifetimes (push `remain_open`, hello `duration`) are capped
///   at [`max_sub_duration`](LimitsBuilder::max_sub_duration).
///
/// Values are clamped rather than rejected — the hello protocol has no
/// negative reply, so a rejected subscription would be indistinguishable from
/// an accepted one to the peer.
///
/// Build one with the method-chain builder [`Limits::builder`]; every field
/// is seeded from its `DEFAULT_*` constant, so set only what you need:
/// `Limits::builder().max_push_subs(8).build()`. [`Default`] gives the
/// all-defaults value (what [`Syncer::new`] uses).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    max_push_subs: usize,
    max_hello_subs: usize,
    min_delay: Duration,
    max_sub_duration: Duration,
}

impl Limits {
    /// Starts a [`LimitsBuilder`] seeded with the `DEFAULT_*` values.
    pub fn builder() -> LimitsBuilder {
        LimitsBuilder {
            limits: Self::default(),
        }
    }

    /// Floors a recurring or debounce delay at `min_delay`.
    fn clamp_delay(&self, d: Duration) -> Duration {
        d.max(self.min_delay)
    }

    /// Caps a subscription lifetime at `max_sub_duration`.
    fn clamp_lifetime(&self, d: Duration) -> Duration {
        d.min(self.max_sub_duration)
    }

    /// Normalizes an outbound push `remain_open` to wire seconds: rounded up
    /// to whole seconds (minimum 1 s, so a sub-second request cannot yield an
    /// instantly-expired subscription), capped at `max_sub_duration`.
    fn clamp_remain_open_secs(&self, remain_open: Duration) -> u64 {
        let mut secs = remain_open.as_secs();
        if remain_open.subsec_nanos() != 0 {
            secs = secs.saturating_add(1);
        }
        secs.clamp(1, self.max_sub_duration.as_secs().max(1))
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_push_subs: DEFAULT_MAX_SUBSCRIBERS,
            max_hello_subs: DEFAULT_MAX_SUBSCRIBERS,
            min_delay: DEFAULT_MIN_DELAY,
            max_sub_duration: DEFAULT_MAX_SUB_DURATION,
        }
    }
}

/// Method-chain builder for [`Limits`].
///
/// Every field defaults to its `DEFAULT_*` constant, so [`build`] is
/// infallible — override only what you need.
///
/// [`build`]: LimitsBuilder::build
#[derive(Copy, Clone, Debug)]
pub struct LimitsBuilder {
    limits: Limits,
}

impl LimitsBuilder {
    /// Max live push subscribers. Default [`DEFAULT_MAX_SUBSCRIBERS`].
    #[must_use]
    pub fn max_push_subs(mut self, n: usize) -> Self {
        self.limits.max_push_subs = n;
        self
    }

    /// Max live hello subscribers. Default [`DEFAULT_MAX_SUBSCRIBERS`].
    #[must_use]
    pub fn max_hello_subs(mut self, n: usize) -> Self {
        self.limits.max_hello_subs = n;
        self
    }

    /// Floor for every recurring or debounce delay (poll `interval`, hello
    /// `schedule_delay` / `graph_change_delay`, renewal periods). Values
    /// below it are clamped up.
    ///
    /// Itself floored at 1 ns by [`Syncer::with_limits`], so the
    /// drain-termination guarantee cannot be configured away. Default
    /// [`DEFAULT_MIN_DELAY`].
    #[must_use]
    pub fn min_delay(mut self, d: Duration) -> Self {
        self.limits.min_delay = d;
        self
    }

    /// Ceiling on subscription lifetimes (push `remain_open`, hello
    /// `duration`). Values above it are clamped down, bounding how long one
    /// subscriber can pin a slot. Default [`DEFAULT_MAX_SUB_DURATION`].
    #[must_use]
    pub fn max_sub_duration(mut self, d: Duration) -> Self {
        self.limits.max_sub_duration = d;
        self
    }

    /// Finishes building. Infallible — every field has a default.
    #[must_use]
    pub fn build(self) -> Limits {
        self.limits
    }
}

/// Work the caller should perform, returned by [`Syncer::poll_action`].
///
/// Every variant carries `graph_id`; [`graph_id`](Self::graph_id) returns it.
///
/// Deliberately exhaustive — no `#[non_exhaustive]`: adding a sync mechanism
/// should break integrators at compile time, because a wildcard arm that
/// silently dropped a new action would break sync invisibly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncAction<A> {
    /// Poll-sync with `peer`: [`SyncRequester::poll`], feed the reply to
    /// [`SyncRequester::receive`], and commit.
    ///
    /// [`SyncRequester::poll`]: super::SyncRequester::poll
    /// [`SyncRequester::receive`]: super::SyncRequester::receive
    Poll {
        /// The peer to poll.
        peer: A,
        /// The graph to sync.
        graph_id: GraphId,
    },
    /// Ask `peer` to push updates to us — emitted for the initial
    /// [`Syncer::subscribe`] and for each renewal: [`SyncRequester::subscribe`].
    /// Feed the peer's reply to [`Syncer::on_subscribe_response`].
    ///
    /// [`SyncRequester::subscribe`]: super::SyncRequester::subscribe
    Subscribe {
        /// The peer to subscribe to.
        peer: A,
        /// The graph to subscribe to.
        graph_id: GraphId,
        /// How long the peer should keep the subscription open. The wire
        /// takes whole seconds, so this carries them verbatim.
        remain_open_secs: u64,
        /// The maximum number of bytes the peer should push.
        max_bytes: u64,
    },
    /// Cancel our push subscription with `peer`:
    /// [`SyncRequester::unsubscribe`].
    ///
    /// [`SyncRequester::unsubscribe`]: super::SyncRequester::unsubscribe
    Unsubscribe {
        /// The peer to unsubscribe from.
        peer: A,
        /// The graph to unsubscribe from.
        graph_id: GraphId,
    },
    /// Push to our push-subscriber `peer`: [`SyncResponder::start_session`]
    /// and [`SyncResponder::push`], then [`Syncer::record_push`].
    ///
    /// [`SyncResponder::start_session`]: super::SyncResponder::start_session
    /// [`SyncResponder::push`]: super::SyncResponder::push
    Push {
        /// The subscriber to push to.
        peer: A,
        /// The graph to push.
        graph_id: GraphId,
    },
    /// Ask `peer` to send us hello notifications — initial request and
    /// renewals: [`HelloMessage::subscribe`]. (The protocol defines no reply
    /// to this.)
    ///
    /// [`HelloMessage::subscribe`]: super::HelloMessage::subscribe
    HelloSubscribe {
        /// The peer to subscribe to.
        peer: A,
        /// The graph to subscribe to.
        graph_id: GraphId,
        /// Requested debounce between change-triggered hellos.
        graph_change_delay: Duration,
        /// Requested subscription lifetime.
        duration: Duration,
        /// Requested cadence of scheduled hellos.
        schedule_delay: Duration,
    },
    /// Cancel hellos from `peer`: [`HelloMessage::unsubscribe`].
    ///
    /// [`HelloMessage::unsubscribe`]: super::HelloMessage::unsubscribe
    HelloUnsubscribe {
        /// The peer to unsubscribe from.
        peer: A,
        /// The graph to unsubscribe from.
        graph_id: GraphId,
    },
    /// Send our current head as a hello to hello-subscriber `peer`:
    /// [`HelloMessage::notification`] (the caller supplies the head from
    /// storage).
    ///
    /// [`HelloMessage::notification`]: super::HelloMessage::notification
    SendHello {
        /// The subscriber to notify.
        peer: A,
        /// The graph whose head to send.
        graph_id: GraphId,
    },
}

impl<A> SyncAction<A> {
    /// Returns the graph this action is for.
    pub fn graph_id(&self) -> GraphId {
        match self {
            Self::Poll { graph_id, .. }
            | Self::Subscribe { graph_id, .. }
            | Self::Unsubscribe { graph_id, .. }
            | Self::Push { graph_id, .. }
            | Self::HelloSubscribe { graph_id, .. }
            | Self::HelloUnsubscribe { graph_id, .. }
            | Self::SendHello { graph_id, .. } => *graph_id,
        }
    }
}

/// A subscribe or hello-subscribe was rejected because we are at the cap.
///
/// Map to [`SubscribeResponse::TooManySubscriptions`] where applicable.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("subscriber limit reached")]
pub struct SubscriberLimitReached;

/// Error from persisting or restoring a [`Syncer`] snapshot
/// ([`save_absolute`], [`save_relative`], [`load`]).
///
/// [`save_absolute`]: Syncer::save_absolute
/// [`save_relative`]: Syncer::save_relative
/// [`load`]: Syncer::load
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SnapshotError {
    /// rkyv failed to serialize the state.
    #[error("failed to encode syncer snapshot: {0}")]
    Encode(#[source] rkyv::rancor::Error),
    /// Bytes were truncated/corrupt or failed rkyv `CheckBytes` validation.
    #[error("failed to decode syncer snapshot: {0}")]
    Decode(#[source] rkyv::rancor::Error),
    /// The blob's leading version byte is not one this build reads. Expected
    /// after a software upgrade that changed the snapshot layout — treat as
    /// "start fresh", not as data loss.
    #[error("unsupported syncer snapshot version: {0}")]
    UnsupportedVersion(u8),
}

/// Composite map key. Graph-first ordering keeps a graph's entries adjacent.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PeerKey<A> {
    graph_id: GraphId,
    peer: A,
}

/// Poll schedule and `sync_on_hello` registration for one peer.
#[derive(Clone, Debug)]
struct PollSlot<T> {
    config: PeerConfig,
    next_sync: Option<T>,
}

/// A peer we push to (they subscribed to us).
#[derive(Clone, Debug)]
struct PushSub<T> {
    expires_at: T,
    remaining_bytes: u64,
}

impl<T: SyncInstant> PushSub<T> {
    fn is_live(&self, now: T) -> bool {
        self.expires_at > now && self.remaining_bytes > 0
    }
}

/// A peer we send hellos to (they subscribed to us).
#[derive(Clone, Debug)]
struct HelloSub<T> {
    graph_change_debounce: Duration,
    schedule_delay: Duration,
    /// The instant before which change-triggered hellos are suppressed.
    /// `None` = never notified, so the first local change always fires.
    next_change_allowed: Option<T>,
    expires_at: T,
    next_hello: T,
}

/// A push subscription we requested from a peer (renewed until unsubscribed).
#[derive(Clone, Debug)]
struct PushReq<T> {
    remain_open_secs: u64,
    max_bytes: u64,
    renew_at: T,
}

/// A hello subscription we requested from a peer (renewed until unsubscribed).
#[derive(Clone, Debug)]
struct HelloReq<T> {
    graph_change_delay: Duration,
    duration: Duration,
    schedule_delay: Duration,
    renew_at: T,
}

/// Which timer source the earliest-due scheduled item came from.
#[derive(Copy, Clone, Debug)]
enum DueKind {
    Poll,
    ScheduledHello,
    PushRenewal,
    HelloRenewal,
}

/// Renewal cadence for an outbound subscription: half its lifetime, floored
/// at `min_delay` so it stays timely without busy-looping.
fn renew_period(lifetime: Duration, min_delay: Duration) -> Duration {
    lifetime
        .checked_div(2)
        .unwrap_or(Duration::ZERO)
        .max(min_delay)
}

/// Enqueues `action` unless an equal action is already queued, so a burst of
/// events before a drain yields one action per subscriber and `pending` stays
/// bounded by live subscribers plus outstanding one-shot requests.
fn enqueue<A: PartialEq>(pending: &mut VecDeque<SyncAction<A>>, action: SyncAction<A>) {
    if !pending.contains(&action) {
        pending.push_back(action);
    }
}

/// A sans-I/O, transport- and clock-agnostic syncer state machine.
///
/// `Syncer` is the orchestration layer above the sync protocol primitives
/// ([`SyncRequester`], [`SyncResponder`], [`SyncIncoming`]): it decides *when
/// to sync with which peer* across all three sync mechanisms — poll, push,
/// and hello — for both the requester and responder roles, including the
/// requester-side subscription lifecycle (request, renew, tear down).
///
/// It performs no I/O and reads no clock. The caller feeds *events* (the
/// methods below) and the current *time*, drains [`SyncAction`]s describing
/// the I/O to perform — each action names the primitive call to make — and
/// sleeps until [`next_deadline`](Self::next_deadline). Time is a trait
/// boundary ([`SyncInstant`]) and the peer-address type `A` is generic, so
/// the machine works in `no_std` (with `alloc`). (It stores future deadlines,
/// which is why the instant type `T` is a struct-level parameter.)
///
/// Every duration a peer supplies is clamped into configurable [`Limits`]
/// before it can drive a timer, so a hostile or buggy peer cannot stall or
/// flood the machine. Answering an inbound poll is stateless and stays with
/// the caller (decode with [`SyncIncoming`], reply with [`SyncResponder`]).
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
/// syncer.add_peer(
///     "peer-a",
///     graph_id,
///     PeerConfig::periodic(Duration::from_secs(30)),
///     now,
/// );
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
pub struct Syncer<A, T> {
    /// Poll schedule and `sync_on_hello` registrations.
    peers: BTreeMap<PeerKey<A>, PollSlot<T>>,
    /// Peers we push to.
    push_subs: BTreeMap<PeerKey<A>, PushSub<T>>,
    /// Peers we send hellos to.
    hello_subs: BTreeMap<PeerKey<A>, HelloSub<T>>,
    /// Peers we asked to push to us.
    push_reqs: BTreeMap<PeerKey<A>, PushReq<T>>,
    /// Peers we asked to hello us.
    hello_reqs: BTreeMap<PeerKey<A>, HelloReq<T>>,
    /// Deduped one-shot actions awaiting a drain.
    pending: VecDeque<SyncAction<A>>,
    limits: Limits,
}

impl<A: Clone + Ord, T: SyncInstant> Default for Syncer<A, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Clone + Ord, T: SyncInstant> Syncer<A, T> {
    /// Creates a syncer with [`Limits::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    /// Creates a syncer with the given limits.
    ///
    /// `min_delay` is floored at 1 ns so the drain-termination guarantee
    /// cannot be configured away.
    #[must_use]
    pub fn with_limits(mut limits: Limits) -> Self {
        limits.min_delay = limits.min_delay.max(Duration::from_nanos(1));
        Self {
            peers: BTreeMap::new(),
            push_subs: BTreeMap::new(),
            hello_subs: BTreeMap::new(),
            push_reqs: BTreeMap::new(),
            hello_reqs: BTreeMap::new(),
            pending: VecDeque::new(),
            limits,
        }
    }

    /// Registers (or reconfigures) `peer` for poll scheduling.
    ///
    /// A recurring `interval` is floored at the configured `min_delay`. With
    /// [`sync_now`](PeerConfig::sync_now) the first poll is due immediately;
    /// otherwise one interval from `now` (if recurring).
    pub fn add_peer(&mut self, peer: A, graph_id: GraphId, cfg: PeerConfig, now: T) {
        let config = PeerConfig {
            interval: cfg.interval.map(|iv| self.limits.clamp_delay(iv)),
            ..cfg
        };
        let next_sync = if config.sync_now {
            Some(now)
        } else {
            config.interval.map(|iv| now.saturating_add(iv))
        };
        self.peers
            .insert(PeerKey { graph_id, peer }, PollSlot { config, next_sync });
    }

    /// Unregisters `peer` from poll scheduling. Returns whether it was
    /// registered.
    pub fn remove_peer(&mut self, peer: &A, graph_id: GraphId) -> bool {
        self.peers
            .remove(&PeerKey {
                graph_id,
                peer: peer.clone(),
            })
            .is_some()
    }

    /// Schedules an immediate poll of `peer`, keeping any recurring
    /// interval. Returns whether the peer is registered.
    pub fn sync_now(&mut self, peer: &A, graph_id: GraphId, now: T) -> bool {
        let key = PeerKey {
            graph_id,
            peer: peer.clone(),
        };
        match self.peers.get_mut(&key) {
            Some(slot) => {
                slot.next_sync = Some(now);
                true
            }
            None => false,
        }
    }

    /// Asks `peer` to push updates to us, and tracks the request so the
    /// emitted [`SyncAction::Subscribe`] is re-emitted at half the
    /// subscription's lifetime until [`unsubscribe`](Self::unsubscribe) — the
    /// subscription stays alive without caller involvement.
    ///
    /// `remain_open` is rounded up to whole wire seconds (minimum 1 s) and
    /// capped at `max_sub_duration`. Feed the peer's reply to
    /// [`on_subscribe_response`](Self::on_subscribe_response).
    pub fn subscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        remain_open: Duration,
        max_bytes: u64,
        now: T,
    ) {
        let remain_open_secs = self.limits.clamp_remain_open_secs(remain_open);
        let lifetime = Duration::from_secs(remain_open_secs);
        let renew_at = now.saturating_add(renew_period(lifetime, self.limits.min_delay));
        self.push_reqs.insert(
            PeerKey {
                graph_id,
                peer: peer.clone(),
            },
            PushReq {
                remain_open_secs,
                max_bytes,
                renew_at,
            },
        );
        enqueue(
            &mut self.pending,
            SyncAction::Subscribe {
                peer,
                graph_id,
                remain_open_secs,
                max_bytes,
            },
        );
    }

    /// Cancels our push subscription with `peer`: drops the tracked request
    /// (renewals stop) and emits a [`SyncAction::Unsubscribe`] — even if
    /// untracked, for idempotent teardown.
    pub fn unsubscribe(&mut self, peer: A, graph_id: GraphId) {
        self.push_reqs.remove(&PeerKey {
            graph_id,
            peer: peer.clone(),
        });
        enqueue(
            &mut self.pending,
            SyncAction::Unsubscribe { peer, graph_id },
        );
    }

    /// Feeds the peer's reply to our [`SyncAction::Subscribe`] back in.
    ///
    /// `Success` confirms (a no-op); `TooManySubscriptions` drops the tracked
    /// request so renewals stop — the caller decoded the reply itself, so it
    /// already knows; re-[`subscribe`](Self::subscribe) later to retry.
    pub fn on_subscribe_response(
        &mut self,
        peer: &A,
        graph_id: GraphId,
        response: SubscribeResponse,
    ) {
        match response {
            SubscribeResponse::Success => {}
            SubscribeResponse::TooManySubscriptions => {
                self.push_reqs.remove(&PeerKey {
                    graph_id,
                    peer: peer.clone(),
                });
            }
        }
    }

    /// Registers `peer` as a push subscriber, from a decoded
    /// [`SyncIncoming::Subscribe`](super::SyncIncoming::Subscribe).
    /// Re-subscribing replaces the existing entry.
    ///
    /// `remain_open` is capped at `max_sub_duration`; `max_bytes` is the push
    /// byte budget (a zero budget is already exhausted). Errors if a new
    /// entry would exceed `max_push_subs` — map to
    /// [`SubscribeResponse::TooManySubscriptions`].
    pub fn add_push_subscriber(
        &mut self,
        peer: A,
        graph_id: GraphId,
        remain_open: Duration,
        max_bytes: u64,
        now: T,
    ) -> Result<(), SubscriberLimitReached> {
        self.push_subs.retain(|_, sub| sub.is_live(now));
        let key = PeerKey { graph_id, peer };
        if !self.push_subs.contains_key(&key) && self.push_subs.len() >= self.limits.max_push_subs {
            return Err(SubscriberLimitReached);
        }
        let expires_at = now.saturating_add(self.limits.clamp_lifetime(remain_open));
        self.push_subs.insert(
            key,
            PushSub {
                expires_at,
                remaining_bytes: max_bytes,
            },
        );
        Ok(())
    }

    /// Removes `peer`'s push subscription, from a decoded
    /// [`SyncIncoming::Unsubscribe`](super::SyncIncoming::Unsubscribe).
    /// Returns whether one was present.
    pub fn remove_push_subscriber(&mut self, peer: &A, graph_id: GraphId) -> bool {
        self.push_subs
            .remove(&PeerKey {
                graph_id,
                peer: peer.clone(),
            })
            .is_some()
    }

    /// Records `bytes` pushed to subscriber `peer`, consuming its budget.
    /// The subscription is dropped when the budget reaches zero.
    pub fn record_push(&mut self, peer: &A, graph_id: GraphId, bytes: u64) {
        let key = PeerKey {
            graph_id,
            peer: peer.clone(),
        };
        if let Some(sub) = self.push_subs.get_mut(&key) {
            sub.remaining_bytes = sub.remaining_bytes.saturating_sub(bytes);
            if sub.remaining_bytes == 0 {
                self.push_subs.remove(&key);
            }
        }
    }

    /// Asks `peer` to send us hello notifications, and tracks the request so
    /// the emitted [`SyncAction::HelloSubscribe`] is re-emitted at half the
    /// subscription's lifetime until
    /// [`hello_unsubscribe`](Self::hello_unsubscribe). Renewal is blind — the
    /// protocol defines no reply to a hello subscribe.
    ///
    /// The delays are floored at `min_delay` and `duration` is capped at
    /// `max_sub_duration`: requesting within our own limits keeps the request
    /// inside what a same-configured peer would grant, so half-life renewal
    /// stays timely.
    pub fn hello_subscribe(
        &mut self,
        peer: A,
        graph_id: GraphId,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
        now: T,
    ) {
        let graph_change_delay = self.limits.clamp_delay(graph_change_delay);
        let schedule_delay = self.limits.clamp_delay(schedule_delay);
        let duration = self.limits.clamp_lifetime(duration);
        let renew_at = now.saturating_add(renew_period(duration, self.limits.min_delay));
        self.hello_reqs.insert(
            PeerKey {
                graph_id,
                peer: peer.clone(),
            },
            HelloReq {
                graph_change_delay,
                duration,
                schedule_delay,
                renew_at,
            },
        );
        enqueue(
            &mut self.pending,
            SyncAction::HelloSubscribe {
                peer,
                graph_id,
                graph_change_delay,
                duration,
                schedule_delay,
            },
        );
    }

    /// Cancels our hello subscription with `peer`: drops the tracked request
    /// (renewals stop) and emits a [`SyncAction::HelloUnsubscribe`] — even if
    /// untracked, for idempotent teardown.
    pub fn hello_unsubscribe(&mut self, peer: A, graph_id: GraphId) {
        self.hello_reqs.remove(&PeerKey {
            graph_id,
            peer: peer.clone(),
        });
        enqueue(
            &mut self.pending,
            SyncAction::HelloUnsubscribe { peer, graph_id },
        );
    }

    /// Handles a hello from `peer` for a head we lack: if the peer is
    /// registered with [`PeerConfig::sync_on_hello`], schedules an immediate
    /// poll. Returns whether one was scheduled.
    ///
    /// The caller does the "do I already have this head?" storage check
    /// before calling this.
    pub fn on_hello(&mut self, peer: &A, graph_id: GraphId, now: T) -> bool {
        let key = PeerKey {
            graph_id,
            peer: peer.clone(),
        };
        match self.peers.get_mut(&key) {
            Some(slot) if slot.config.sync_on_hello => {
                slot.next_sync = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Registers `peer` as a hello subscriber, from a decoded
    /// [`SyncHello::Subscribe`](super::SyncHello::Subscribe). Re-subscribing
    /// replaces the existing entry.
    ///
    /// `graph_change_delay` and `schedule_delay` are floored at `min_delay`
    /// and `duration` is capped at `max_sub_duration`. The first scheduled
    /// hello is due one `schedule_delay` from `now`; the first local change
    /// always notifies. Errors if a new entry would exceed `max_hello_subs`.
    pub fn add_hello_subscriber(
        &mut self,
        peer: A,
        graph_id: GraphId,
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
        now: T,
    ) -> Result<(), SubscriberLimitReached> {
        self.hello_subs.retain(|_, sub| sub.expires_at > now);
        let key = PeerKey { graph_id, peer };
        if !self.hello_subs.contains_key(&key)
            && self.hello_subs.len() >= self.limits.max_hello_subs
        {
            return Err(SubscriberLimitReached);
        }
        let schedule_delay = self.limits.clamp_delay(schedule_delay);
        self.hello_subs.insert(
            key,
            HelloSub {
                graph_change_debounce: self.limits.clamp_delay(graph_change_delay),
                schedule_delay,
                next_change_allowed: None,
                expires_at: now.saturating_add(self.limits.clamp_lifetime(duration)),
                next_hello: now.saturating_add(schedule_delay),
            },
        );
        Ok(())
    }

    /// Removes `peer`'s hello subscription, from a decoded
    /// [`SyncHello::Unsubscribe`](super::SyncHello::Unsubscribe). Returns
    /// whether one was present.
    pub fn remove_hello_subscriber(&mut self, peer: &A, graph_id: GraphId) -> bool {
        self.hello_subs
            .remove(&PeerKey {
                graph_id,
                peer: peer.clone(),
            })
            .is_some()
    }

    /// Reacts to a local change of `graph_id`: enqueues a [`SyncAction::Push`]
    /// to every live push subscriber of the graph and a
    /// [`SyncAction::SendHello`] to every hello subscriber past its debounce.
    ///
    /// Enqueues dedupe against already-queued actions, so a burst of calls
    /// before a drain yields one action per subscriber. Drain
    /// [`poll_action`](Self::poll_action) after feeding the event.
    pub fn notify_local_change(&mut self, graph_id: GraphId, now: T) {
        let Self {
            push_subs,
            hello_subs,
            pending,
            ..
        } = self;
        push_subs.retain(|key, sub| {
            if !sub.is_live(now) {
                return false;
            }
            if key.graph_id == graph_id {
                enqueue(
                    pending,
                    SyncAction::Push {
                        peer: key.peer.clone(),
                        graph_id,
                    },
                );
            }
            true
        });
        hello_subs.retain(|key, sub| {
            if sub.expires_at <= now {
                return false;
            }
            if key.graph_id == graph_id && sub.next_change_allowed.is_none_or(|at| at <= now) {
                enqueue(
                    pending,
                    SyncAction::SendHello {
                        peer: key.peer.clone(),
                        graph_id,
                    },
                );
                // Any sent hello resets both timers: the change-triggered
                // hello also satisfies the keepalive, so the next scheduled
                // hello waits a full period instead of re-sending the same
                // head moments later.
                sub.next_change_allowed = Some(now.saturating_add(sub.graph_change_debounce));
                sub.next_hello = now.saturating_add(sub.schedule_delay);
            }
            true
        });
    }

    /// Drops all state for `graph_id`: poll schedule, subscriptions in both
    /// directions, tracked outbound requests, and queued actions.
    pub fn remove_graph(&mut self, graph_id: GraphId) {
        self.peers.retain(|key, _| key.graph_id != graph_id);
        self.push_subs.retain(|key, _| key.graph_id != graph_id);
        self.hello_subs.retain(|key, _| key.graph_id != graph_id);
        self.push_reqs.retain(|key, _| key.graph_id != graph_id);
        self.hello_reqs.retain(|key, _| key.graph_id != graph_id);
        self.pending.retain(|action| action.graph_id() != graph_id);
    }

    /// Returns the next action the caller should perform, or `None` when
    /// nothing is due at `now`.
    ///
    /// Scheduled work (polls, scheduled hellos, subscription renewals) comes
    /// first, earliest-due item first; each is rescheduled *before* it is
    /// returned, so — with the enforced `min_delay` floor — an item fires at
    /// most once per drain and the drain terminates. Queued one-shots follow;
    /// a queued [`Push`](SyncAction::Push) or
    /// [`SendHello`](SyncAction::SendHello) whose subscription was removed,
    /// expired, or ran out of budget since it was enqueued is skipped.
    ///
    /// Drain until `None` after feeding events, then sleep until
    /// [`next_deadline`](Self::next_deadline).
    pub fn poll_action(&mut self, now: T) -> Option<SyncAction<A>> {
        if let Some(action) = self.poll_scheduled(now) {
            return Some(action);
        }
        self.poll_pending(now)
    }

    /// Finds the earliest-due scheduled item, reschedules it, and returns its
    /// action. An expired hello subscription is dropped silently (no farewell
    /// hello) when the scan reaches it, and the scan continues.
    fn poll_scheduled(&mut self, now: T) -> Option<SyncAction<A>> {
        loop {
            let mut due: Option<(T, DueKind, PeerKey<A>)> = None;
            {
                let mut consider = |at: T, kind: DueKind, key: &PeerKey<A>| {
                    if at <= now && due.as_ref().is_none_or(|&(best, ..)| at < best) {
                        due = Some((at, kind, key.clone()));
                    }
                };
                for (key, slot) in &self.peers {
                    if let Some(at) = slot.next_sync {
                        consider(at, DueKind::Poll, key);
                    }
                }
                for (key, sub) in &self.hello_subs {
                    consider(sub.next_hello, DueKind::ScheduledHello, key);
                }
                for (key, req) in &self.push_reqs {
                    consider(req.renew_at, DueKind::PushRenewal, key);
                }
                for (key, req) in &self.hello_reqs {
                    consider(req.renew_at, DueKind::HelloRenewal, key);
                }
            }
            let (_, kind, key) = due?;
            let min_delay = self.limits.min_delay;
            match kind {
                DueKind::Poll => {
                    let Some(slot) = self.peers.get_mut(&key) else {
                        continue;
                    };
                    slot.next_sync = slot.config.interval.map(|iv| now.saturating_add(iv));
                    return Some(SyncAction::Poll {
                        peer: key.peer,
                        graph_id: key.graph_id,
                    });
                }
                DueKind::ScheduledHello => {
                    let Some(sub) = self.hello_subs.get_mut(&key) else {
                        continue;
                    };
                    if sub.expires_at <= now {
                        self.hello_subs.remove(&key);
                        continue;
                    }
                    // The sent-hello reset (see `notify_local_change`).
                    sub.next_change_allowed = Some(now.saturating_add(sub.graph_change_debounce));
                    sub.next_hello = now.saturating_add(sub.schedule_delay);
                    return Some(SyncAction::SendHello {
                        peer: key.peer,
                        graph_id: key.graph_id,
                    });
                }
                DueKind::PushRenewal => {
                    let Some(req) = self.push_reqs.get_mut(&key) else {
                        continue;
                    };
                    let lifetime = Duration::from_secs(req.remain_open_secs);
                    req.renew_at = now.saturating_add(renew_period(lifetime, min_delay));
                    return Some(SyncAction::Subscribe {
                        peer: key.peer,
                        graph_id: key.graph_id,
                        remain_open_secs: req.remain_open_secs,
                        max_bytes: req.max_bytes,
                    });
                }
                DueKind::HelloRenewal => {
                    let Some(req) = self.hello_reqs.get_mut(&key) else {
                        continue;
                    };
                    req.renew_at = now.saturating_add(renew_period(req.duration, min_delay));
                    return Some(SyncAction::HelloSubscribe {
                        peer: key.peer,
                        graph_id: key.graph_id,
                        graph_change_delay: req.graph_change_delay,
                        duration: req.duration,
                        schedule_delay: req.schedule_delay,
                    });
                }
            }
        }
    }

    /// Pops queued one-shots, skipping (and pruning) a `Push`/`SendHello`
    /// whose subscription died between enqueue and drain.
    fn poll_pending(&mut self, now: T) -> Option<SyncAction<A>> {
        while let Some(action) = self.pending.pop_front() {
            match &action {
                SyncAction::Push { peer, graph_id } => {
                    let key = PeerKey {
                        graph_id: *graph_id,
                        peer: peer.clone(),
                    };
                    let live = self.push_subs.get(&key).is_some_and(|sub| sub.is_live(now));
                    if !live {
                        self.push_subs.remove(&key);
                        continue;
                    }
                }
                SyncAction::SendHello { peer, graph_id } => {
                    let key = PeerKey {
                        graph_id: *graph_id,
                        peer: peer.clone(),
                    };
                    let live = self
                        .hello_subs
                        .get(&key)
                        .is_some_and(|sub| sub.expires_at > now);
                    if !live {
                        self.hello_subs.remove(&key);
                        continue;
                    }
                }
                _ => {}
            }
            return Some(action);
        }
        None
    }

    /// Returns the earliest scheduled timer — the next poll, scheduled
    /// hello, or renewal — i.e. when [`poll_action`](Self::poll_action) next
    /// has work. Sleep until then (or until the next event).
    pub fn next_deadline(&self) -> Option<T> {
        let mut deadline: Option<T> = None;
        {
            let mut consider = |at: T| {
                if deadline.is_none_or(|best| at < best) {
                    deadline = Some(at);
                }
            };
            for slot in self.peers.values() {
                if let Some(at) = slot.next_sync {
                    consider(at);
                }
            }
            for sub in self.hello_subs.values() {
                consider(sub.next_hello);
            }
            for req in self.push_reqs.values() {
                consider(req.renew_at);
            }
            for req in self.hello_reqs.values() {
                consider(req.renew_at);
            }
        }
        deadline
    }

    /// Serializes durable state — schedules, subscriptions in both
    /// directions, tracked outbound requests, and limits — storing deadlines
    /// **as `T`**, and returns an opaque, versioned blob for
    /// [`load`](Self::load).
    ///
    /// Correct only when `T`'s epoch is stable across restarts (wall-clock /
    /// `SystemTime`-derived instants). **A monotonic `T` saved absolutely
    /// reloads as garbage deadlines after reboot, and `load` cannot detect
    /// that** — use [`save_relative`](Self::save_relative) for monotonic
    /// clocks.
    pub fn save_absolute(&self) -> Result<Vec<u8>, SnapshotError>
    where
        A: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RancorError>>,
        T: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RancorError>>,
    {
        encode(MODE_ABSOLUTE, &self.to_state(|at| at))
    }

    /// Serializes durable state like [`save_absolute`](Self::save_absolute),
    /// but stores each deadline as a [`Duration`] offset from `now`
    /// (already-due deadlines become zero). For process-monotonic clocks:
    /// [`load`](Self::load) re-anchors the offsets onto its own `now`.
    pub fn save_relative(&self, now: T) -> Result<Vec<u8>, SnapshotError>
    where
        A: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RancorError>>,
    {
        encode(
            MODE_RELATIVE,
            &self.to_state(|at| at.saturating_duration_since(now)),
        )
    }

    /// Reconstructs a syncer from a snapshot blob.
    ///
    /// The version and timer mode are read from the blob: absolute deadlines
    /// are used as stored (`now` is ignored), relative offsets re-anchor onto
    /// `now` (already-due timers fire immediately). The bytes are validated
    /// (rkyv `CheckBytes`); an unrecognized version is
    /// [`SnapshotError::UnsupportedVersion`], which callers should treat as
    /// "start fresh".
    ///
    /// Queued one-shot actions are not persisted: after a load the queue
    /// starts empty, scheduled work regenerates from the restored timers, and
    /// outbound subscriptions re-emit on their restored renewal schedule.
    pub fn load(bytes: &[u8], now: T) -> Result<Self, SnapshotError>
    where
        A: rkyv::Archive,
        A::Archived: for<'a> CheckBytes<HighValidator<'a, RancorError>>
            + rkyv::Deserialize<A, Strategy<Pool, RancorError>>,
        T: rkyv::Archive,
        T::Archived: for<'a> CheckBytes<HighValidator<'a, RancorError>>
            + rkyv::Deserialize<T, Strategy<Pool, RancorError>>,
    {
        let Some((&version, rest)) = bytes.split_first() else {
            return Err(truncated());
        };
        if version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }
        let Some((&mode, payload)) = rest.split_first() else {
            return Err(truncated());
        };
        // The payload sits at arbitrary alignment inside the blob and rkyv
        // validates alignment, so copy it into aligned storage first.
        let mut aligned = AlignedVec::<16>::new();
        aligned.extend_from_slice(payload);
        match mode {
            MODE_ABSOLUTE => {
                let state = rkyv::from_bytes::<State<A, T>, RancorError>(&aligned)
                    .map_err(SnapshotError::Decode)?;
                Ok(Self::from_state(state, |at| at))
            }
            MODE_RELATIVE => {
                let state = rkyv::from_bytes::<State<A, Duration>, RancorError>(&aligned)
                    .map_err(SnapshotError::Decode)?;
                Ok(Self::from_state(state, |offset| now.saturating_add(offset)))
            }
            unknown => Err(SnapshotError::Decode(RancorError::new(
                BlobFormatError::UnknownMode(unknown),
            ))),
        }
    }

    /// Flattens the durable state into entry vectors, converting each stored
    /// deadline with `conv`.
    fn to_state<Time>(&self, conv: impl Fn(T) -> Time) -> State<A, Time> {
        State {
            max_push_subs: u64::try_from(self.limits.max_push_subs).unwrap_or(u64::MAX),
            max_hello_subs: u64::try_from(self.limits.max_hello_subs).unwrap_or(u64::MAX),
            min_delay: self.limits.min_delay,
            max_sub_duration: self.limits.max_sub_duration,
            peers: self
                .peers
                .iter()
                .map(|(key, slot)| PeerEntry {
                    graph_id: key.graph_id,
                    peer: key.peer.clone(),
                    interval: slot.config.interval,
                    sync_now: slot.config.sync_now,
                    sync_on_hello: slot.config.sync_on_hello,
                    next_sync: slot.next_sync.map(&conv),
                })
                .collect(),
            push_subs: self
                .push_subs
                .iter()
                .map(|(key, sub)| PushSubEntry {
                    graph_id: key.graph_id,
                    peer: key.peer.clone(),
                    expires_at: conv(sub.expires_at),
                    remaining_bytes: sub.remaining_bytes,
                })
                .collect(),
            hello_subs: self
                .hello_subs
                .iter()
                .map(|(key, sub)| HelloSubEntry {
                    graph_id: key.graph_id,
                    peer: key.peer.clone(),
                    graph_change_debounce: sub.graph_change_debounce,
                    schedule_delay: sub.schedule_delay,
                    next_change_allowed: sub.next_change_allowed.map(&conv),
                    expires_at: conv(sub.expires_at),
                    next_hello: conv(sub.next_hello),
                })
                .collect(),
            push_reqs: self
                .push_reqs
                .iter()
                .map(|(key, req)| PushReqEntry {
                    graph_id: key.graph_id,
                    peer: key.peer.clone(),
                    remain_open_secs: req.remain_open_secs,
                    max_bytes: req.max_bytes,
                    renew_at: conv(req.renew_at),
                })
                .collect(),
            hello_reqs: self
                .hello_reqs
                .iter()
                .map(|(key, req)| HelloReqEntry {
                    graph_id: key.graph_id,
                    peer: key.peer.clone(),
                    graph_change_delay: req.graph_change_delay,
                    duration: req.duration,
                    schedule_delay: req.schedule_delay,
                    renew_at: conv(req.renew_at),
                })
                .collect(),
        }
    }

    /// Rebuilds a syncer from flattened state, converting each stored
    /// deadline with `conv`. Delays are re-clamped against the restored
    /// limits so the drain-termination invariant holds even for a blob this
    /// build did not write.
    fn from_state<Time: Copy>(state: State<A, Time>, conv: impl Fn(Time) -> T) -> Self {
        let mut syncer = Self::with_limits(Limits {
            max_push_subs: usize::try_from(state.max_push_subs).unwrap_or(usize::MAX),
            max_hello_subs: usize::try_from(state.max_hello_subs).unwrap_or(usize::MAX),
            min_delay: state.min_delay,
            max_sub_duration: state.max_sub_duration,
        });
        // `with_limits` floored `min_delay`; clamp with what it kept.
        let limits = syncer.limits;
        for entry in state.peers {
            syncer.peers.insert(
                PeerKey {
                    graph_id: entry.graph_id,
                    peer: entry.peer,
                },
                PollSlot {
                    config: PeerConfig {
                        interval: entry.interval.map(|iv| limits.clamp_delay(iv)),
                        sync_now: entry.sync_now,
                        sync_on_hello: entry.sync_on_hello,
                    },
                    next_sync: entry.next_sync.map(&conv),
                },
            );
        }
        for entry in state.push_subs {
            syncer.push_subs.insert(
                PeerKey {
                    graph_id: entry.graph_id,
                    peer: entry.peer,
                },
                PushSub {
                    expires_at: conv(entry.expires_at),
                    remaining_bytes: entry.remaining_bytes,
                },
            );
        }
        for entry in state.hello_subs {
            syncer.hello_subs.insert(
                PeerKey {
                    graph_id: entry.graph_id,
                    peer: entry.peer,
                },
                HelloSub {
                    graph_change_debounce: limits.clamp_delay(entry.graph_change_debounce),
                    schedule_delay: limits.clamp_delay(entry.schedule_delay),
                    next_change_allowed: entry.next_change_allowed.map(&conv),
                    expires_at: conv(entry.expires_at),
                    next_hello: conv(entry.next_hello),
                },
            );
        }
        for entry in state.push_reqs {
            syncer.push_reqs.insert(
                PeerKey {
                    graph_id: entry.graph_id,
                    peer: entry.peer,
                },
                PushReq {
                    remain_open_secs: entry.remain_open_secs.max(1),
                    max_bytes: entry.max_bytes,
                    renew_at: conv(entry.renew_at),
                },
            );
        }
        for entry in state.hello_reqs {
            syncer.hello_reqs.insert(
                PeerKey {
                    graph_id: entry.graph_id,
                    peer: entry.peer,
                },
                HelloReq {
                    graph_change_delay: limits.clamp_delay(entry.graph_change_delay),
                    duration: limits.clamp_lifetime(entry.duration),
                    schedule_delay: limits.clamp_delay(entry.schedule_delay),
                    renew_at: conv(entry.renew_at),
                },
            );
        }
        syncer
    }
}

/// Snapshot format version; the blob's first byte. Bump when the layout
/// below changes — rkyv archives are not self-describing.
const SNAPSHOT_VERSION: u8 = 1;

/// Timer mode; the blob's second byte. Deadlines stored as `T`.
const MODE_ABSOLUTE: u8 = 0;
/// Timer mode; the blob's second byte. Deadlines stored as offsets-from-save.
const MODE_RELATIVE: u8 = 1;

/// A snapshot blob defect detected before rkyv validation.
#[derive(Debug)]
enum BlobFormatError {
    /// Shorter than the version + mode header.
    Truncated,
    /// The mode byte is neither absolute nor relative.
    UnknownMode(u8),
}

impl fmt::Display for BlobFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "snapshot shorter than its header"),
            Self::UnknownMode(mode) => write!(f, "unknown snapshot timer mode: {mode}"),
        }
    }
}

impl core::error::Error for BlobFormatError {}

fn truncated() -> SnapshotError {
    SnapshotError::Decode(RancorError::new(BlobFormatError::Truncated))
}

/// Prepends the version and mode header to the rkyv-serialized `state`.
fn encode<S>(mode: u8, state: &S) -> Result<Vec<u8>, SnapshotError>
where
    S: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RancorError>>,
{
    let payload = rkyv::to_bytes::<RancorError>(state).map_err(SnapshotError::Encode)?;
    let mut blob = Vec::with_capacity(payload.len().saturating_add(2));
    blob.push(SNAPSHOT_VERSION);
    blob.push(mode);
    blob.extend_from_slice(&payload);
    Ok(blob)
}

/// Durable state flattened for rkyv, with deadlines of type `Time` (`T` in
/// an absolute snapshot, offset [`Duration`]s in a relative one). Maps are
/// stored as entry vectors and rebuilt on load, sidestepping archived-map
/// key-ordering constraints.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct State<A, Time> {
    max_push_subs: u64,
    max_hello_subs: u64,
    min_delay: Duration,
    max_sub_duration: Duration,
    peers: Vec<PeerEntry<A, Time>>,
    push_subs: Vec<PushSubEntry<A, Time>>,
    hello_subs: Vec<HelloSubEntry<A, Time>>,
    push_reqs: Vec<PushReqEntry<A, Time>>,
    hello_reqs: Vec<HelloReqEntry<A, Time>>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PeerEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    interval: Option<Duration>,
    sync_now: bool,
    sync_on_hello: bool,
    next_sync: Option<Time>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PushSubEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    expires_at: Time,
    remaining_bytes: u64,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct HelloSubEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    graph_change_debounce: Duration,
    schedule_delay: Duration,
    next_change_allowed: Option<Time>,
    expires_at: Time,
    next_hello: Time,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PushReqEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    remain_open_secs: u64,
    max_bytes: u64,
    renew_at: Time,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct HelloReqEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    graph_change_delay: Duration,
    duration: Duration,
    schedule_delay: Duration,
    renew_at: Time,
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestSyncer = Syncer<&'static str, Duration>;
    type PersistentSyncer = Syncer<String, Duration>;

    fn gid(n: u8) -> GraphId {
        GraphId::from_bytes([n; 32])
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn owned(peer: &str) -> String {
        String::from(peer)
    }

    /// Drains every due action, panicking if the drain does not terminate.
    fn drain<A: Clone + Ord + fmt::Debug>(
        syncer: &mut Syncer<A, Duration>,
        now: Duration,
    ) -> Vec<SyncAction<A>> {
        let mut actions = Vec::new();
        for _ in 0..64 {
            match syncer.poll_action(now) {
                Some(action) => actions.push(action),
                None => return actions,
            }
        }
        panic!("drain did not terminate: {actions:?}");
    }

    #[test]
    fn sync_now_fires_immediately_once() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_peer("a", g, PeerConfig::immediate(), secs(5));
        assert_eq!(
            drain(&mut s, secs(5)),
            [SyncAction::Poll {
                peer: "a",
                graph_id: g
            }],
        );
        assert_eq!(drain(&mut s, secs(100)), []);
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn periodic_peer_reschedules() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0));
        // Immediate first poll.
        assert_eq!(drain(&mut s, secs(0)).len(), 1);
        assert_eq!(s.next_deadline(), Some(secs(10)));
        // Nothing fires early.
        assert_eq!(drain(&mut s, secs(9)), []);
        // Due at the interval; reschedules from `now`.
        assert_eq!(
            drain(&mut s, secs(10)),
            [SyncAction::Poll {
                peer: "a",
                graph_id: g
            }],
        );
        assert_eq!(s.next_deadline(), Some(secs(20)));
    }

    #[test]
    fn interval_without_sync_now_waits_one_period() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        let cfg = PeerConfig {
            interval: Some(secs(10)),
            sync_now: false,
            sync_on_hello: false,
        };
        s.add_peer("a", g, cfg, secs(3));
        assert_eq!(drain(&mut s, secs(3)), []);
        assert_eq!(s.next_deadline(), Some(secs(13)));
    }

    #[test]
    fn sync_now_polls_registered_peer_and_keeps_interval() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0));
        drain(&mut s, secs(0));
        assert!(s.sync_now(&"a", g, secs(2)));
        assert_eq!(
            drain(&mut s, secs(2)),
            [SyncAction::Poll {
                peer: "a",
                graph_id: g
            }],
        );
        // The interval is kept: rescheduled from the manual poll.
        assert_eq!(s.next_deadline(), Some(secs(12)));
        // Unregistered peers are reported.
        assert!(!s.sync_now(&"b", g, secs(2)));
        assert!(!s.sync_now(&"a", gid(2), secs(2)));
    }

    #[test]
    fn remove_peer_cancels_schedule() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0));
        assert!(s.remove_peer(&"a", g));
        assert!(!s.remove_peer(&"a", g));
        assert_eq!(drain(&mut s, secs(0)), []);
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn zero_poll_interval_is_floored() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        let cfg = PeerConfig {
            interval: Some(Duration::ZERO),
            sync_now: false,
            sync_on_hello: false,
        };
        s.add_peer("a", g, cfg, secs(0));
        // Floored at the default `min_delay`.
        assert_eq!(s.next_deadline(), Some(DEFAULT_MIN_DELAY));
        // A due poll reschedules a full `min_delay` out, so a drain at a
        // fixed `now` terminates.
        assert_eq!(drain(&mut s, secs(1)).len(), 1);
        assert_eq!(s.next_deadline(), Some(secs(2)));
    }

    #[test]
    fn remote_hello_delays_are_floored_and_drain_terminates() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        // A hostile peer supplies zero delays; both are floored at `min_delay`.
        s.add_hello_subscriber("a", g, Duration::ZERO, secs(60), Duration::ZERO, secs(0))
            .unwrap();
        // The scheduled hello is due one floored `schedule_delay` out, and
        // rescheduling pushes it a full `min_delay` ahead: the drain
        // terminates instead of re-firing at `now` forever.
        assert_eq!(
            drain(&mut s, secs(1)),
            [SyncAction::SendHello {
                peer: "a",
                graph_id: g
            }],
        );
        assert_eq!(s.next_deadline(), Some(secs(2)));
        // The change debounce is floored too: a change right after the sent
        // hello is suppressed.
        s.notify_local_change(g, secs(1));
        assert_eq!(drain(&mut s, secs(1)), []);
    }

    #[test]
    fn oversized_lifetimes_are_capped() {
        let limits = Limits::builder().max_sub_duration(secs(100)).build();
        let mut s = TestSyncer::with_limits(limits);
        let g = gid(1);
        // Hello `duration` is capped at 100 s: the sub expires (and is
        // silently dropped) at t = 100 despite the far longer request.
        s.add_hello_subscriber("a", g, secs(1), secs(1_000_000), secs(40), secs(0))
            .unwrap();
        assert_eq!(drain(&mut s, secs(40)).len(), 1);
        assert_eq!(drain(&mut s, secs(80)).len(), 1);
        // The next scheduled hello (t = 120) is past expiry: dropped.
        assert_eq!(drain(&mut s, secs(120)), []);
        assert_eq!(s.next_deadline(), None);

        // Push `remain_open` is capped likewise: expired at t = 100.
        s.add_push_subscriber("a", g, secs(1_000_000), 1_000, secs(0))
            .unwrap();
        s.notify_local_change(g, secs(100));
        assert_eq!(drain(&mut s, secs(100)), []);
    }

    #[test]
    fn with_limits_floors_zero_min_delay() {
        let mut s = TestSyncer::with_limits(Limits::builder().min_delay(Duration::ZERO).build());
        let g = gid(1);
        s.add_hello_subscriber("a", g, Duration::ZERO, secs(60), Duration::ZERO, secs(0))
            .unwrap();
        // Even with `min_delay` configured to zero, the 1 ns floor keeps a
        // due hello from rescheduling to `now` forever.
        assert_eq!(drain(&mut s, secs(1)).len(), 1);
        assert_eq!(s.next_deadline(), Some(Duration::new(1, 1)));
    }

    #[test]
    fn subsecond_remain_open_rounds_up_to_one_second() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.subscribe("a", g, Duration::from_millis(300), 1_000, secs(0));
        assert_eq!(
            drain(&mut s, secs(0)),
            [SyncAction::Subscribe {
                peer: "a",
                graph_id: g,
                remain_open_secs: 1,
                max_bytes: 1_000
            }],
        );
    }

    #[test]
    fn fractional_remain_open_rounds_up() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.subscribe("a", g, Duration::from_millis(4_200), 1_000, secs(0));
        match drain(&mut s, secs(0)).as_slice() {
            [
                SyncAction::Subscribe {
                    remain_open_secs: 5,
                    ..
                },
            ] => {}
            other => panic!("unexpected actions: {other:?}"),
        }
    }

    #[test]
    fn push_subscriber_cap_and_replace() {
        let limits = Limits::builder().max_push_subs(2).build();
        let mut s = TestSyncer::with_limits(limits);
        let g = gid(1);
        s.add_push_subscriber("a", g, secs(60), 1_000, secs(0))
            .unwrap();
        s.add_push_subscriber("b", g, secs(60), 1_000, secs(0))
            .unwrap();
        // A new key at the cap is rejected...
        assert_eq!(
            s.add_push_subscriber("c", g, secs(60), 1_000, secs(0)),
            Err(SubscriberLimitReached),
        );
        // ...but re-subscribing an existing key replaces in place.
        s.add_push_subscriber("b", g, secs(90), 2_000, secs(0))
            .unwrap();
        // Expired entries are pruned before the cap check: at t = 70 "a"
        // (expiry t = 60) no longer holds a slot.
        s.add_push_subscriber("c", g, secs(60), 1_000, secs(70))
            .unwrap();
        s.notify_local_change(g, secs(70));
        let actions = drain(&mut s, secs(70));
        assert_eq!(actions.len(), 2);
        assert!(actions.contains(&SyncAction::Push {
            peer: "b",
            graph_id: g
        }));
        assert!(actions.contains(&SyncAction::Push {
            peer: "c",
            graph_id: g
        }));
    }

    #[test]
    fn push_budget_exhaustion_drops_subscriber() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_push_subscriber("a", g, secs(60), 100, secs(0))
            .unwrap();
        s.record_push(&"a", g, 60);
        s.notify_local_change(g, secs(1));
        assert_eq!(
            drain(&mut s, secs(1)),
            [SyncAction::Push {
                peer: "a",
                graph_id: g
            }],
        );
        // Over-consumption saturates; the subscription drops at zero.
        s.record_push(&"a", g, 400);
        s.notify_local_change(g, secs(2));
        assert_eq!(drain(&mut s, secs(2)), []);
    }

    #[test]
    fn zero_byte_budget_is_already_exhausted() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_push_subscriber("a", g, secs(60), 0, secs(0)).unwrap();
        s.notify_local_change(g, secs(1));
        assert_eq!(drain(&mut s, secs(1)), []);
    }

    #[test]
    fn notify_targets_only_the_changed_graph() {
        let mut s = TestSyncer::new();
        s.add_push_subscriber("a", gid(1), secs(60), 1_000, secs(0))
            .unwrap();
        s.add_push_subscriber("a", gid(2), secs(60), 1_000, secs(0))
            .unwrap();
        s.notify_local_change(gid(1), secs(1));
        assert_eq!(
            drain(&mut s, secs(1)),
            [SyncAction::Push {
                peer: "a",
                graph_id: gid(1)
            }],
        );
    }

    #[test]
    fn drain_skips_actions_whose_subscription_was_removed() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_push_subscriber("a", g, secs(60), 1_000, secs(0))
            .unwrap();
        s.add_hello_subscriber("b", g, secs(1), secs(60), secs(30), secs(0))
            .unwrap();
        s.notify_local_change(g, secs(1));
        // Both subscriptions die between enqueue and drain.
        s.remove_push_subscriber(&"a", g);
        s.remove_hello_subscriber(&"b", g);
        assert_eq!(drain(&mut s, secs(1)), []);
    }

    #[test]
    fn drain_skips_push_expired_since_enqueue() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_push_subscriber("a", g, secs(10), 1_000, secs(0))
            .unwrap();
        // Queued while live, drained only after expiry.
        s.notify_local_change(g, secs(9));
        assert_eq!(drain(&mut s, secs(20)), []);
    }

    #[test]
    fn hello_subscriber_cap_and_replace() {
        let limits = Limits::builder().max_hello_subs(1).build();
        let mut s = TestSyncer::with_limits(limits);
        let g = gid(1);
        s.add_hello_subscriber("a", g, secs(1), secs(60), secs(30), secs(0))
            .unwrap();
        assert_eq!(
            s.add_hello_subscriber("b", g, secs(1), secs(60), secs(30), secs(0)),
            Err(SubscriberLimitReached),
        );
        // Replacing the existing key is allowed at the cap.
        s.add_hello_subscriber("a", g, secs(2), secs(90), secs(45), secs(0))
            .unwrap();
        // Expired entries are pruned before the cap check.
        s.add_hello_subscriber("b", g, secs(1), secs(60), secs(30), secs(100))
            .unwrap();
    }

    #[test]
    fn scheduled_hellos_fire_on_cadence_until_expiry() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_hello_subscriber("a", g, secs(1), secs(70), secs(30), secs(0))
            .unwrap();
        assert_eq!(drain(&mut s, secs(29)), []);
        assert_eq!(
            drain(&mut s, secs(30)),
            [SyncAction::SendHello {
                peer: "a",
                graph_id: g
            }],
        );
        assert_eq!(
            drain(&mut s, secs(60)),
            [SyncAction::SendHello {
                peer: "a",
                graph_id: g
            }],
        );
        // The next scheduled hello (t = 90) lands past expiry (t = 70):
        // dropped silently, no farewell hello.
        assert_eq!(drain(&mut s, secs(90)), []);
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn change_triggered_hello_respects_debounce() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_hello_subscriber("a", g, secs(10), secs(100), secs(60), secs(0))
            .unwrap();
        // The first change always fires.
        s.notify_local_change(g, secs(1));
        assert_eq!(drain(&mut s, secs(1)).len(), 1);
        // Inside the debounce window: suppressed.
        s.notify_local_change(g, secs(5));
        assert_eq!(drain(&mut s, secs(5)), []);
        // Window over (1 + 10 = 11): fires again.
        s.notify_local_change(g, secs(11));
        assert_eq!(drain(&mut s, secs(11)).len(), 1);
    }

    #[test]
    fn sent_hello_resets_the_scheduled_cadence() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_hello_subscriber("a", g, secs(1), secs(1_000), secs(60), secs(0))
            .unwrap();
        // A change-triggered hello at t = 50...
        s.notify_local_change(g, secs(50));
        assert_eq!(drain(&mut s, secs(50)).len(), 1);
        // ...also satisfies the keepalive: the scheduled hello moves a full
        // period out (t = 110) instead of re-sending the same head at t = 60.
        assert_eq!(s.next_deadline(), Some(secs(110)));
        assert_eq!(drain(&mut s, secs(60)), []);
        assert_eq!(drain(&mut s, secs(110)).len(), 1);
    }

    #[test]
    fn expired_hello_sub_drops_silently_and_scan_continues() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        // `schedule_delay >= duration`: the only scheduled hello lands past
        // expiry.
        s.add_hello_subscriber("a", g, secs(1), secs(50), secs(60), secs(0))
            .unwrap();
        // A second, live subscriber whose hello is due *later* than the dead
        // one's timer: the scan must continue past the drop to reach it.
        s.add_hello_subscriber("b", g, secs(1), secs(1_000), secs(70), secs(0))
            .unwrap();
        assert_eq!(
            drain(&mut s, secs(70)),
            [SyncAction::SendHello {
                peer: "b",
                graph_id: g
            }],
        );
        // "a" is gone: no timer left besides "b"'s next hello.
        assert_eq!(s.next_deadline(), Some(secs(140)));
    }

    #[test]
    fn change_triggered_hellos_work_up_to_expiry() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        // No keepalive fits before expiry (schedule 60 >= duration 50), but
        // change-triggered hellos keep working for the whole lifetime.
        s.add_hello_subscriber("a", g, secs(1), secs(50), secs(60), secs(0))
            .unwrap();
        s.notify_local_change(g, secs(45));
        assert_eq!(drain(&mut s, secs(45)).len(), 1);
        // At expiry the subscription is gone.
        s.notify_local_change(g, secs(50));
        assert_eq!(drain(&mut s, secs(50)), []);
    }

    #[test]
    fn subscribe_renews_at_half_life_with_stored_params() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.subscribe("a", g, secs(100), 5_000, secs(0));
        let expected = || SyncAction::Subscribe {
            peer: "a",
            graph_id: g,
            remain_open_secs: 100,
            max_bytes: 5_000,
        };
        assert_eq!(drain(&mut s, secs(0)), [expected()]);
        // The renewal is due at half the lifetime.
        assert_eq!(s.next_deadline(), Some(secs(50)));
        assert_eq!(drain(&mut s, secs(50)), [expected()]);
        // And again, rescheduled from the renewal.
        assert_eq!(s.next_deadline(), Some(secs(100)));
        assert_eq!(drain(&mut s, secs(100)), [expected()]);
    }

    #[test]
    fn too_many_subscriptions_stops_renewals() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.subscribe("a", g, secs(100), 5_000, secs(0));
        drain(&mut s, secs(0));
        s.on_subscribe_response(&"a", g, SubscribeResponse::TooManySubscriptions);
        assert_eq!(drain(&mut s, secs(500)), []);
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn success_response_keeps_renewals() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.subscribe("a", g, secs(100), 5_000, secs(0));
        drain(&mut s, secs(0));
        s.on_subscribe_response(&"a", g, SubscribeResponse::Success);
        assert_eq!(drain(&mut s, secs(50)).len(), 1);
    }

    #[test]
    fn unsubscribe_stops_renewals_and_emits() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.subscribe("a", g, secs(100), 5_000, secs(0));
        drain(&mut s, secs(0));
        s.unsubscribe("a", g);
        assert_eq!(
            drain(&mut s, secs(0)),
            [SyncAction::Unsubscribe {
                peer: "a",
                graph_id: g
            }],
        );
        assert_eq!(drain(&mut s, secs(500)), []);
        // Idempotent teardown: emitted even when untracked.
        s.unsubscribe("a", g);
        assert_eq!(
            drain(&mut s, secs(500)),
            [SyncAction::Unsubscribe {
                peer: "a",
                graph_id: g
            }],
        );
    }

    #[test]
    fn hello_subscribe_renews_blindly() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.hello_subscribe("a", g, secs(5), secs(200), secs(30), secs(0));
        let expected = || SyncAction::HelloSubscribe {
            peer: "a",
            graph_id: g,
            graph_change_delay: secs(5),
            duration: secs(200),
            schedule_delay: secs(30),
        };
        assert_eq!(drain(&mut s, secs(0)), [expected()]);
        // No reply is ever fed in; the renewal still fires at half-life.
        assert_eq!(drain(&mut s, secs(100)), [expected()]);
        assert_eq!(s.next_deadline(), Some(secs(200)));
        // Until told to stop.
        s.hello_unsubscribe("a", g);
        assert_eq!(
            drain(&mut s, secs(500)),
            [SyncAction::HelloUnsubscribe {
                peer: "a",
                graph_id: g
            }],
        );
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn hello_subscribe_params_are_clamped() {
        let mut s = TestSyncer::with_limits(Limits::builder().max_sub_duration(secs(100)).build());
        let g = gid(1);
        s.hello_subscribe("a", g, Duration::ZERO, secs(1_000), Duration::ZERO, secs(0));
        match drain(&mut s, secs(0)).as_slice() {
            [
                SyncAction::HelloSubscribe {
                    graph_change_delay,
                    duration,
                    schedule_delay,
                    ..
                },
            ] => {
                assert_eq!(*graph_change_delay, DEFAULT_MIN_DELAY);
                assert_eq!(*duration, secs(100));
                assert_eq!(*schedule_delay, DEFAULT_MIN_DELAY);
            }
            other => panic!("unexpected actions: {other:?}"),
        }
    }

    #[test]
    fn on_hello_polls_only_with_sync_on_hello() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        let armed = PeerConfig {
            interval: None,
            sync_now: false,
            sync_on_hello: true,
        };
        let unarmed = PeerConfig {
            interval: None,
            sync_now: false,
            sync_on_hello: false,
        };
        s.add_peer("a", g, armed, secs(0));
        s.add_peer("b", g, unarmed, secs(0));
        assert!(s.on_hello(&"a", g, secs(5)));
        assert!(!s.on_hello(&"b", g, secs(5)));
        assert!(!s.on_hello(&"unknown", g, secs(5)));
        assert_eq!(
            drain(&mut s, secs(5)),
            [SyncAction::Poll {
                peer: "a",
                graph_id: g
            }],
        );
    }

    #[test]
    fn burst_of_changes_dedupes_to_one_action_per_subscriber() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        s.add_push_subscriber("a", g, secs(60), 1_000, secs(0))
            .unwrap();
        s.add_hello_subscriber("b", g, secs(1), secs(60), secs(30), secs(0))
            .unwrap();
        s.notify_local_change(g, secs(1));
        s.notify_local_change(g, secs(1));
        s.notify_local_change(g, secs(1));
        let actions = drain(&mut s, secs(1));
        assert_eq!(actions.len(), 2);
        assert!(actions.contains(&SyncAction::Push {
            peer: "a",
            graph_id: g
        }));
        assert!(actions.contains(&SyncAction::SendHello {
            peer: "b",
            graph_id: g
        }));
    }

    #[test]
    fn earliest_due_ordering_across_sources() {
        let mut s = TestSyncer::new();
        let g = gid(1);
        // Scheduled hello due at t = 30.
        s.add_hello_subscriber("h", g, secs(1), secs(500), secs(30), secs(0))
            .unwrap();
        // Push renewal due at t = 40 (half of 80 s).
        s.subscribe("p", g, secs(80), 1_000, secs(0));
        // Poll due at t = 50.
        let cfg = PeerConfig {
            interval: Some(secs(50)),
            sync_now: false,
            sync_on_hello: false,
        };
        s.add_peer("q", g, cfg, secs(0));
        // The initial Subscribe one-shot drains first; nothing scheduled is
        // due yet.
        assert_eq!(drain(&mut s, secs(0)).len(), 1);
        assert_eq!(s.next_deadline(), Some(secs(30)));
        // At t = 50 all three are due: earliest-due first.
        assert_eq!(
            drain(&mut s, secs(50)),
            [
                SyncAction::SendHello {
                    peer: "h",
                    graph_id: g
                },
                SyncAction::Subscribe {
                    peer: "p",
                    graph_id: g,
                    remain_open_secs: 80,
                    max_bytes: 1_000
                },
                SyncAction::Poll {
                    peer: "q",
                    graph_id: g
                },
            ],
        );
    }

    #[test]
    fn remove_graph_clears_all_state() {
        let mut s = TestSyncer::new();
        let (g1, g2) = (gid(1), gid(2));
        for g in [g1, g2] {
            s.add_peer("peer", g, PeerConfig::periodic(secs(10)), secs(0));
            s.add_push_subscriber("sub", g, secs(60), 1_000, secs(0))
                .unwrap();
            s.add_hello_subscriber("sub", g, secs(1), secs(60), secs(30), secs(0))
                .unwrap();
            s.subscribe("req", g, secs(100), 1_000, secs(0));
            s.hello_subscribe("req", g, secs(1), secs(100), secs(10), secs(0));
            s.notify_local_change(g, secs(0));
        }
        s.remove_graph(g1);
        // Everything left belongs to g2.
        let actions = drain(&mut s, secs(5));
        assert!(!actions.is_empty());
        assert!(actions.iter().all(|action| action.graph_id() == g2));
        assert!(!s.remove_peer(&"peer", g1));
        assert!(!s.remove_push_subscriber(&"sub", g1));
        assert!(!s.remove_hello_subscriber(&"sub", g1));
    }

    /// Milliseconds since an arbitrary origin, as a caller-supplied instant.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Tick(u64);

    impl SyncInstant for Tick {
        fn saturating_add(self, d: Duration) -> Self {
            let millis = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
            Self(self.0.saturating_add(millis))
        }

        fn saturating_duration_since(self, earlier: Self) -> Duration {
            Duration::from_millis(self.0.saturating_sub(earlier.0))
        }
    }

    #[test]
    fn drives_a_custom_instant_type() {
        let mut s: Syncer<&'static str, Tick> = Syncer::new();
        let g = gid(1);
        s.add_peer("a", g, PeerConfig::periodic(secs(10)), Tick(500));
        assert_eq!(
            s.poll_action(Tick(500)),
            Some(SyncAction::Poll {
                peer: "a",
                graph_id: g
            }),
        );
        assert_eq!(s.poll_action(Tick(500)), None);
        assert_eq!(s.next_deadline(), Some(Tick(10_500)));
        assert_eq!(s.poll_action(Tick(10_499)), None);
        assert!(s.poll_action(Tick(10_500)).is_some());
    }

    #[test]
    fn instant_arithmetic_saturates_at_bounds() {
        // The provided `Duration` impl clamps instead of wrapping/panicking.
        assert_eq!(
            SyncInstant::saturating_add(Duration::MAX, secs(1)),
            Duration::MAX,
        );
        assert_eq!(
            SyncInstant::saturating_duration_since(secs(1), secs(5)),
            Duration::ZERO,
        );
        // So does a custom instant near its bounds.
        assert_eq!(Tick(u64::MAX).saturating_add(secs(1)), Tick(u64::MAX));
        assert_eq!(
            Tick(u64::MAX.saturating_sub(1)).saturating_add(Duration::MAX),
            Tick(u64::MAX),
        );
        assert_eq!(Tick(0).saturating_duration_since(Tick(5)), Duration::ZERO);
    }

    #[test]
    fn absolute_snapshot_round_trips() {
        let mut s = PersistentSyncer::new();
        let g = gid(1);
        s.add_peer(owned("a"), g, PeerConfig::periodic(secs(30)), secs(10));
        s.subscribe(owned("b"), g, secs(100), 5_000, secs(10));
        s.hello_subscribe(owned("c"), g, secs(5), secs(200), secs(20), secs(10));
        s.add_push_subscriber(owned("d"), g, secs(300), 9_000, secs(10))
            .unwrap();
        s.add_hello_subscriber(owned("e"), g, secs(5), secs(300), secs(25), secs(10))
            .unwrap();
        // Clear the one-shots (Poll + Subscribe + HelloSubscribe).
        assert_eq!(drain(&mut s, secs(10)).len(), 3);

        let blob = s.save_absolute().unwrap();
        assert_eq!(blob[0], SNAPSHOT_VERSION);
        // `now` is ignored for an absolute blob.
        let mut restored = PersistentSyncer::load(&blob, secs(9_999)).unwrap();
        // Deadlines are preserved exactly; the earliest is the hello sub's
        // first scheduled hello (t = 35).
        assert_eq!(restored.next_deadline(), s.next_deadline());
        assert_eq!(restored.next_deadline(), Some(secs(35)));
        // Restored subscriber state drives: a local change pushes to "d" and
        // hellos "e".
        restored.notify_local_change(g, secs(36));
        assert_eq!(
            drain(&mut restored, secs(36)),
            [
                SyncAction::Push {
                    peer: owned("d"),
                    graph_id: g
                },
                SyncAction::SendHello {
                    peer: owned("e"),
                    graph_id: g
                },
            ],
        );
    }

    #[test]
    fn relative_snapshot_reanchors_offsets() {
        let mut s = PersistentSyncer::new();
        let g = gid(1);
        let cfg = PeerConfig {
            interval: Some(secs(30)),
            sync_now: false,
            sync_on_hello: false,
        };
        s.add_peer(owned("a"), g, cfg, secs(0));
        s.subscribe(owned("b"), g, secs(100), 5_000, secs(0));
        drain(&mut s, secs(0));
        // Saved at t = 20, the poll (t = 30) and renewal (t = 50) become
        // offsets of 10 and 30; loading at t' = 1000 reproduces the spacing.
        let blob = s.save_relative(secs(20)).unwrap();
        let mut restored = PersistentSyncer::load(&blob, secs(1_000)).unwrap();
        assert_eq!(restored.next_deadline(), Some(secs(1_010)));
        assert_eq!(
            drain(&mut restored, secs(1_010)),
            [SyncAction::Poll {
                peer: owned("a"),
                graph_id: g
            }],
        );
        assert_eq!(
            drain(&mut restored, secs(1_030)),
            [SyncAction::Subscribe {
                peer: owned("b"),
                graph_id: g,
                remain_open_secs: 100,
                max_bytes: 5_000
            }],
        );
    }

    #[test]
    fn relative_snapshot_fires_already_due_timers_immediately() {
        let mut s = PersistentSyncer::new();
        let g = gid(1);
        // Due at t = 5, saved at t = 50: the offset saturates to zero.
        s.add_peer(owned("a"), g, PeerConfig::immediate(), secs(5));
        let blob = s.save_relative(secs(50)).unwrap();
        let mut restored = PersistentSyncer::load(&blob, secs(1_000)).unwrap();
        assert_eq!(
            drain(&mut restored, secs(1_000)),
            [SyncAction::Poll {
                peer: owned("a"),
                graph_id: g
            }],
        );
    }

    #[test]
    fn debounce_window_survives_relative_snapshot() {
        let mut s = PersistentSyncer::new();
        let g = gid(1);
        s.add_hello_subscriber(owned("a"), g, secs(10), secs(600), secs(300), secs(0))
            .unwrap();
        // Fires at t = 0; the debounce window runs to t = 10.
        s.notify_local_change(g, secs(0));
        drain(&mut s, secs(0));
        // Two seconds into the window, snapshot; restore at t' = 100.
        let blob = s.save_relative(secs(2)).unwrap();
        let mut restored = PersistentSyncer::load(&blob, secs(100)).unwrap();
        // Eight seconds of the window remain: still suppressed at t' + 7...
        restored.notify_local_change(g, secs(107));
        assert_eq!(drain(&mut restored, secs(107)), []);
        // ...open again at t' + 8.
        restored.notify_local_change(g, secs(108));
        assert_eq!(
            drain(&mut restored, secs(108)),
            [SyncAction::SendHello {
                peer: owned("a"),
                graph_id: g
            }],
        );
    }

    #[test]
    fn outbound_requests_survive_both_modes_and_renew() {
        let mut s = PersistentSyncer::new();
        let g = gid(1);
        s.subscribe(owned("a"), g, secs(100), 5_000, secs(0));
        s.hello_subscribe(owned("b"), g, secs(5), secs(200), secs(20), secs(0));
        drain(&mut s, secs(0));
        let push_renewal = || SyncAction::Subscribe {
            peer: owned("a"),
            graph_id: g,
            remain_open_secs: 100,
            max_bytes: 5_000,
        };
        let hello_renewal = || SyncAction::HelloSubscribe {
            peer: owned("b"),
            graph_id: g,
            graph_change_delay: secs(5),
            duration: secs(200),
            schedule_delay: secs(20),
        };

        let absolute = PersistentSyncer::load(&s.save_absolute().unwrap(), secs(0)).unwrap();
        let relative = PersistentSyncer::load(&s.save_relative(secs(0)).unwrap(), secs(0)).unwrap();
        for mut restored in [absolute, relative] {
            // The push renewal (t = 50) fires, rescheduling itself to t = 100
            // where the hello renewal is also due.
            assert_eq!(drain(&mut restored, secs(50)), [push_renewal()]);
            assert_eq!(
                drain(&mut restored, secs(100)),
                [push_renewal(), hello_renewal()],
            );
        }
    }

    #[test]
    fn pending_actions_are_not_persisted() {
        let mut s = PersistentSyncer::new();
        let g = gid(1);
        s.add_push_subscriber(owned("a"), g, secs(600), 5_000, secs(0))
            .unwrap();
        // Queued but never drained.
        s.notify_local_change(g, secs(0));
        let blob = s.save_absolute().unwrap();
        let mut restored = PersistentSyncer::load(&blob, secs(0)).unwrap();
        assert_eq!(drain(&mut restored, secs(0)), []);
        // The subscription itself survived; the next change pushes again.
        restored.notify_local_change(g, secs(1));
        assert_eq!(drain(&mut restored, secs(1)).len(), 1);
    }

    #[test]
    fn save_relative_works_without_rkyv_instant_bounds() {
        // `Tick` has no rkyv impls: absolute saves would have to persist
        // `Tick`s and don't compile, but relative saves only store offsets.
        let mut s: Syncer<String, Tick> = Syncer::new();
        let g = gid(1);
        s.add_peer(owned("a"), g, PeerConfig::periodic(secs(30)), Tick(0));
        let blob = s.save_relative(Tick(10)).unwrap();
        // A relative blob is instant-agnostic: any rkyv-capable clock can
        // re-anchor it (the poll was already due, so it is due at load).
        let restored: Syncer<String, Duration> = Syncer::load(&blob, Duration::ZERO).unwrap();
        assert_eq!(restored.next_deadline(), Some(Duration::ZERO));
    }

    #[test]
    fn unknown_snapshot_version_is_rejected_without_decoding() {
        let mut s = PersistentSyncer::new();
        s.add_peer(owned("a"), gid(1), PeerConfig::immediate(), secs(0));
        let mut blob = s.save_absolute().unwrap();
        blob[0] = 99;
        match PersistentSyncer::load(&blob, secs(0)) {
            Err(SnapshotError::UnsupportedVersion(99)) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn corrupt_snapshots_fail_cleanly() {
        // Too short for the header.
        assert!(matches!(
            PersistentSyncer::load(&[], secs(0)),
            Err(SnapshotError::Decode(_)),
        ));
        assert!(matches!(
            PersistentSyncer::load(&[SNAPSHOT_VERSION], secs(0)),
            Err(SnapshotError::Decode(_)),
        ));
        // An unknown timer mode.
        assert!(matches!(
            PersistentSyncer::load(&[SNAPSHOT_VERSION, 9], secs(0)),
            Err(SnapshotError::Decode(_)),
        ));
        // A truncated payload fails validation rather than panicking.
        let mut s = PersistentSyncer::new();
        s.add_peer(owned("a"), gid(1), PeerConfig::immediate(), secs(0));
        s.subscribe(owned("b"), gid(1), secs(100), 5_000, secs(0));
        let blob = s.save_absolute().unwrap();
        let truncated = &blob[..blob.len().saturating_sub(5)];
        assert!(matches!(
            PersistentSyncer::load(truncated, secs(0)),
            Err(SnapshotError::Decode(_)),
        ));
        // Garbage likewise.
        let mut garbage = vec![SNAPSHOT_VERSION, MODE_ABSOLUTE];
        garbage.extend_from_slice(&[0xAB; 64]);
        assert!(matches!(
            PersistentSyncer::load(&garbage, secs(0)),
            Err(SnapshotError::Decode(_)),
        ));
    }
}
