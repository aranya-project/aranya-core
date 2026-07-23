//! A sans-I/O syncer state machine.
//!
//! [`Syncer`] (see its docs for the model) owns the *stateful* parts of the
//! three sync mechanisms — poll schedules, subscriber tables in both
//! directions, outbound-subscription renewal, debounce/expiry/budget, remote
//! input clamping — and emits a [`SyncAction`] for every outbound message,
//! leaving I/O, clocks, storage, and crypto to the caller.
//!
//! Like time ([`SyncInstant`]), memory is a trait boundary: all per-peer
//! state lives in caller-supplied [`SyncSlots`], so the machine itself
//! allocates nothing. [`FixedSlots`] holds a fixed number of slots inline for
//! callers without a heap; [`HeapSlots`] grows on demand and is the default
//! where `alloc` is available.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData, time::Duration};

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

mod tests;

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
/// The subscriber caps are a *policy* bound on how much of the caller's
/// [`SyncSlots`] remote peers can occupy; the slots themselves bound total
/// state physically.
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
    /// Itself floored at 1 ns by [`Syncer::with_limits_in`], so the
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

/// A subscribe or hello-subscribe was rejected because we are at the cap or
/// out of [`SyncSlots`].
///
/// Map to [`SubscribeResponse::TooManySubscriptions`] where applicable.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("subscriber limit reached")]
pub struct SubscriberLimitReached;

/// The caller-supplied [`SyncSlots`] have no room for another peer-graph
/// pair.
///
/// Free a slot (`remove_*`, [`Syncer::remove_graph`]) or supply larger
/// storage. Never returned through [`HeapSlots`], which grows on demand.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("out of syncer slots")]
pub struct OutOfSlots;

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
    /// The snapshot holds more peer-graph pairs than the provided
    /// [`SyncSlots`] can hold.
    #[error("snapshot does not fit in the provided syncer slots")]
    OutOfSlots,
}

/// Poll schedule and `sync_on_hello` registration for one peer.
#[derive(Clone, Debug)]
struct PollState<T> {
    config: PeerConfig,
    next_sync: Option<T>,
}

/// A peer we push to (they subscribed to us).
#[derive(Clone, Debug)]
struct PushSub<T> {
    expires_at: T,
    remaining_bytes: u64,
    /// A local change queued a push at this instant; emitted (and cleared) by
    /// the next drain. Transient — not persisted.
    push_due: Option<T>,
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

/// A push subscription we requested from a peer.
#[derive(Clone, Debug)]
enum PushReq<T> {
    /// Renewed until unsubscribed.
    Active {
        remain_open_secs: u64,
        max_bytes: u64,
        renew_at: T,
    },
    /// Torn down: emit one [`SyncAction::Unsubscribe`] at `due`, then drop
    /// the record. Transient — not persisted.
    Cancel { due: T },
}

/// A hello subscription we requested from a peer.
#[derive(Clone, Debug)]
enum HelloReq<T> {
    /// Renewed until unsubscribed.
    Active {
        graph_change_delay: Duration,
        duration: Duration,
        schedule_delay: Duration,
        renew_at: T,
    },
    /// Torn down: emit one [`SyncAction::HelloUnsubscribe`] at `due`, then
    /// drop the record. Transient — not persisted.
    Cancel { due: T },
}

/// One peer-graph pair's sync state: an entry in the caller-supplied
/// [`SyncSlots`].
///
/// A slot bundles every role the pair can hold at once — polled peer, push
/// subscriber, hello subscriber, and our outbound push/hello subscription
/// requests to it — so a pair occupies one slot no matter how many roles are
/// active. The contents are private; [`SyncSlots`] implementations only
/// construct empty slots ([`new`](Self::new)) and order or look them up by
/// [`graph_id`](Self::graph_id) and [`peer`](Self::peer).
#[derive(Clone, Debug)]
pub struct SyncSlot<A, T> {
    graph_id: GraphId,
    peer: A,
    poll: Option<PollState<T>>,
    push_sub: Option<PushSub<T>>,
    hello_sub: Option<HelloSub<T>>,
    push_req: Option<PushReq<T>>,
    hello_req: Option<HelloReq<T>>,
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

    /// Visits every armed timer on this slot as an `(instant, kind)` pair.
    /// The fixed role order — poll, queued push, scheduled hello, then
    /// outbound push/hello requests — breaks exact ties for callers that
    /// keep the first-seen earliest instant.
    fn for_each_deadline(&self, mut consider: impl FnMut(T, DueKind))
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

/// Backing memory for a [`Syncer`]'s per-peer state, supplied by the caller.
///
/// Like time ([`SyncInstant`]), memory is a trait boundary: the syncer holds
/// one [`SyncSlot`] per peer-graph pair in whatever storage the caller
/// provides and never allocates itself. Use [`FixedSlots`] to place a fixed
/// number of slots inline (`no_std`, no heap), [`HeapSlots`] to grow on
/// demand, or implement this trait for your own storage.
///
/// # Contract
///
/// - Slots are keyed by the `(graph_id, peer)` pair; at most one slot per
///   pair.
/// - [`for_each`](Self::for_each) and [`retain`](Self::retain) visit every
///   slot in a **stable, deterministic order** (the provided implementations
///   iterate graph-first, then by peer). Equal deadlines fire in visit
///   order, so an unstable order yields an unstable action order.
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

/// [`SyncSlots`] with capacity for `N` peer-graph pairs, stored inline —
/// no allocation, for `no_std` callers without a heap.
///
/// The caller supplies the memory by placing the value (and the [`Syncer`]
/// around it) wherever it wants — a `static`, the stack, or a heap box.
/// Kept sorted graph-first, then by peer.
///
/// Size `N` for the distinct `(graph_id, peer)` pairs in play at once: a
/// pair occupies one slot however many roles (poll, push, hello, either
/// direction) it holds. When full, slot-creating calls fail ([`OutOfSlots`],
/// or [`SubscriberLimitReached`] for the remote-driven subscriber adds).
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
/// storage, never [`OutOfSlots`].
///
/// Kept sorted graph-first, then by peer. Remote peers cannot grow it
/// unboundedly: the subscriber tables are capped by [`Limits`], and every
/// other slot is created by a local call.
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

/// Which timer the earliest-due scheduled item came from.
#[derive(Copy, Clone, Debug)]
enum DueKind {
    Poll,
    Push,
    ScheduledHello,
    PushRenewal,
    PushCancel,
    HelloRenewal,
    HelloCancel,
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
/// ([`SyncRequester`], [`SyncResponder`], [`SyncIncoming`]): it decides *when
/// to sync with which peer* across all three sync mechanisms — poll, push,
/// and hello — for both the requester and responder roles, including the
/// requester-side subscription lifecycle (request, renew, tear down).
///
/// It performs no I/O, reads no clock, and allocates no memory. The caller
/// feeds *events* (the methods below) and the current *time*, drains
/// [`SyncAction`]s describing the I/O to perform — each action names the
/// primitive call to make — and sleeps until
/// [`next_deadline`](Self::next_deadline). Time is a trait boundary
/// ([`SyncInstant`]), the peer-address type `A` is generic, and the backing
/// memory is caller-supplied [`SyncSlots`] (`S`): with [`FixedSlots`] the
/// machine runs in `no_std` without a heap, and methods that need a new slot
/// report [`OutOfSlots`] when the storage is full. [`HeapSlots`], the
/// default `S`, grows on demand. (The machine stores future deadlines, which
/// is why the instant type `T` is a struct-level parameter.)
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
/// // `Syncer::new` uses `HeapSlots`; pass `FixedSlots` (or your own
/// // `SyncSlots`) to `Syncer::new_in` to supply the memory yourself.
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

    /// Reconstructs a syncer from a snapshot blob into fresh [`HeapSlots`];
    /// see [`load_in`](Self::load_in).
    pub fn load(bytes: &[u8], now: T) -> Result<Self, SnapshotError>
    where
        A: rkyv::Archive,
        A::Archived: for<'a> CheckBytes<HighValidator<'a, RancorError>>
            + rkyv::Deserialize<A, Strategy<Pool, RancorError>>,
        T: rkyv::Archive,
        T::Archived: for<'a> CheckBytes<HighValidator<'a, RancorError>>
            + rkyv::Deserialize<T, Strategy<Pool, RancorError>>,
    {
        Self::load_in(bytes, now, HeapSlots::new())
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
    /// A recurring `interval` is floored at the configured `min_delay`. With
    /// [`sync_now`](PeerConfig::sync_now) the first poll is due immediately;
    /// otherwise one interval from `now` (if recurring). Errors when a new
    /// slot is needed and the storage is full.
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
    /// subscription's lifetime until [`unsubscribe`](Self::unsubscribe) — the
    /// subscription stays alive without caller involvement.
    ///
    /// `remain_open` is rounded up to whole wire seconds (minimum 1 s) and
    /// capped at `max_sub_duration`. The initial [`SyncAction::Subscribe`] is
    /// due immediately — drain [`poll_action`](Self::poll_action). Feed the
    /// peer's reply to [`on_subscribe_response`](Self::on_subscribe_response).
    /// Errors when a new slot is needed and the storage is full.
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
    /// for idempotent teardown (which is when a free slot may be needed, and
    /// the storage being full is an error).
    pub fn unsubscribe(&mut self, peer: A, graph_id: GraphId, now: T) -> Result<(), OutOfSlots> {
        let slot = self.slots.get_or_insert(graph_id, &peer)?;
        slot.push_req = Some(PushReq::Cancel { due: now });
        Ok(())
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
    /// `remain_open` is capped at `max_sub_duration`; `max_bytes` is the push
    /// byte budget (a zero budget is already exhausted). Errors if a new
    /// entry would exceed `max_push_subs` or the slots are full — map to
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
    /// [`hello_unsubscribe`](Self::hello_unsubscribe). Renewal is blind — the
    /// protocol defines no reply to a hello subscribe.
    ///
    /// The delays are floored at `min_delay` and `duration` is capped at
    /// `max_sub_duration`: requesting within our own limits keeps the request
    /// inside what a same-configured peer would grant, so half-life renewal
    /// stays timely. The initial [`SyncAction::HelloSubscribe`] is due
    /// immediately — drain [`poll_action`](Self::poll_action). Errors when a
    /// new slot is needed and the storage is full.
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
    /// needed, and the storage being full is an error).
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
    /// poll. Returns whether one was scheduled.
    ///
    /// The caller does the "do I already have this head?" storage check
    /// before calling this.
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
    /// `graph_change_delay` and `schedule_delay` are floored at `min_delay`
    /// and `duration` is capped at `max_sub_duration`. The first scheduled
    /// hello is due one `schedule_delay` from `now`; the first local change
    /// always notifies. Errors if a new entry would exceed `max_hello_subs`
    /// or the slots are full.
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
    /// every live push subscriber of the graph and a [`SyncAction::SendHello`]
    /// to every hello subscriber past its debounce become due immediately.
    ///
    /// Re-notifying before a drain is idempotent — one action per subscriber,
    /// however many changes accumulated. Drain
    /// [`poll_action`](Self::poll_action) after feeding the event.
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
    /// nothing is due at `now`.
    ///
    /// The earliest-due timer fires first — recurring work (polls, scheduled
    /// hellos, subscription renewals) and one-shots (pushes and hellos queued
    /// by [`notify_local_change`](Self::notify_local_change), initial
    /// subscribes, teardowns) share one schedule, one-shots being due at the
    /// instant of the event that queued them. Exact ties fire in the slot
    /// table's order. Each item is rescheduled (or cleared) *before* it is
    /// returned, so — with the enforced `min_delay` floor — an item fires at
    /// most once per drain and the drain terminates. A `Push` or `SendHello`
    /// whose subscription expired, ran out of budget, or was removed since it
    /// was queued is dropped silently, as is an expired hello subscription
    /// when its timer comes due (no farewell hello).
    ///
    /// Drain until `None` after feeding events, then sleep until
    /// [`next_deadline`](Self::next_deadline).
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

    /// Fires one due item: reschedules or clears its timer, then returns
    /// the action to perform. Returns `None` when the item went stale
    /// between scan and firing (its slot or role is gone, or the
    /// subscription expired) — in every such case the timer is also gone,
    /// so a rescan cannot select it again.
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
                    // Any sent hello resets both timers: it also
                    // satisfies the keepalive, so the next scheduled
                    // hello waits a full period instead of re-sending
                    // the same head moments later.
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

    /// Returns the earliest timer — the next poll, scheduled hello, renewal,
    /// or already-due one-shot — i.e. when [`poll_action`](Self::poll_action)
    /// next has work. Sleep until then (or until the next event).
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

    /// Serializes durable state — schedules, subscriptions in both
    /// directions, tracked outbound requests, and limits — storing deadlines
    /// **as `T`**, and returns an opaque, versioned blob for
    /// [`load`](Self::load). (Persistence is the one part of the machine
    /// that allocates: the blob is built in memory.)
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

    /// Reconstructs a syncer from a snapshot blob, storing its state in the
    /// caller-supplied `slots` (any existing contents are cleared).
    ///
    /// The version and timer mode are read from the blob: absolute deadlines
    /// are used as stored (`now` is ignored), relative offsets re-anchor onto
    /// `now` (already-due timers fire immediately). The bytes are validated
    /// (rkyv `CheckBytes`); an unrecognized version is
    /// [`SnapshotError::UnsupportedVersion`], which callers should treat as
    /// "start fresh", and a snapshot with more peer-graph pairs than `slots`
    /// can hold is [`SnapshotError::OutOfSlots`].
    ///
    /// Due-but-undrained one-shots are not persisted: after a load, scheduled
    /// work regenerates from the restored timers and outbound subscriptions
    /// re-emit on their restored renewal schedule.
    pub fn load_in(bytes: &[u8], now: T, slots: S) -> Result<Self, SnapshotError>
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
                Self::from_state(state, |at| at, slots)
            }
            MODE_RELATIVE => {
                let state = rkyv::from_bytes::<State<A, Duration>, RancorError>(&aligned)
                    .map_err(SnapshotError::Decode)?;
                Self::from_state(state, |offset| now.saturating_add(offset), slots)
            }
            unknown => Err(SnapshotError::Decode(RancorError::new(
                BlobFormatError::UnknownMode(unknown),
            ))),
        }
    }

    /// Flattens the durable state into entry vectors, converting each stored
    /// deadline with `conv`. Transient one-shots (queued pushes, pulled-
    /// forward hellos, cancels) are not stored, matching how queued actions
    /// have never been persisted.
    fn to_state<Time>(&self, conv: impl Fn(T) -> Time) -> State<A, Time>
    where
        A: Clone,
    {
        let mut state = State {
            max_push_subs: u64::try_from(self.limits.max_push_subs).unwrap_or(u64::MAX),
            max_hello_subs: u64::try_from(self.limits.max_hello_subs).unwrap_or(u64::MAX),
            min_delay: self.limits.min_delay,
            max_sub_duration: self.limits.max_sub_duration,
            peers: Vec::new(),
            push_subs: Vec::new(),
            hello_subs: Vec::new(),
            push_reqs: Vec::new(),
            hello_reqs: Vec::new(),
        };
        self.slots.for_each(|slot| {
            let graph_id = slot.graph_id();
            if let Some(poll) = &slot.poll {
                state.peers.push(PeerEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    interval: poll.config.interval,
                    sync_now: poll.config.sync_now,
                    sync_on_hello: poll.config.sync_on_hello,
                    next_sync: poll.next_sync.map(&conv),
                });
            }
            if let Some(sub) = &slot.push_sub {
                state.push_subs.push(PushSubEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    expires_at: conv(sub.expires_at),
                    remaining_bytes: sub.remaining_bytes,
                });
            }
            if let Some(sub) = &slot.hello_sub {
                state.hello_subs.push(HelloSubEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    graph_change_debounce: sub.graph_change_debounce,
                    schedule_delay: sub.schedule_delay,
                    next_change_allowed: sub.next_change_allowed.map(&conv),
                    expires_at: conv(sub.expires_at),
                    next_hello: conv(sub.next_hello),
                });
            }
            if let Some(PushReq::Active {
                remain_open_secs,
                max_bytes,
                renew_at,
            }) = &slot.push_req
            {
                state.push_reqs.push(PushReqEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    remain_open_secs: *remain_open_secs,
                    max_bytes: *max_bytes,
                    renew_at: conv(*renew_at),
                });
            }
            if let Some(HelloReq::Active {
                graph_change_delay,
                duration,
                schedule_delay,
                renew_at,
            }) = &slot.hello_req
            {
                state.hello_reqs.push(HelloReqEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    graph_change_delay: *graph_change_delay,
                    duration: *duration,
                    schedule_delay: *schedule_delay,
                    renew_at: conv(*renew_at),
                });
            }
        });
        state
    }

    /// Rebuilds a syncer from flattened state into `slots`, converting each
    /// stored deadline with `conv`. Delays are re-clamped against the
    /// restored limits so the drain-termination invariant holds even for a
    /// blob this build did not write.
    fn from_state<Time: Copy>(
        state: State<A, Time>,
        conv: impl Fn(Time) -> T,
        slots: S,
    ) -> Result<Self, SnapshotError> {
        let mut syncer = Self::with_limits_in(
            Limits {
                max_push_subs: usize::try_from(state.max_push_subs).unwrap_or(usize::MAX),
                max_hello_subs: usize::try_from(state.max_hello_subs).unwrap_or(usize::MAX),
                min_delay: state.min_delay,
                max_sub_duration: state.max_sub_duration,
            },
            slots,
        );
        syncer.slots.retain(|_| false);
        // `with_limits_in` floored `min_delay`; clamp with what it kept.
        let limits = syncer.limits;
        for entry in state.peers {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.poll = Some(PollState {
                config: PeerConfig {
                    interval: entry.interval.map(|iv| limits.clamp_delay(iv)),
                    sync_now: entry.sync_now,
                    sync_on_hello: entry.sync_on_hello,
                },
                next_sync: entry.next_sync.map(&conv),
            });
        }
        for entry in state.push_subs {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.push_sub = Some(PushSub {
                expires_at: conv(entry.expires_at),
                remaining_bytes: entry.remaining_bytes,
                push_due: None,
            });
        }
        for entry in state.hello_subs {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.hello_sub = Some(HelloSub {
                graph_change_debounce: limits.clamp_delay(entry.graph_change_debounce),
                schedule_delay: limits.clamp_delay(entry.schedule_delay),
                next_change_allowed: entry.next_change_allowed.map(&conv),
                expires_at: conv(entry.expires_at),
                next_hello: conv(entry.next_hello),
            });
        }
        for entry in state.push_reqs {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.push_req = Some(PushReq::Active {
                remain_open_secs: entry.remain_open_secs.max(1),
                max_bytes: entry.max_bytes,
                renew_at: conv(entry.renew_at),
            });
        }
        for entry in state.hello_reqs {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.hello_req = Some(HelloReq::Active {
                graph_change_delay: limits.clamp_delay(entry.graph_change_delay),
                duration: limits.clamp_lifetime(entry.duration),
                schedule_delay: limits.clamp_delay(entry.schedule_delay),
                renew_at: conv(entry.renew_at),
            });
        }
        Ok(syncer)
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
/// an absolute snapshot, offset [`Duration`]s in a relative one). The slot
/// table is stored as per-role entry vectors and rebuilt on load,
/// sidestepping archived-map key-ordering constraints.
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
