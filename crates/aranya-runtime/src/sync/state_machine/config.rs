//! Poll configuration and subscription limits.

use core::time::Duration;

/// How a scheduled peer should be polled.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerConfig {
    /// Recurring poll interval, floored at [`LimitsBuilder::min_delay`].
    /// `None` = do not poll on a schedule.
    pub interval: Option<Duration>,
    /// Poll immediately on registration.
    pub sync_now: bool,
    /// When a hello for a head we lack arrives from this peer, poll it.
    /// Only consulted for peers registered via [`add_peer`];
    /// [`hello_subscribe`] alone does not arm hello-triggered polling.
    ///
    /// [`add_peer`]: super::Syncer::add_peer
    /// [`hello_subscribe`]: super::Syncer::hello_subscribe
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
/// Every duration a peer supplies is clamped before it can drive a timer, so
/// remote input cannot stall or flood the machine: recurring and debounce
/// delays are floored at [`min_delay`](LimitsBuilder::min_delay),
/// subscription lifetimes capped at
/// [`max_sub_duration`](LimitsBuilder::max_sub_duration). Values are clamped
/// rather than rejected because the hello protocol has no negative reply.
/// The subscriber caps bound how many [`SyncSlots`](super::SyncSlots) remote
/// peers can occupy.
///
/// Build with [`Limits::builder`]; [`Default`] is the all-defaults value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub(super) max_push_subs: usize,
    pub(super) max_hello_subs: usize,
    pub(super) min_delay: Duration,
    pub(super) max_sub_duration: Duration,
}

impl Limits {
    /// Starts a [`LimitsBuilder`] seeded with the `DEFAULT_*` values.
    pub fn builder() -> LimitsBuilder {
        LimitsBuilder {
            limits: Self::default(),
        }
    }

    /// Floors a recurring or debounce delay at `min_delay`.
    pub(super) fn clamp_delay(&self, d: Duration) -> Duration {
        d.max(self.min_delay)
    }

    /// Caps a subscription lifetime at `max_sub_duration`.
    pub(super) fn clamp_lifetime(&self, d: Duration) -> Duration {
        d.min(self.max_sub_duration)
    }

    /// Normalizes an outbound push `remain_open` to whole wire seconds:
    /// rounded up (minimum 1 s, so a sub-second request cannot yield an
    /// instantly-expired subscription), capped at `max_sub_duration`.
    pub(super) fn clamp_remain_open_secs(&self, remain_open: Duration) -> u64 {
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

/// Method-chain builder for [`Limits`]. Every field defaults to its
/// `DEFAULT_*` constant, so [`build`](Self::build) is infallible.
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

    /// Floor for every recurring or debounce delay. Itself floored at 1 ns
    /// by [`Syncer::with_limits_in`](super::Syncer::with_limits_in), so the
    /// drain-termination guarantee cannot be configured away. Default
    /// [`DEFAULT_MIN_DELAY`].
    #[must_use]
    pub fn min_delay(mut self, d: Duration) -> Self {
        self.limits.min_delay = d;
        self
    }

    /// Ceiling on subscription lifetimes (push `remain_open`, hello
    /// `duration`), bounding how long one subscriber can pin a slot. Default
    /// [`DEFAULT_MAX_SUB_DURATION`].
    #[must_use]
    pub fn max_sub_duration(mut self, d: Duration) -> Self {
        self.limits.max_sub_duration = d;
        self
    }

    /// Finishes building.
    #[must_use]
    pub fn build(self) -> Limits {
        self.limits
    }
}
