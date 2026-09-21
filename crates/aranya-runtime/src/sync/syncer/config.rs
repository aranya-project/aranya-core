//! Poll, push, and hello configuration, and the syncer's limits.

use core::time::Duration;

/// How and when to poll a peer.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerConfig {
    /// Recurring poll interval, floored at [`LimitsBuilder::min_delay`].
    /// `None`: do not poll on a schedule.
    pub interval: Option<Duration>,
    /// Poll once as soon as registered.
    pub sync_now: bool,
    /// Poll when this peer announces a head we lack.
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

/// Parameters of a push subscription we request from a peer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PushConfig {
    /// Lease length. Rounded up to whole wire seconds (minimum 1 s) and
    /// capped at [`LimitsBuilder::max_sub_duration`]; renewed at half-life.
    pub remain_open: Duration,
    /// Byte budget the peer may push to us over the lease.
    pub max_bytes: u64,
}

/// Parameters of a hello subscription we request from a peer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HelloConfig {
    /// Debounce between change-triggered hellos.
    pub graph_change_delay: Duration,
    /// Lease length; renewed at half-life.
    pub duration: Duration,
    /// Cadence of keepalive hellos sent regardless of changes.
    pub schedule_delay: Duration,
}

pub(crate) const DEFAULT_MAX_SUBSCRIBERS: usize = 64;
pub(crate) const DEFAULT_MIN_DELAY: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_MAX_SUB_DURATION: Duration = Duration::from_secs(365 * 24 * 60 * 60);
pub(crate) const DEFAULT_REPLY_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
pub(crate) const DEFAULT_MAX_ONE_SHOT_RETRIES: u8 = 3;

/// Caps and clamps on syncer state.
///
/// Every duration a remote peer supplies is clamped before it can drive a
/// timer, so remote input cannot stall or flood the machine. Clamped rather
/// than rejected because the hello protocol has no negative reply. The
/// subscriber caps bound how many slots remote peers can occupy.
///
/// Build with [`Limits::builder`]; [`Default`] is the all-defaults value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub(crate) max_push_subs: usize,
    pub(crate) max_hello_subs: usize,
    pub(crate) min_delay: Duration,
    pub(crate) max_sub_duration: Duration,
    pub(crate) reply_timeout: Duration,
    pub(crate) initial_backoff: Option<Duration>,
    pub(crate) max_backoff: Duration,
    pub(crate) max_one_shot_retries: u8,
}

impl Limits {
    /// Starts a [`LimitsBuilder`] seeded with the defaults.
    pub fn builder() -> LimitsBuilder {
        LimitsBuilder {
            limits: Self::default(),
        }
    }

    /// Floors `min_delay` at 1 ns so drain termination cannot be configured
    /// away, and keeps the other delays consistent with it.
    pub(crate) fn normalized(mut self) -> Self {
        self.min_delay = self.min_delay.max(Duration::from_nanos(1));
        self.max_backoff = self.max_backoff.max(self.min_delay);
        self.reply_timeout = self.reply_timeout.max(self.min_delay);
        self
    }

    /// Floors a recurring or debounce delay at `min_delay`.
    pub(crate) fn clamp_delay(&self, d: Duration) -> Duration {
        d.max(self.min_delay)
    }

    /// Caps a subscription lifetime at `max_sub_duration`.
    pub(crate) fn clamp_lifetime(&self, d: Duration) -> Duration {
        d.min(self.max_sub_duration)
    }

    /// Normalizes an outbound push `remain_open` to whole wire seconds:
    /// rounded up (minimum 1 s), capped at `max_sub_duration`.
    pub(crate) fn clamp_remain_open_secs(&self, remain_open: Duration) -> u64 {
        let mut secs = remain_open.as_secs();
        if remain_open.subsec_nanos() != 0 {
            secs = secs.saturating_add(1);
        }
        secs.clamp(1, self.max_sub_duration.as_secs().max(1))
    }

    /// Delay before the next poll attempt after `failures` consecutive
    /// failures (`failures >= 1`): exponential from `initial_backoff`,
    /// capped at `max_backoff` and at the peer's own `interval`.
    pub(crate) fn backoff(&self, failures: u8, interval: Option<Duration>) -> Duration {
        let base = self
            .initial_backoff
            .unwrap_or(self.min_delay)
            .max(self.min_delay);
        let shift = u32::from(failures.saturating_sub(1)).min(16);
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        let mut d = base.checked_mul(factor).unwrap_or(self.max_backoff);
        d = d.min(self.max_backoff);
        if let Some(iv) = interval {
            d = d.min(iv);
        }
        d.max(self.min_delay)
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_push_subs: DEFAULT_MAX_SUBSCRIBERS,
            max_hello_subs: DEFAULT_MAX_SUBSCRIBERS,
            min_delay: DEFAULT_MIN_DELAY,
            max_sub_duration: DEFAULT_MAX_SUB_DURATION,
            reply_timeout: DEFAULT_REPLY_TIMEOUT,
            initial_backoff: None,
            max_backoff: DEFAULT_MAX_BACKOFF,
            max_one_shot_retries: DEFAULT_MAX_ONE_SHOT_RETRIES,
        }
    }
}

/// Method-chain builder for [`Limits`]. Every field has a default, so
/// [`build`](Self::build) is infallible.
#[derive(Copy, Clone, Debug)]
pub struct LimitsBuilder {
    limits: Limits,
}

impl LimitsBuilder {
    /// Max live inbound push subscribers across all graphs. Default 64.
    #[must_use]
    pub fn max_push_subs(mut self, n: usize) -> Self {
        self.limits.max_push_subs = n;
        self
    }

    /// Max live inbound hello subscribers across all graphs. Default 64.
    #[must_use]
    pub fn max_hello_subs(mut self, n: usize) -> Self {
        self.limits.max_hello_subs = n;
        self
    }

    /// Floor for every recurring or debounce delay, local or remote; itself
    /// floored at 1 ns. Default 1 s.
    #[must_use]
    pub fn min_delay(mut self, d: Duration) -> Self {
        self.limits.min_delay = d;
        self
    }

    /// Ceiling on every subscription lifetime, inbound or outbound. Default
    /// 365 days.
    #[must_use]
    pub fn max_sub_duration(mut self, d: Duration) -> Self {
        self.limits.max_sub_duration = d;
        self
    }

    /// How long a poll request or subscribe may wait for its reply before
    /// it counts as failed. Default 30 s.
    #[must_use]
    pub fn reply_timeout(mut self, d: Duration) -> Self {
        self.limits.reply_timeout = d;
        self
    }

    /// First retry delay after a failed poll. Default: `min_delay`.
    #[must_use]
    pub fn initial_backoff(mut self, d: Duration) -> Self {
        self.limits.initial_backoff = Some(d);
        self
    }

    /// Backoff ceiling; a peer's own `interval` also caps it. Default 5 min.
    #[must_use]
    pub fn max_backoff(mut self, d: Duration) -> Self {
        self.limits.max_backoff = d;
        self
    }

    /// A peer with no recurring interval is dropped after this many
    /// consecutive failures. Default 3.
    #[must_use]
    pub fn max_one_shot_retries(mut self, n: u8) -> Self {
        self.limits.max_one_shot_retries = n;
        self
    }

    /// Finishes building.
    #[must_use]
    pub fn build(self) -> Limits {
        self.limits
    }
}
