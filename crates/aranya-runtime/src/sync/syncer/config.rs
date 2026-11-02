//! Poll configuration and the syncer's limits.

use core::time::Duration;

/// How and when to poll a peer.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerConfig {
    /// Recurring poll interval, floored at [`LimitsBuilder::min_delay`].
    /// `None`: do not poll on a schedule.
    pub interval: Option<Duration>,
    /// Poll once as soon as registered.
    pub sync_now: bool,
}

impl PeerConfig {
    /// Polls immediately, then every `interval`.
    #[must_use]
    pub const fn periodic(interval: Duration) -> Self {
        Self {
            interval: Some(interval),
            sync_now: true,
        }
    }

    /// Polls once, immediately, with no recurring schedule.
    #[must_use]
    pub const fn immediate() -> Self {
        Self {
            interval: None,
            sync_now: true,
        }
    }
}

pub(crate) const DEFAULT_MIN_DELAY: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_REPLY_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
pub(crate) const DEFAULT_MAX_ONE_SHOT_RETRIES: u8 = 3;
pub(crate) const DEFAULT_MAX_INFLIGHT_POLLS: usize = 8;

/// Caps and clamps on syncer state.
///
/// Build with [`Limits::builder`]; [`Default`] is the all-defaults value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub(crate) min_delay: Duration,
    pub(crate) reply_timeout: Duration,
    pub(crate) initial_backoff: Option<Duration>,
    pub(crate) max_backoff: Duration,
    pub(crate) max_one_shot_retries: u8,
    pub(crate) max_inflight_polls: usize,
}

impl Limits {
    /// Starts a [`LimitsBuilder`] seeded with the defaults.
    pub fn builder() -> LimitsBuilder {
        LimitsBuilder {
            limits: Self::default(),
        }
    }

    /// Floors `min_delay` at 1 ns so drain termination cannot be configured
    /// away, keeps the other delays consistent with it, and allows at least
    /// one poll in flight.
    pub(crate) fn normalized(mut self) -> Self {
        self.min_delay = self.min_delay.max(Duration::from_nanos(1));
        self.max_backoff = self.max_backoff.max(self.min_delay);
        self.reply_timeout = self.reply_timeout.max(self.min_delay);
        self.max_inflight_polls = self.max_inflight_polls.max(1);
        self
    }

    /// Floors a recurring delay at `min_delay`.
    pub(crate) fn clamp_delay(&self, d: Duration) -> Duration {
        d.max(self.min_delay)
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
            min_delay: DEFAULT_MIN_DELAY,
            reply_timeout: DEFAULT_REPLY_TIMEOUT,
            initial_backoff: None,
            max_backoff: DEFAULT_MAX_BACKOFF,
            max_one_shot_retries: DEFAULT_MAX_ONE_SHOT_RETRIES,
            max_inflight_polls: DEFAULT_MAX_INFLIGHT_POLLS,
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
    /// Floor for every recurring delay; itself floored at 1 ns. Default 1 s.
    #[must_use]
    pub fn min_delay(mut self, d: Duration) -> Self {
        self.limits.min_delay = d;
        self
    }

    /// How long a poll request may wait for its reply before it counts as
    /// failed. Default 30 s.
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

    /// Max poll requests awaiting a reply at once, across all peers and
    /// graphs; floored at 1. A due poll waits while the cap is reached.
    /// Default 8.
    #[must_use]
    pub fn max_inflight_polls(mut self, n: usize) -> Self {
        self.limits.max_inflight_polls = n;
        self
    }

    /// Finishes building.
    #[must_use]
    pub fn build(self) -> Limits {
        self.limits
    }
}
