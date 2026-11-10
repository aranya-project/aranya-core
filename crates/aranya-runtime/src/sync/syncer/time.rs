//! Caller-supplied monotonic time.

use core::time::Duration;

/// A monotonic point in time supplied by the caller.
///
/// The syncer never reads a clock: every entry point that schedules takes
/// `now: T`. It only orders instants and adds [`Duration`]s to them. `now`
/// must be non-decreasing across calls.
pub trait SyncInstant: Copy + Ord {
    /// Returns `self + d`, saturating at the type's maximum.
    #[must_use]
    fn saturating_add(self, d: Duration) -> Self;
}

/// Ticks since an arbitrary epoch.
impl SyncInstant for Duration {
    fn saturating_add(self, d: Duration) -> Self {
        // Resolves to the inherent method, not this impl.
        Self::saturating_add(self, d)
    }
}

/// An overflowing addition yields `self`, so an absurdly far deadline fires
/// immediately rather than never.
#[cfg(feature = "std")]
impl SyncInstant for std::time::Instant {
    fn saturating_add(self, d: Duration) -> Self {
        self.checked_add(d).unwrap_or(self)
    }
}
