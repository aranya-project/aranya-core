//! Caller-supplied monotonic time.

use core::time::Duration;

/// A monotonic point in time supplied by the caller.
///
/// The syncer never reads a clock: every entry point takes `now: T`. It
/// only orders instants and does saturating [`Duration`] arithmetic with
/// them. `now` must be non-decreasing across calls.
pub trait SyncInstant: Copy + Ord {
    /// Returns `self + d`, saturating at the type's maximum.
    #[must_use]
    fn saturating_add(self, d: Duration) -> Self;

    /// Returns `self - earlier`, saturating at [`Duration::ZERO`] when
    /// `earlier > self`.
    #[must_use]
    fn saturating_duration_since(self, earlier: Self) -> Duration;
}

/// Ticks since an arbitrary epoch.
impl SyncInstant for Duration {
    fn saturating_add(self, d: Duration) -> Self {
        // Resolves to the inherent method, not this impl.
        Self::saturating_add(self, d)
    }

    fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.saturating_sub(earlier)
    }
}

/// An overflowing addition yields `self`, so an absurdly far deadline fires
/// immediately rather than never. Lifetimes are capped well below that.
#[cfg(feature = "std")]
impl SyncInstant for std::time::Instant {
    fn saturating_add(self, d: Duration) -> Self {
        self.checked_add(d).unwrap_or(self)
    }

    fn saturating_duration_since(self, earlier: Self) -> Duration {
        Self::saturating_duration_since(&self, earlier)
    }
}
