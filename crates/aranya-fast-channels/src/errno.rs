//! Support for libc's `errno`.

use core::fmt;

/// Returns the value of `errno`.
pub fn errno() -> Errno {
    Errno(::errno::errno())
}

/// libc's `errno`.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Errno(::errno::Errno);

impl Errno {
    #[cfg(feature = "libc")]
    #[allow(missing_docs)]
    pub const EINTR: Self = Self(::errno::Errno(libc::EINTR));
    #[cfg(feature = "libc")]
    #[allow(missing_docs)]
    pub const EAGAIN: Self = Self(::errno::Errno(libc::EAGAIN));

    /// Returns the underlying code.
    #[inline]
    pub const fn code(&self) -> i32 {
        self.0.0
    }
}

impl core::error::Error for Errno {}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
