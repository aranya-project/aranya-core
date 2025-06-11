use core::{ffi::c_int, fmt};

/// Returns the value of `errno`.
pub fn errno() -> Errno {
    Errno::new()
}

pub(crate) fn clear_errno() {
    ::errno::set_errno(::errno::Errno(0))
}

/// libc's `errno`.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Errno(::errno::Errno);

impl Errno {
    /// `EINTR`.
    pub const EINTR: Errno = Errno(::errno::Errno(libc::EINTR));
    /// `ENOENT`.
    pub const ENOENT: Errno = Errno(::errno::Errno(libc::ENOENT));

    /// Returns `Errno`.
    fn new() -> Self {
        // SAFETY: FFI call, no invariants.
        Self(::errno::errno())
    }

    /// Creates an `Errno` from the raw error code.
    pub const fn from_raw_os_error(err: c_int) -> Self {
        Self(::errno::Errno(err))
    }

    /// Returns the underlying code.
    pub const fn code(self) -> c_int {
        self.0 .0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        const CODES: [Errno; 4] = [
            Errno::from_raw_os_error(0),
            Errno::EINTR,
            Errno::ENOENT,
            Errno::from_raw_os_error(c_int::MAX),
        ];
        for (i, err) in CODES.into_iter().enumerate() {
            let got = err.to_string();
            eprintln!("{got:?}");
            assert!(!got.is_empty(), "#{i}")
        }
    }
}
