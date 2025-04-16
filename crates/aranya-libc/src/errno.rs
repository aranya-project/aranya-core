use core::{
    ffi::{c_int, CStr},
    fmt,
};

use cfg_if::cfg_if;
use tracing::warn;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub(crate) unsafe fn get_errno() -> c_int {
            // SAFETY: FFI call, no invariants.
            unsafe { *libc::__errno_location() }
        }
    } else if #[cfg(target_os = "macos")] {
        pub(crate) unsafe fn get_errno() -> c_int {
            // SAFETY: FFI call, no invariants.
            unsafe { *libc::__error() }
        }
    } else if #[cfg(target_os = "vxworks")] {
        pub(crate) unsafe fn get_errno() -> c_int {
            // SAFETY: FFI call, no invariants.
            unsafe { libc::errnoGet() }
        }
    } else {
        compile_error!("unsupported OS");
    }
}

cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub(crate) unsafe fn clear_errno() {
            // SAFETY: FFI call, no invariants.
            unsafe { *libc::__errno_location() = 0; }
        }
    } else if #[cfg(target_os = "macos")] {
        pub(crate) unsafe fn clear_errno() {
            // SAFETY: FFI call, no invariants.
            unsafe { *libc::__error() = 0; }
        }
    } else if #[cfg(target_os = "vxworks")] {
        pub(crate) unsafe fn clear_errno() {
            // SAFETY: FFI call, no invariants.
            unsafe { libc::errnoGet() = 0; }
        }
    } else {
        compile_error!("unsupported OS");
    }
}

/// Returns the value of `errno`.
pub fn errno() -> Errno {
    Errno::new()
}

/// libc's `errno`.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Errno(c_int);

impl Errno {
    /// `EINTR`.
    pub const EINTR: Errno = Errno(libc::EINTR);
    /// `ENOENT`.
    pub const ENOENT: Errno = Errno(libc::ENOENT);

    /// Returns `Errno`.
    fn new() -> Self {
        // SAFETY: FFI call, no invariants.
        Self(unsafe { get_errno() })
    }

    /// Creates an `Errno` from the raw error code.
    pub const fn from_raw_os_error(err: c_int) -> Self {
        Self(err)
    }

    /// Returns the underlying code.
    pub const fn code(self) -> c_int {
        self.0
    }
}

impl core::error::Error for Errno {}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.0, self)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 256];

        // SAFETY: FFI call, no invariants.
        let ret = unsafe { libc::strerror_r(self.0, buf.as_mut_ptr().cast(), buf.len()) };
        if ret != 0 {
            warn!(
                ret,
                errno = errno().code(),
                "`strerror_r` returned non-zero"
            );
            // We'll get here if either the error code is unknown
            // or if `buf` is too small. In either case,
            // `strerror_r` should still write a message to
            // `buf`.
        }

        match CStr::from_bytes_until_nul(&buf) {
            Ok(s) => match s.to_str() {
                Ok(s) => return s.fmt(f),
                Err(err) => warn!(?err, "`strerror_r` did not write valid UTF-8"),
            },
            Err(err) => warn!(?err, "`strerror_r` did not null-terminate `buf`"),
        }
        // Might as well write *something*.
        write!(f, "errno: {}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        const CODES: [Errno; 4] = [Errno(0), Errno::EINTR, Errno::ENOENT, Errno(c_int::MAX)];
        for (i, err) in CODES.into_iter().enumerate() {
            let got = err.to_string();
            assert!(!got.is_empty(), "#{i}")
        }
    }
}
