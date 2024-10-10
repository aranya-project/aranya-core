//! Support for libc's `errno`.

use core::{ffi::c_int, fmt};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(not(feature = "libc"))] {
        unsafe fn get_errno() -> c_int { 0 }
    } else if #[cfg(target_os = "linux")] {
        unsafe fn get_errno() -> c_int{
            *libc::__errno_location()
        }
    } else if #[cfg(target_os = "vxworks")] {
        unsafe fn get_errno() -> c_int{
            libc::errnoGet()
        }
    } else if #[cfg(target_os = "macos")] {
        unsafe fn get_errno() -> c_int {
            *libc::__error()
        }
    } else {
        unsafe fn get_errno() -> c_int { 0 }
    }
}

/// Returns the value of `errno`.
pub fn errno() -> Errno {
    // SAFETY: FFI call, no invariants.
    Errno(unsafe { get_errno() })
}

/// libc's `errno`.
///
/// If the `libc` feature is not enabled, it is always zero and
/// its string representation is `"???"`.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Errno(i32);

impl Errno {
    #[cfg(feature = "libc")]
    #[allow(missing_docs)]
    pub const EINTR: Errno = Errno(libc::EINTR);
    #[cfg(feature = "libc")]
    #[allow(missing_docs)]
    pub const EAGAIN: Errno = Errno(libc::EAGAIN);

    /// Returns the underlying code.
    #[inline]
    pub const fn code(&self) -> i32 {
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
        cfg_if! {
            if #[cfg(not(feature = "libc"))] {
                write!(f, "???")
            } else {
                // SAFETY: FFI call, no invariants.
                let str = unsafe {
                    let ptr = libc::strerror(self.0);
                    core::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("???")
                };
                write!(f, "{str}")
            }
        }
    }
}
