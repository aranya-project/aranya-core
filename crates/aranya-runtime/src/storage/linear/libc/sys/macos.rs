#![cfg(target_os = "macos")]

use core::ffi::c_int;

#[allow(clippy::wildcard_imports)]
pub use super::unix::*;
use super::{
    errno::{errno, Errno},
    BorrowedFd,
};

/// See `fallocate(2)`.
pub fn fallocate(_fd: BorrowedFd<'_>, _mode: c_int, _off: i64, _len: i64) -> Result<(), Errno> {
    Ok(())
}

/// See `read(2)`.
pub fn pread(fd: BorrowedFd<'_>, buf: &mut [u8], off: i64) -> Result<usize, Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::pread(fd.fd, buf.as_mut_ptr().cast(), buf.len(), off) };
    if ret < 0 {
        Err(errno())
    } else {
        // The cast is safe because we've checked that `ret` is
        // zero or positive.
        #[allow(clippy::cast_sign_loss)]
        Ok(ret as usize)
    }
}

/// See `write(2)`.
pub fn pwrite(fd: BorrowedFd<'_>, buf: &[u8], off: i64) -> Result<usize, Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::pwrite(fd.fd, buf.as_ptr().cast(), buf.len(), off) };
    if ret < 0 {
        Err(errno())
    } else {
        // The cast is safe because we've checked that `ret` is
        // zero or positive.
        #[allow(clippy::cast_sign_loss)]
        Ok(ret as usize)
    }
}
