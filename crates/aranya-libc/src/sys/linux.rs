#![cfg(target_os = "linux")]

use core::ffi::c_int;

#[allow(clippy::wildcard_imports)]
pub use super::unix::*;
use crate::{
    BorrowedFd,
    errno::{Errno, errno},
};

/// See `fallocate(2)`.
pub fn fallocate(fd: BorrowedFd<'_>, mode: c_int, off: i64, len: i64) -> Result<(), Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::fallocate64(fd.fd, mode, off, len) };
    if ret < 0 { Err(errno()) } else { Ok(()) }
}

/// See `read(2)`.
pub fn pread(fd: BorrowedFd<'_>, buf: &mut [u8], off: i64) -> Result<usize, Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::pread64(fd.fd, buf.as_mut_ptr().cast(), buf.len(), off) };
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
    let ret = unsafe { libc::pwrite64(fd.fd, buf.as_ptr().cast(), buf.len(), off) };
    if ret < 0 {
        Err(errno())
    } else {
        // The cast is safe because we've checked that `ret` is
        // zero or positive.
        #[allow(clippy::cast_sign_loss)]
        Ok(ret as usize)
    }
}
