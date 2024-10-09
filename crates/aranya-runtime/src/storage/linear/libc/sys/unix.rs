#![cfg(all(target_family = "unix", not(target_os = "vxworks")))]

use core::ffi::{c_int, c_uint};

pub use libc::{
    mode_t, LOCK_EX, LOCK_NB, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY, O_RDWR, S_IRGRP,
    S_IRUSR, S_IWGRP, S_IWUSR,
};

use super::{
    super::path::Path,
    errno::{errno, Errno},
    AsAtRoot, AsFd, BorrowedFd,
};

/// A raw file descriptor.
pub type RawFd = c_int;

/// The `fd` argument to `openat(2)`, etc.
pub type AtRoot<'a> = BorrowedFd<'a>;

impl<T: AsFd> AsAtRoot for T {
    fn as_root(&self) -> AtRoot<'_> {
        self.as_fd()
    }
}

/// See `open(2)`.
pub fn open(path: &Path, oflag: c_int, mode: mode_t) -> Result<RawFd, Errno> {
    let fd = path.with_cstr(&|path| {
        // SAFETY: FFI call, no invariants.
        unsafe { libc::open(path, oflag, c_uint::from(mode)) }
    });
    if fd < 0 {
        Err(errno())
    } else {
        Ok(fd)
    }
}

/// See `open(2)`.
pub fn openat(fd: BorrowedFd<'_>, path: &Path, oflag: c_int, mode: mode_t) -> Result<RawFd, Errno> {
    let fd = path.with_cstr(&|path| {
        // SAFETY: FFI call, no invariants.
        unsafe { libc::openat(fd.fd, path, oflag, c_uint::from(mode)) }
    });
    if fd < 0 {
        Err(errno())
    } else {
        Ok(fd)
    }
}

/// See `close(2)`.
pub fn close(fd: RawFd) -> Result<(), Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::close(fd) };
    if ret < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

/// See `flock(2)`.
pub fn flock(fd: BorrowedFd<'_>, op: c_int) -> Result<(), Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::flock(fd.fd, op) };
    if ret < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

/// See `fsync(2)`.
pub fn fsync(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::fsync(fd.fd) };
    if ret < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}
