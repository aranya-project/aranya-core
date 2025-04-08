#![cfg(all(target_family = "unix", not(target_os = "vxworks")))]

use core::ffi::{c_int, c_uint};

pub use libc::{
    mode_t, LOCK_EX, LOCK_NB, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY, O_RDWR, S_IRGRP,
    S_IRUSR, S_IWGRP, S_IWUSR,
};

use crate::{
    errno::{errno, Errno},
    path::Path,
    AsAtRoot, AsFd, BorrowedFd,
};

/// A raw file descriptor.
pub type RawFd = c_int;

/// A raw directory stream.
pub type RawDir = *mut libc::DIR;

/// A raw directory entry.
pub type DirEntry = *mut libc::dirent;

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

/// See `fdopendir(2)`.
pub fn fdopendir(fd: BorrowedFd<'_>) -> Result<RawDir, Errno> {
    // SAFETY: FFI call, no invariants.
    let dir = unsafe { libc::fdopendir(fd.fd) };
    if dir.is_null() {
        Err(errno())
    } else {
        Ok(dir)
    }
}

/// See `readdir(2)`.
pub fn readdir(dir: RawDir) -> Result<DirEntry, Errno> {
    // `To distinguish between an end-of-directory condition or an error, you
    // must set errno to zero before calling readdir.`
    unsafe { crate::errno::clear_errno(); }
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::readdir(dir) };
    if ret.is_null() {
        Err(errno())
    } else {
        Ok(ret)
    }
}

/// See `closedir(2)`.
pub fn closedir(dir: RawDir) -> Result<(), Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::closedir(dir) };
    if ret < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}
