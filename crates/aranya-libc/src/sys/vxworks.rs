//! VxWorks support.
//!
//! While VxWorks is sorta-kinda Unixy, it's different enough
//! that it deserves its own module.

#![cfg(target_os = "vxworks")]

use core::{cell::Cell, ffi::c_int, marker::PhantomData};

pub use libc::{
    mode_t, O_CLOEXEC, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, SEEK_SET, S_IRGRP, S_IRUSR, S_IWGRP,
    S_IWUSR,
};

use crate::{
    errno::{errno, Errno},
    path::Path,
    AsAtRoot, BorrowedFd,
};

/// Does not exist on VxWorks.
pub const LOCK_EX: c_int = 0;

/// Does not exist on VxWorks.
pub const LOCK_NB: c_int = 0;

/// Does not exist on VxWorks.
pub const O_DIRECTORY: c_int = 0;

/// A raw file descriptor.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct RawFd {
    fd: c_int,
    // VxWorks does not support pread/pwrite, so ensure that
    // `RawFd` is not used concurrently.
    _no_sync: PhantomData<Cell<()>>,
}

impl BorrowedFd<'_> {
    fn as_raw(&self) -> c_int {
        self.fd.fd
    }
}

/// The `fd` argument to `openat(2)`, etc.
pub type AtRoot<'a> = &'a Path;

impl<T: AsRef<Path>> AsAtRoot for T {
    fn as_root(&self) -> AtRoot<'_> {
        self.as_ref()
    }
}

/// See `open(2)`.
pub fn open(path: &Path, oflag: c_int, mode: mode_t) -> Result<RawFd, Errno> {
    let fd = path.with_cstr(&|path| {
        // SAFETY: FFI call, no invariants.
        unsafe { libc::open(path, oflag, c_int::from(mode)) }
    });
    if fd < 0 {
        Err(errno())
    } else {
        Ok(RawFd {
            fd,
            _no_sync: PhantomData,
        })
    }
}

/// See `open(2)`.
pub fn openat(fd: &Path, path: &Path, oflag: c_int, mode: mode_t) -> Result<RawFd, Errno> {
    if path.is_abs() {
        open(path, oflag, mode)
    } else {
        open(&fd.join(path), oflag, mode)
    }
}

/// See `close(2)`.
pub fn close(fd: RawFd) -> Result<(), Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::close(fd.fd) };
    if ret < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

/// See `flock(2)`.
pub fn flock(_fd: BorrowedFd<'_>, _op: c_int) -> Result<(), Errno> {
    // Not supported on VxWorks.
    Ok(())
}

/// See `fallocate(2)`.
pub fn fallocate(_fd: BorrowedFd<'_>, _mode: c_int, _off: i64, _len: i64) -> Result<(), Errno> {
    // Not supported on VxWorks.
    Ok(())
}

/// See `read(2)`.
pub fn pread(fd: BorrowedFd<'_>, buf: &mut [u8], off: i64) -> Result<usize, Errno> {
    // NB: this is only thread safe because `RawFd` is `!Sync`.

    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::lseek(fd.as_raw(), off, SEEK_SET) };
    if ret < 0 {
        return Err(errno());
    }
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::read(fd.as_raw(), buf.as_mut_ptr().cast(), buf.len()) };
    if ret < 0 {
        Err(errno())
    } else {
        // The cast is safe because we've checked that `ret` is
        // zero or positive.
        Ok(ret as usize)
    }
}

/// See `write(2)`.
pub fn pwrite(fd: BorrowedFd<'_>, buf: &[u8], off: i64) -> Result<usize, Errno> {
    // NB: this is only thread safe because `RawFd` is `!Sync`.

    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::lseek(fd.as_raw(), off, SEEK_SET) };
    if ret < 0 {
        return Err(errno());
    }
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::write(fd.as_raw(), buf.as_ptr().cast(), buf.len()) };
    if ret < 0 {
        Err(errno())
    } else {
        // The cast is safe because we've checked that `ret` is
        // zero or positive.
        Ok(ret as usize)
    }
}

/// See `fsync(2)`.
pub fn fsync(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { libc::fsync(fd.as_raw()) };
    if ret < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}
