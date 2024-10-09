mod errno;
mod linux;
mod macos;
mod unix;
mod vxworks;

use alloc::sync::Arc;
use core::{ffi::c_int, marker::PhantomData};

use cfg_if::cfg_if;
pub use errno::Errno;

use super::path::Path;

cfg_if! {
    if #[cfg(target_os = "vxworks")] {
        use vxworks as imp;
    } else if #[cfg(target_os = "linux")] {
        use linux as imp;
    } else if #[cfg(target_os = "macos")] {
        use macos as imp;
    } else {
        compile_error!("unsupported OS");
    }
}

pub use imp::{
    mode_t, LOCK_EX, LOCK_NB, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY, O_RDWR, S_IRGRP,
    S_IRUSR, S_IWGRP, S_IWUSR,
};

/// Allows borrowing the file descriptor.
pub trait AsFd {
    /// Borrows the file descriptor.
    fn as_fd(&self) -> BorrowedFd<'_>;
}

impl<T> AsFd for &T
where
    T: AsFd + ?Sized,
{
    fn as_fd(&self) -> BorrowedFd<'_> {
        T::as_fd(self)
    }
}

impl<T> AsFd for Arc<T>
where
    T: AsFd + ?Sized,
{
    fn as_fd(&self) -> BorrowedFd<'_> {
        (**self).as_fd()
    }
}

/// An owned file descriptor.
///
/// It's closed on drop.
#[derive(Debug, Eq, PartialEq)]
#[repr(transparent)]
#[clippy::has_significant_drop]
pub struct OwnedFd {
    fd: imp::RawFd,
}

impl AsFd for OwnedFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        BorrowedFd {
            fd: self.fd,
            _lifetime: PhantomData,
        }
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        let _ = imp::close(self.fd);
    }
}

/// A borrowed file descriptor.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct BorrowedFd<'fd> {
    fd: imp::RawFd,
    _lifetime: PhantomData<&'fd OwnedFd>,
}

impl AsFd for BorrowedFd<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        *self
    }
}

/// The `fd` argument to `openat(2)`, etc.
pub trait AsAtRoot {
    /// Returns the `fd` argument.
    fn as_root(&self) -> imp::AtRoot<'_>;
}

/// See `open(2)`.
pub fn open(path: impl AsRef<Path>, oflag: c_int, mode: mode_t) -> Result<OwnedFd, Errno> {
    let fd = imp::open(path.as_ref(), oflag, mode)?;
    Ok(OwnedFd { fd })
}

/// See `open(2)`.
pub fn openat(
    fd: impl AsAtRoot,
    path: impl AsRef<Path>,
    oflag: c_int,
    mode: mode_t,
) -> Result<OwnedFd, Errno> {
    let fd = imp::openat(fd.as_root(), path.as_ref(), oflag, mode)?;
    Ok(OwnedFd { fd })
}

/// See `flock(2)`.
pub fn flock(fd: impl AsFd, op: c_int) -> Result<(), Errno> {
    imp::flock(fd.as_fd(), op)
}

/// See `fallocate(2)`.
pub fn fallocate(fd: impl AsFd, mode: c_int, off: i64, len: i64) -> Result<(), Errno> {
    imp::fallocate(fd.as_fd(), mode, off, len)
}

/// See `read(2)`.
pub fn pread(fd: impl AsFd, buf: &mut [u8], off: i64) -> Result<usize, Errno> {
    imp::pread(fd.as_fd(), buf, off)
}

/// See `write(2)`.
pub fn pwrite(fd: impl AsFd, buf: &[u8], off: i64) -> Result<usize, Errno> {
    imp::pwrite(fd.as_fd(), buf, off)
}

/// See `fsync(2)`.
pub fn fsync(fd: impl AsFd) -> Result<(), Errno> {
    imp::fsync(fd.as_fd())
}
