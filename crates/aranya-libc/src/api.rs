use alloc::sync::Arc;
use core::{
    ffi::{c_int, CStr},
    marker::PhantomData,
};

use cfg_if::cfg_if;

use super::{errno::Errno, path::Path};

cfg_if! {
    if #[cfg(target_os = "vxworks")] {
        use super::sys::vxworks as imp;
    } else if #[cfg(target_os = "linux")] {
        use super::sys::linux as imp;
    } else if #[cfg(target_os = "macos")] {
        use super::sys::macos as imp;
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

/// An owned directory stream.
///
/// It's closed on drop.
#[derive(Debug, Eq, PartialEq)]
#[repr(transparent)]
#[clippy::has_significant_drop]
pub struct OwnedDir {
    fd: imp::RawDir,
}

/// Information about an entry in a directory.
///
/// This is tied to the lifetime of the OwnedDir, and will be invalidated on the
/// next call to `readdir`.
#[derive(Debug, Eq, PartialEq)]
pub struct DirEntry<'dir> {
    entry: imp::DirEntry,
    _phantom: PhantomData<&'dir OwnedDir>,
}

impl OwnedDir {
    fn readdir(&mut self) -> Result<Option<DirEntry<'_>>, Errno> {
        let entry = imp::readdir(self.fd)?;
        Ok(entry.map(|entry| DirEntry {
            entry,
            _phantom: PhantomData,
        }))
    }
}

impl Drop for OwnedDir {
    fn drop(&mut self) {
        let _ = imp::closedir(self.fd);
    }
}

impl<'dir> DirEntry<'dir> {
    /// Returns the name for the current entry.
    #[allow(clippy::cast_possible_wrap)]
    pub fn name(&self) -> &'dir CStr {
        // SAFETY: We're far inside of the bounds of both usize and isize
        const OFFSET: isize = core::mem::offset_of!(libc::dirent, d_name) as isize;
        // SAFETY: d_name is guaranteed to be null terminated.
        let name = unsafe { CStr::from_ptr((self.entry.byte_offset(OFFSET)).cast()) };
        name
    }
}

/// A borrowed file descriptor.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct BorrowedFd<'fd> {
    pub(crate) fd: imp::RawFd,
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

/// See `fdopendir(2)`.
pub fn fdopendir(fd: impl AsAtRoot) -> Result<OwnedDir, Errno> {
    let fd = imp::fdopendir(fd.as_root())?;
    Ok(OwnedDir { fd })
}

/// See `readdir(2)`.
pub fn readdir(dir: &mut OwnedDir) -> Result<Option<DirEntry<'_>>, Errno> {
    dir.readdir()
}
