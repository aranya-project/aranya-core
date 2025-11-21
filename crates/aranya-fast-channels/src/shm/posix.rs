#![cfg(feature = "posix")]
#![cfg_attr(feature = "sdlib", allow(dead_code))]

use core::{
    alloc::Layout,
    ffi::{c_int, c_void},
    ptr,
};

use buggy::BugExt as _;
use cfg_if::cfg_if;
use derive_where::derive_where;
use libc::{
    MAP_FAILED, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, PROT_READ, PROT_WRITE, S_IRUSR, S_IWUSR, off_t,
};

use super::{
    align::Aligned,
    error::Error,
    path::{Flag, Mode, Path},
};
use crate::errno::{Errno, errno};

// On macOS (and probably other BSDs), shm_open is variadic so
// its other arguments are interpreted as c_int.
cfg_if! {
    if #[cfg(target_os = "macos")] {
        type ModeT = c_int;
    } else {
        type ModeT = libc::mode_t;
    }
}

const fn invalid_argument(msg: &'static str) -> Error {
    Error::InvalidArgument(msg)
}

// See `shm_open(2)`.
fn shm_open<P>(path: P, flag: c_int, mode: ModeT) -> Result<Fd, Errno>
where
    P: AsRef<Path>,
{
    // SAFETY: FFI call, no invariants
    let fd = unsafe { libc::shm_open(path.as_ref().as_ptr(), flag, mode) };
    if fd < 0 { Err(errno()) } else { Ok(Fd(fd)) }
}

// See `shm_unlink(2)`.
pub(super) fn shm_unlink<P>(path: P) -> Result<(), Errno>
where
    P: AsRef<Path>,
{
    // SAFETY: FFI call, no invariants
    let ret = unsafe { libc::shm_unlink(path.as_ref().as_ptr()) };
    if ret < 0 { Err(errno()) } else { Ok(()) }
}

/// Memory mapped shared memory.
#[derive_where(Debug)]
pub(super) struct Mapping<T> {
    /// The usable section of the mapping.
    ptr: Aligned<T>,
    /// The base of the mapping.
    base: *mut c_void,
    /// How the mapping is laid out.
    layout: Layout,
}

// SAFETY: `Mapping` is !Send by default because it contains raw
// pointers. But since it does not have any thread affinity, we
// can safely make it Send.
unsafe impl<T: Send> Send for Mapping<T> {}

// SAFETY: `Mapping` is !Sync by default because it contains raw
// pointers. But since it does not have any thread affinity, we
// can safely make it Sync.
unsafe impl<T: Sync> Sync for Mapping<T> {}

impl<T> Drop for Mapping<T> {
    fn drop(&mut self) {
        // SAFETY: FFI call, no invariants.
        let _ = unsafe { libc::munmap(self.base, self.layout.size()) };
    }
}

impl<T: Sync> AsRef<T> for Mapping<T> {
    fn as_ref(&self) -> &T {
        // SAFETY: the pointer is aligned, the pointer is
        // dereferenceable, the data is initialized, we do not
        // violate aliasing rules.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> Mapping<T> {
    /// Acquires the underlying `*mut` pointer.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Creates a shared memory mapping at `path`.
    pub fn open<P>(path: P, flag: Flag, mode: Mode, layout: Layout) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let need_init = flag == Flag::Create;
        let (mut flag, prot) = match mode {
            #[allow(deprecated)]
            Mode::ReadOnly => (O_RDONLY, PROT_READ),
            Mode::ReadWrite => (O_RDWR, PROT_READ | PROT_WRITE),
        };
        if need_init {
            flag |= O_CREAT | O_EXCL;
        }
        const MODE: ModeT = (S_IRUSR | S_IWUSR) as ModeT;
        let fd = shm_open(path, flag, MODE).map_err(Error::Errno)?;
        if need_init {
            ftruncate(fd.0, layout.size())?;
        }
        Self::try_mmap(fd, prot, layout)
    }

    fn try_mmap(fd: Fd, prot: c_int, layout: Layout) -> Result<Self, Error> {
        const ADDR: *mut c_void = ptr::null_mut::<c_void>();
        cfg_if! {
            if #[cfg(target_os = "macos")] {
                const FLAGS: c_int = libc::MAP_SHARED | libc::MAP_HASSEMAPHORE;
            } else if #[cfg(target_os = "linux")] {
                const FLAGS: c_int =
                    libc::MAP_SHARED | libc::MAP_SHARED_VALIDATE | libc::MAP_NORESERVE | libc::MAP_POPULATE;
            } else {
                const FLAGS: c_int = libc::MAP_SHARED;
            }
        }

        // SAFETY: FFI call, no invariants.
        match unsafe { libc::mmap(ADDR, layout.size(), prot, FLAGS, fd.0, 0) } {
            MAP_FAILED => Err(Error::Errno(errno())),
            // TODO(eric): better error here.
            base if base.is_null() => Err(invalid_argument("mmap returned null, not MAP_FAILED")),
            base => {
                let ptr = Aligned::new(base.cast::<T>(), layout)
                    // TODO(eric): better error here.
                    .ok_or(invalid_argument("unable to align mapping"))?;
                Ok(Self { ptr, base, layout })
            }
        }
    }
}

struct Fd(c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

/// See `close(2)`.
fn close(fd: c_int) -> Result<(), Errno> {
    // SAFETY: FFI call, no invariants.
    if unsafe { libc::close(fd) } < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

/// See `ftruncate(2)`.
fn ftruncate(fd: c_int, len: usize) -> Result<(), Error> {
    let len = off_t::try_from(len).assume("`len` should fit inside `off_t`")?;
    // SAFETY: FFI call, no invariants.
    if unsafe { libc::ftruncate(fd, len) } < 0 {
        Err(Error::Errno(errno()))
    } else {
        Ok(())
    }
}
