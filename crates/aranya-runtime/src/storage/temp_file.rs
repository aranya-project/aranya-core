//! Temporary scratch file for spilling data during braiding and convergence.
//!
//! Two backends:
//! - `libc`: file-backed using `aranya_libc` pread/pwrite, matching
//!   the same APIs used by `linear::libc`.
//! - `testing`: in-memory `Vec<u8>` buffer (when libc is not available).

use crate::StorageError;

#[cfg(all(feature = "testing", not(feature = "libc")))]
use alloc::vec::Vec;

// --- libc backend ---

#[cfg(feature = "libc")]
pub struct TempFile {
    fd: alloc::sync::Arc<aranya_libc::OwnedFd>,
}

#[cfg(feature = "libc")]
impl TempFile {
    /// Create a new temporary file.
    ///
    /// The file is created in `/tmp` and immediately unlinked so it
    /// is cleaned up when the fd is closed.
    pub fn new() -> Result<Self, StorageError> {
        use aranya_libc::{
            self as libc, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY, O_RDWR, Path, S_IRUSR,
            S_IWUSR,
        };

        static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let tmp_path = Path::new(b"/tmp\0");
        let dir_fd = libc::open(tmp_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)
            .map_err(|_| StorageError::IoError)?;

        let name = alloc::format!(".aranya_spill_{}\0", id);
        let file_path = Path::new(name.as_bytes());

        let fd = libc::openat(
            libc::AsFd::as_fd(&dir_fd),
            file_path,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
            S_IRUSR | S_IWUSR,
        )
        .map_err(|_| StorageError::IoError)?;

        // Unlink immediately — file stays open via fd, cleaned up on drop.
        let _ = libc::unlinkat(libc::AsFd::as_fd(&dir_fd), file_path, 0);

        Ok(Self {
            fd: alloc::sync::Arc::new(fd),
        })
    }

    /// Write `buf` at the given byte offset.
    pub fn write_at(&self, offset: usize, buf: &[u8]) -> Result<(), StorageError> {
        use aranya_libc::{self as libc, Errno};
        use buggy::BugExt as _;

        let mut off = i64::try_from(offset).assume("`offset` fits in i64")?;
        let mut remaining = buf;
        while !remaining.is_empty() {
            match libc::pwrite(&self.fd, remaining, off) {
                Ok(0) => return Err(StorageError::IoError),
                Ok(n) => {
                    remaining = remaining.get(n..).assume("`n` is in bounds")?;
                    off = off
                        .checked_add(i64::try_from(n).assume("write within bounds")?)
                        .assume("write within bounds")?;
                }
                Err(Errno::EINTR) => {}
                Err(_) => return Err(StorageError::IoError),
            }
        }
        Ok(())
    }

    /// Read exactly `buf.len()` bytes starting at the given byte offset.
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<(), StorageError> {
        use aranya_libc::{self as libc, Errno};
        use buggy::BugExt as _;

        let mut off = i64::try_from(offset).assume("`offset` fits in i64")?;
        let mut remaining = buf;
        while !remaining.is_empty() {
            match libc::pread(&self.fd, remaining, off) {
                Ok(0) => return Err(StorageError::IoError),
                Ok(n) => {
                    remaining = remaining.get_mut(n..).assume("`n` is in bounds")?;
                    off = off
                        .checked_add(i64::try_from(n).assume("read within bounds")?)
                        .assume("read within bounds")?;
                }
                Err(Errno::EINTR) => {}
                Err(_) => return Err(StorageError::IoError),
            }
        }
        Ok(())
    }
}

// --- testing (in-memory) backend ---

#[cfg(all(feature = "testing", not(feature = "libc")))]
pub struct TempFile {
    buf: core::cell::RefCell<Vec<u8>>,
}

#[cfg(all(feature = "testing", not(feature = "libc")))]
impl TempFile {
    /// Create a new in-memory temporary file.
    pub fn new() -> Result<Self, StorageError> {
        Ok(Self {
            buf: core::cell::RefCell::new(Vec::new()),
        })
    }

    /// Write `buf` at the given byte offset, extending if needed.
    pub fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), StorageError> {
        let mut buf = self.buf.borrow_mut();
        let end = offset
            .checked_add(data.len())
            .ok_or(StorageError::IoError)?;
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[offset..end].copy_from_slice(data);
        Ok(())
    }

    /// Read exactly `buf.len()` bytes starting at the given byte offset.
    pub fn read_at(&self, offset: usize, data: &mut [u8]) -> Result<(), StorageError> {
        let buf = self.buf.borrow();
        let end = offset
            .checked_add(data.len())
            .ok_or(StorageError::IoError)?;
        let src = buf.get(offset..end).ok_or(StorageError::IoError)?;
        data.copy_from_slice(src);
        Ok(())
    }
}
