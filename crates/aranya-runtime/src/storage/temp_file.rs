//! Scratch-file backends for spilling braid and convergence data.
//!
//! Two independent backends, each behind its own feature flag and both
//! implementing [`ScratchFile`]. When both features are enabled, both
//! types coexist and the caller picks which one to plug into
//! [`BraidResult`](crate::client::braiding::BraidResult) /
//! [`ConvergenceMap`](crate::client::convergence_map::ConvergenceMap),
//! matching the `IoManager` pattern used by linear storage.
//!
//! - [`FileScratchFile`] (`libc`): file-backed via `aranya_libc` pread/pwrite,
//!   using the same APIs as `linear::libc`. The underlying file is unlinked
//!   at creation and cleaned up when the last handle is dropped.
//! - [`MemScratchFile`] (`testing`): in-memory `RefCell<Vec<u8>>` buffer,
//!   suitable for unit tests and environments without a filesystem.

#[cfg(feature = "testing")]
use alloc::vec::Vec;

use crate::{StorageError, storage::ScratchFile};

// --- libc backend ---

/// File-backed scratch file, created unlinked under `/tmp` and cleaned up
/// when the last clone of the handle drops.
#[cfg(feature = "libc")]
pub struct FileScratchFile {
    fd: alloc::sync::Arc<aranya_libc::OwnedFd>,
}

#[cfg(feature = "libc")]
impl ScratchFile for FileScratchFile {
    fn new() -> Result<Self, StorageError> {
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

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<(), StorageError> {
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

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<(), StorageError> {
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

/// In-memory scratch file backed by a growable byte buffer.
#[cfg(feature = "testing")]
pub struct MemScratchFile {
    buf: core::cell::RefCell<Vec<u8>>,
}

#[cfg(feature = "testing")]
impl ScratchFile for MemScratchFile {
    fn new() -> Result<Self, StorageError> {
        Ok(Self {
            buf: core::cell::RefCell::new(Vec::new()),
        })
    }

    fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), StorageError> {
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

    fn read_at(&self, offset: usize, data: &mut [u8]) -> Result<(), StorageError> {
        let buf = self.buf.borrow();
        let end = offset
            .checked_add(data.len())
            .ok_or(StorageError::IoError)?;
        let src = buf.get(offset..end).ok_or(StorageError::IoError)?;
        data.copy_from_slice(src);
        Ok(())
    }
}
