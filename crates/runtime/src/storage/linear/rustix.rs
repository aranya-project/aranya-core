//! IO provider for linear storage based on rustix (libc) files.

#![cfg(feature = "rustix")]
#![cfg_attr(docs, doc(cfg(feature = "rustix")))]

use alloc::{string::ToString, sync::Arc};
use core::{cmp::Ordering, hash::Hasher};

use buggy::{bug, BugExt};
use rustix::{
    fd::OwnedFd,
    fs::{self, FallocateFlags, Mode, OFlags},
    io::Errno,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::error;

use crate::{linear, GraphId, Location, StorageError};

#[derive(Debug)]
pub struct FileManager {
    dir: OwnedFd,
}

impl FileManager {
    pub fn new<P: rustix::path::Arg>(dir: P) -> rustix::io::Result<Self> {
        Ok(Self {
            dir: fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())?,
        })
    }
}

impl linear::io::IoManager for FileManager {
    type Writer = Writer;

    fn create(&mut self, id: GraphId) -> Result<Self::Writer, StorageError> {
        let name = id.to_string();
        let fd = fs::openat(
            &self.dir,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP,
        )?;
        fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive)?;
        // TODO(jdygert): fallocate?
        Writer::create(fd)
    }

    fn open(&mut self, id: GraphId) -> Result<Option<Self::Writer>, StorageError> {
        let name = id.to_string();
        let fd = match fs::openat(&self.dir, name, OFlags::RDWR, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive)?;
        Ok(Some(Writer::open(fd)?))
    }
}

#[derive(Debug)]
/// A file-based writer for linear storage.
pub struct Writer {
    file: File,
    root: Root,
}

/// An estimated page size for spacing the control data.
const PAGE: u64 = 4096;

// We store 2 roots for redudancy.
/// Offset of the first [`Root`].
const ROOT_A: u64 = PAGE;
/// Offset of the second [`Root`].
const ROOT_B: u64 = PAGE * 2;

/// Starting offset for segment/fact data
const FREE_START: u64 = PAGE * 3;

impl Writer {
    fn create(fd: OwnedFd) -> Result<Self, StorageError> {
        let file = File { fd: Arc::new(fd) };
        // Preallocate so we can start appending from FREE_START forward.
        file.fallocate(0, FREE_START)?;
        Ok(Self {
            file,
            root: Root::new(),
        })
    }

    fn open(fd: OwnedFd) -> Result<Self, StorageError> {
        let file = File { fd: Arc::new(fd) };

        // Pick the latest valid root.
        let (root, overwrite) = match (
            file.load(ROOT_A).and_then(Root::validate),
            file.load(ROOT_B).and_then(Root::validate),
        ) {
            (Ok(root_a), Ok(root_b)) => match root_a.generation.cmp(&root_b.generation) {
                Ordering::Equal => (root_a, None),
                Ordering::Greater => (root_a, Some(ROOT_B)),
                Ordering::Less => (root_b, Some(ROOT_A)),
            },
            (Ok(root_a), Err(_)) => (root_a, Some(ROOT_B)),
            (Err(_), Ok(root_b)) => (root_b, Some(ROOT_A)),
            (Err(e), Err(_)) => return Err(e),
        };

        // Write other side if needed (corrupted or outdated)
        if let Some(offset) = overwrite {
            file.dump(offset, &root)?;
        }

        Ok(Self { file, root })
    }

    fn write_root(&mut self) -> Result<(), StorageError> {
        self.root.generation = self
            .root
            .generation
            .checked_add(1)
            .assume("generation will not overflow u64")?;

        // Write roots one at a time, flushing afterward to ensure one is always valid.
        for offset in [ROOT_A, ROOT_B] {
            self.root.checksum = self.root.calc_checksum();
            self.file.dump(offset, &self.root)?;
            self.file.sync()?;
        }

        Ok(())
    }
}

impl linear::io::Write for Writer {
    type ReadOnly = Reader;
    fn readonly(&self) -> Self::ReadOnly {
        Reader {
            file: self.file.clone(),
        }
    }

    fn head(&self) -> Result<Location, StorageError> {
        if self.root.generation == 0 {
            bug!("not initialized")
        }
        Ok(self.root.head)
    }

    fn append<F, T>(&mut self, builder: F) -> Result<T, StorageError>
    where
        F: FnOnce(usize) -> T,
        T: Serialize,
    {
        let offset = self.root.free_offset as usize;

        let item = builder(offset);
        let new_offset = self.file.dump(offset as u64, &item)?;

        self.root.free_offset = new_offset;
        self.write_root()?;

        Ok(item)
    }

    fn commit(&mut self, head: Location) -> Result<(), StorageError> {
        self.root.head = head;
        self.write_root()?;
        Ok(())
    }
}

/// Section of control data for the file
#[derive(Debug, Serialize, Deserialize)]
struct Root {
    /// Incremented each commit
    generation: u64,
    /// Commit head.
    head: Location,
    /// Offset to write new item at.
    free_offset: u64,
    /// Used to ensure root is valid. Write could be interrupted or corrupted.
    checksum: u64,
}

impl Root {
    fn new() -> Self {
        Self {
            generation: 0,
            head: Location::new(usize::MAX, usize::MAX),
            free_offset: FREE_START,
            checksum: 0,
        }
    }

    fn calc_checksum(&self) -> u64 {
        let mut hasher = crypto::siphasher::sip::SipHasher::new();
        hasher.write_u64(self.generation);
        hasher.write_usize(self.head.segment);
        hasher.write_usize(self.head.command);
        hasher.write_u64(self.free_offset);
        hasher.finish()
    }

    fn validate(self) -> Result<Self, StorageError> {
        if self.checksum != self.calc_checksum() {
            // TODO(jdygert): Isn't really a bug.
            bug!("invalid checksum");
        }
        Ok(self)
    }
}

#[derive(Clone, Debug)]
/// A file-based reader for linear storage.
pub struct Reader {
    file: File,
}

impl linear::io::Read for Reader {
    fn fetch<T>(&self, offset: usize) -> Result<T, StorageError>
    where
        T: DeserializeOwned,
    {
        self.file.load(offset as u64)
    }
}

#[derive(Clone, Debug)]
struct File {
    fd: Arc<OwnedFd>,
}

impl File {
    fn fallocate(&self, offset: u64, len: u64) -> Result<(), StorageError> {
        Ok(fs::fallocate(
            &self.fd,
            FallocateFlags::empty(),
            offset,
            len,
        )?)
    }

    fn read_exact(&self, mut offset: u64, mut buf: &mut [u8]) -> Result<(), StorageError> {
        while !buf.is_empty() {
            match rustix::io::pread(&self.fd, buf, offset) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    offset = offset
                        .checked_add(u64::try_from(n).assume("read within bounds")?)
                        .assume("read within bounds")?;
                }
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !buf.is_empty() {
            error!(remaining = buf.len(), "could not fill buffer");
            Err(StorageError::IoError)
        } else {
            Ok(())
        }
    }

    fn write_all(&self, mut offset: u64, mut buf: &[u8]) -> Result<(), StorageError> {
        while !buf.is_empty() {
            match rustix::io::pwrite(&self.fd, buf, offset) {
                Ok(0) => {
                    error!(remaining = buf.len(), "could not write whole buffer");
                    return Err(StorageError::IoError);
                }
                Ok(n) => {
                    buf = &buf[n..];
                    offset = offset
                        .checked_add(u64::try_from(n).assume("write within bounds")?)
                        .assume("write within bounds")?;
                }
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), StorageError> {
        fs::fsync(&self.fd)?;
        Ok(())
    }

    fn dump<T: Serialize>(&self, offset: u64, value: &T) -> Result<u64, StorageError> {
        let bytes = postcard::to_allocvec(value).map_err(|err| {
            error!(?err, "dump");
            StorageError::IoError
        })?;
        let len: u32 = bytes
            .len()
            .try_into()
            .assume("serialized objects should fit in u32")?;
        self.write_all(offset, &len.to_be_bytes())?;
        let offset2 = offset.checked_add(4).assume("offset not near u64::MAX")?;
        self.write_all(offset2, &bytes)?;
        Ok(offset2
            .checked_add(len.into())
            .assume("offset valid after write")?)
    }

    fn load<T: DeserializeOwned>(&self, offset: u64) -> Result<T, StorageError> {
        let mut bytes = [0u8; 4];
        self.read_exact(offset, &mut bytes)?;
        let len = u32::from_be_bytes(bytes);
        let mut bytes = alloc::vec![0u8; len as usize];
        self.read_exact(
            offset.checked_add(4).assume("offset not near u64::MAX")?,
            &mut bytes,
        )?;
        postcard::from_bytes(&bytes).map_err(|err| {
            error!(?err, "load");
            StorageError::IoError
        })
    }
}

#[cfg(test)]
mod tests {
    use tracing::info;

    use super::*;
    use crate::{
        storage::linear::LinearStorageProvider,
        testing::dsl::{test_suite, StorageBackend},
    };

    struct LinearBackend {
        tempdir: tempfile::TempDir,
    }

    impl StorageBackend for LinearBackend {
        type StorageProvider = LinearStorageProvider<FileManager>;

        fn provider(&mut self, client_id: u64) -> Self::StorageProvider {
            let dir = self.tempdir.path().join(client_id.to_string());
            std::fs::create_dir(&dir).unwrap();
            let manager = FileManager::new(&dir).unwrap();
            LinearStorageProvider::new(manager)
        }
    }

    test_suite!(|| {
        let tempdir = tempfile::tempdir().unwrap();
        info!(path = ?tempdir.path(), "using tempdir");
        LinearBackend { tempdir }
    });
}
