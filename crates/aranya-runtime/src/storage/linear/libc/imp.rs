use alloc::sync::Arc;
use core::{cmp::Ordering, hash::Hasher as _};

use aranya_libc::{
    self as libc, AsAtRoot, Errno, LOCK_EX, LOCK_NB, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL,
    O_RDONLY, O_RDWR, OwnedDir, OwnedFd, Path, S_IRGRP, S_IRUSR, S_IWGRP, S_IWUSR,
};
use buggy::{BugExt as _, bug};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{error, warn};

use super::error::Error;
use crate::{
    GraphId, Location, MaxCut, SegmentIndex, StorageError,
    linear::{
        io::{IoManager, Read, Write},
        libc::IdPath,
    },
};

struct GraphIdIterator {
    inner: OwnedDir,
}

impl GraphIdIterator {
    fn new(fd: impl AsAtRoot) -> Result<Self, StorageError> {
        // We're probably reusing a fd, so let's dupe it. This still shares
        // state so any subsequent calls are affected, but this solves the
        // problem of closedir destroying this specific fd.
        let fd = libc::dup(fd.as_root())?;
        let mut inner = libc::fdopendir(fd)?;
        // Since we may be at the end of the directory due to shared state,
        // let's be kind, rewind.
        libc::rewinddir(&mut inner);
        Ok(Self { inner })
    }
}

impl Iterator for GraphIdIterator {
    type Item = Result<GraphId, StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Loop until we find an entry that contains an actual GraphId
        loop {
            let entry = match libc::readdir(&mut self.inner) {
                Ok(Some(entry)) => entry,
                Ok(None) => return None,
                Err(errno) => return Some(Err(errno.into())),
            };

            let name = entry.name().to_bytes();
            if name != b"." && name != b".." {
                match GraphId::decode(name) {
                    Ok(graph_id) => return Some(Ok(graph_id)),
                    Err(err) => {
                        warn!(
                            "Filename {:?} is not a valid GraphId: {}",
                            entry.name(),
                            err
                        );
                    }
                }
            }
        }
    }
}

/// A file-backed implementation of [`IoManager`].
#[derive(Debug)]
#[clippy::has_significant_drop]
pub struct FileManager {
    #[cfg_attr(target_os = "vxworks", allow(dead_code))]
    fd: OwnedFd,

    // VxWorks doesn't support `openat`, so we also need to store
    // the path.
    #[cfg(target_os = "vxworks")]
    dir: aranya_libc::PathBuf,
}

impl FileManager {
    /// Creates a `FileManager` at `dir`.
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        let fd = libc::open(dir.as_ref(), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)?;
        Ok(Self {
            fd,
            // TODO(eric): skip the alloc if `P` is `PathBuf`?
            #[cfg(target_os = "vxworks")]
            dir: dir.as_ref().to_path_buf(),
        })
    }

    /// Returns the root.
    #[cfg(target_os = "vxworks")]
    fn root(&self) -> &Path {
        &self.dir
    }

    /// Returns the root.
    #[cfg(not(target_os = "vxworks"))]
    fn root(&self) -> libc::BorrowedFd<'_> {
        libc::AsFd::as_fd(&self.fd)
    }
}

impl IoManager for FileManager {
    type Writer = Writer;

    fn create(&mut self, id: GraphId) -> Result<Self::Writer, StorageError> {
        let name = IdPath::new(id);
        let fd = libc::openat(
            self.root(),
            name,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
        )?;
        libc::flock(&fd, LOCK_EX | LOCK_NB)?;
        // TODO(jdygert): fallocate?
        Writer::create(fd)
    }

    fn open(&mut self, id: GraphId) -> Result<Option<Self::Writer>, StorageError> {
        let name = IdPath::new(id);
        let fd = match libc::openat(self.root(), name, O_RDWR | O_CLOEXEC, 0) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        libc::flock(&fd, LOCK_EX | LOCK_NB)?;
        Ok(Some(Writer::open(fd)?))
    }

    fn remove(&mut self, id: GraphId) -> Result<(), StorageError> {
        let name = IdPath::new(id);
        libc::unlinkat(self.root(), name, 0)?;

        Ok(())
    }

    fn list(
        &mut self,
    ) -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError> {
        GraphIdIterator::new(self.root())
    }
}

/// A file-based writer for linear storage.
#[derive(Debug)]
pub struct Writer {
    file: File,
    root: Root,
    /// End of the region preallocated (and size-extended) via
    /// `fallocate`. Appends stay within this bound so `fdatasync`
    /// doesn't have to flush a file-size change on every commit.
    alloc_end: i64,
    /// Root slot (`ROOT_A`/`ROOT_B`) to write on the next commit.
    /// We ping-pong between the two so the previously committed root
    /// stays intact until the new one is durable.
    next_root: i64,
    /// Whether data has been appended since the last durability
    /// barrier, i.e. whether the next commit must flush data before
    /// writing the root.
    data_dirty: bool,
}

/// An estimated page size for spacing the control data.
const PAGE: i64 = 4096;

// We store 2 roots for redudancy.
/// Offset of the first [`Root`].
const ROOT_A: i64 = PAGE;
/// Offset of the second [`Root`].
const ROOT_B: i64 = PAGE * 2;

/// Starting offset for segment/fact data
const FREE_START: i64 = PAGE * 3;

/// Returns the other root slot, for ping-ponging between the two.
fn other_root(slot: i64) -> i64 {
    if slot == ROOT_A { ROOT_B } else { ROOT_A }
}

/// Granularity by which the file is grown ahead of the write
/// frontier. Preallocating in large chunks keeps the file size
/// stable across appends so `fdatasync` avoids the extra
/// inode-metadata journal commit that a growing file forces.
const PREALLOC_CHUNK: i64 = 4 * 1024 * 1024;

impl Writer {
    fn create(fd: OwnedFd) -> Result<Self, StorageError> {
        let file = File { fd: Arc::new(fd) };
        // Preallocate the control region plus a first data chunk so
        // we can start appending from FREE_START forward without
        // extending the file size on every append.
        let alloc_end = FREE_START
            .checked_add(PREALLOC_CHUNK)
            .assume("initial preallocation fits in `i64`")?;
        file.fallocate(0, alloc_end)?;
        Ok(Self {
            file,
            root: Root::new(),
            alloc_end,
            next_root: ROOT_A,
            data_dirty: false,
        })
    }

    fn open(fd: OwnedFd) -> Result<Self, StorageError> {
        let file = File { fd: Arc::new(fd) };

        // Pick the latest valid root and remember which slot it came
        // from; the next commit writes to the other slot so this one
        // survives until the new root is durable.
        let (root, chosen) = match (
            file.load(ROOT_A).and_then(Root::validate),
            file.load(ROOT_B).and_then(Root::validate),
        ) {
            (Ok(root_a), Ok(root_b)) => match root_a.generation.cmp(&root_b.generation) {
                Ordering::Less => (root_b, ROOT_B),
                Ordering::Equal | Ordering::Greater => (root_a, ROOT_A),
            },
            (Ok(root_a), Err(_)) => (root_a, ROOT_A),
            (Err(_), Ok(root_b)) => (root_b, ROOT_B),
            (Err(e), Err(_)) => return Err(e),
        };

        // Everything up to the write frontier is known to be
        // allocated; `ensure_capacity` grows from here as needed.
        let alloc_end = root.free_offset;

        Ok(Self {
            file,
            root,
            alloc_end,
            next_root: other_root(chosen),
            data_dirty: false,
        })
    }

    /// Grows the preallocated region so it covers `end`, extending
    /// the file size in `PREALLOC_CHUNK` steps. Appends stay inside
    /// this bound so their `fdatasync` doesn't flush a size change.
    fn ensure_capacity(&mut self, end: i64) -> Result<(), StorageError> {
        if end <= self.alloc_end {
            return Ok(());
        }
        let mut new_end = self.alloc_end;
        while new_end < end {
            new_end = new_end
                .checked_add(PREALLOC_CHUNK)
                .assume("preallocation size fits in `i64`")?;
        }
        self.file.fallocate(0, new_end)?;
        self.alloc_end = new_end;
        Ok(())
    }

    fn write_root(&mut self) -> Result<(), StorageError> {
        self.root.generation = self
            .root
            .generation
            .checked_add(1)
            .assume("generation will not overflow u64")?;
        self.root.checksum = self.root.calc_checksum();

        // Write to the inactive slot and flush. The other slot still
        // holds the previously committed root, so a crash mid-write
        // leaves at least one valid root on disk. Ping-pong for next
        // time.
        let slot = self.next_root;
        self.file.dump(slot, &self.root)?;
        self.file.sync()?;
        self.next_root = other_root(slot);

        Ok(())
    }
}

impl Write for Writer {
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
        F: FnOnce(u64) -> T,
        T: Serialize,
    {
        let offset = self.root.free_offset;

        let item = builder(
            offset
                .try_into()
                .assume("`free_offset` can be converted to `u64`")?,
        );
        let bytes = postcard::to_allocvec(&item).map_err(|err| {
            error!(?err, "append");
            StorageError::IoError
        })?;
        // Ensure the file is grown ahead of this write so appending
        // it doesn't change the file size (keeping `fdatasync` cheap).
        let len = i64::try_from(bytes.len()).assume("serialized len fits in `i64`")?;
        let end = offset
            .checked_add(4)
            .and_then(|o| o.checked_add(len))
            .assume("append stays within `i64`")?;
        self.ensure_capacity(end)?;
        let new_offset = self.file.dump_bytes(offset, &bytes)?;

        // The write frontier is advanced in memory only; it is made
        // durable (along with the committed head) by `commit`. Data
        // appended past the last committed `free_offset` is unreachable
        // and safely overwritten after a crash.
        self.root.free_offset = new_offset;
        self.data_dirty = true;

        Ok(item)
    }

    fn commit(&mut self, head: Location) -> Result<(), StorageError> {
        // Barrier 1: ensure the appended data is durable before the
        // root that references it, so a crash can't leave the head
        // pointing at data that never reached disk.
        if self.data_dirty {
            self.file.sync()?;
            self.data_dirty = false;
        }

        // Barrier 2: durably record the new head and write frontier.
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
    free_offset: i64,
    /// Used to ensure root is valid. Write could be interrupted
    /// or corrupted.
    checksum: u64,
}

impl Root {
    fn new() -> Self {
        Self {
            generation: 0,
            head: Location::new(SegmentIndex::new(u64::MAX), MaxCut::new(u64::MAX)),
            free_offset: FREE_START,
            checksum: 0,
        }
    }

    fn calc_checksum(&self) -> u64 {
        let mut hasher = aranya_crypto::dangerous::siphasher::sip::SipHasher::new();
        hasher.write_u64(self.generation);
        hasher.write_u64(self.head.segment.get());
        hasher.write_u64(self.head.max_cut.get());
        hasher.write_i64(self.free_offset);
        hasher.finish()
    }

    fn validate(self) -> Result<Self, StorageError> {
        if self.checksum != self.calc_checksum() {
            tracing::warn!("invalid checksum");
            return Err(StorageError::IoError);
        }
        Ok(self)
    }
}

/// A file-based reader for linear storage.
#[derive(Clone, Debug)]
pub struct Reader {
    file: File,
}

impl Read for Reader {
    fn fetch<T>(&self, offset: u64) -> Result<T, StorageError>
    where
        T: DeserializeOwned,
    {
        let off = i64::try_from(offset).assume("`offset` can be converted to `i64`")?;
        self.file.load(off)
    }
}

#[derive(Clone, Debug)]
struct File {
    fd: Arc<OwnedFd>,
}

impl File {
    fn fallocate(&self, offset: i64, len: i64) -> Result<(), StorageError> {
        libc::fallocate(&self.fd, 0, offset, len)?;
        Ok(())
    }

    fn read_exact(&self, mut offset: i64, mut buf: &mut [u8]) -> Result<(), StorageError> {
        while !buf.is_empty() {
            match libc::pread(&self.fd, buf, offset) {
                Ok(0) => break,
                Ok(n) => {
                    buf = buf.get_mut(n..).assume("`n` should be in bounds")?;
                    offset = offset
                        .checked_add(i64::try_from(n).assume("read within bounds")?)
                        .assume("read within bounds")?;
                }
                Err(Errno::EINTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !buf.is_empty() {
            error!(remaining = buf.len(), "could not fill buffer");
            return Err(StorageError::IoError);
        }
        Ok(())
    }

    fn write_all(&self, mut offset: i64, mut buf: &[u8]) -> Result<(), StorageError> {
        while !buf.is_empty() {
            match libc::pwrite(&self.fd, buf, offset) {
                Ok(0) => {
                    error!(remaining = buf.len(), "could not write whole buffer");
                    return Err(StorageError::IoError);
                }
                Ok(n) => {
                    buf = buf.get(n..).assume("`n` is in bounds")?;
                    offset = offset
                        .checked_add(i64::try_from(n).assume("write within bounds")?)
                        .assume("write within bounds")?;
                }
                Err(Errno::EINTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), StorageError> {
        // `fdatasync` is sufficient for durability here: we only ever need the
        // data and the metadata required to read it back (file size, block
        // mapping), never timestamps. It avoids the extra inode-metadata journal
        // commit that `fsync` forces.
        libc::fdatasync(&self.fd)?;
        Ok(())
    }

    fn dump<T: Serialize>(&self, offset: i64, value: &T) -> Result<i64, StorageError> {
        let bytes = postcard::to_allocvec(value).map_err(|err| {
            error!(?err, "dump");
            StorageError::IoError
        })?;
        self.dump_bytes(offset, &bytes)
    }

    /// Writes an already-serialized value (length prefix + bytes)
    /// at `offset`, returning the offset just past it.
    fn dump_bytes(&self, offset: i64, bytes: &[u8]) -> Result<i64, StorageError> {
        let len: u32 = bytes
            .len()
            .try_into()
            .assume("serialized objects should fit in u32")?;
        self.write_all(offset, &len.to_be_bytes())?;
        let offset2 = offset.checked_add(4).assume("offset not near u64::MAX")?;
        self.write_all(offset2, bytes)?;
        let off = offset2
            .checked_add(len.into())
            .assume("offset valid after write")?;
        Ok(off)
    }

    fn load<T: DeserializeOwned>(&self, offset: i64) -> Result<T, StorageError> {
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
