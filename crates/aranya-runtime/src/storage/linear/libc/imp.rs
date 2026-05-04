use alloc::{boxed::Box, sync::Arc};
use core::{cmp::Ordering, hash::Hasher as _, ops::Deref};

use aranya_libc::{
    self as libc, AsAtRoot, Errno, LOCK_EX, LOCK_NB, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL,
    O_RDONLY, O_RDWR, OwnedDir, OwnedFd, Path, S_IRGRP, S_IRUSR, S_IWGRP, S_IWUSR,
};
use buggy::{BugExt as _, bug};
use rkyv::{Archive, Deserialize, Serialize};
use tracing::{error, warn};
use yoke::Yoke;

use super::error::Error;
use crate::{
    GraphId, Location, MaxCut, SegmentIndex, StorageError,
    linear::{
        Readable,
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

impl Writer {
    fn create(fd: OwnedFd) -> Result<Self, StorageError> {
        let file = File { fd: Arc::new(fd) };
        // Preallocate so we can start appending from FREE_START
        // forward.
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
            file.load_root(ROOT_A).and_then(Root::validate),
            file.load_root(ROOT_B).and_then(Root::validate),
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

        // Write roots one at a time, flushing afterward to
        // ensure one is always valid.
        for offset in [ROOT_A, ROOT_B] {
            self.root.checksum = self.root.calc_checksum();
            self.file.dump_root(offset, &self.root)?;
            self.file.sync()?;
        }

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

    fn append<F, T>(&mut self, builder: F) -> Result<Handle<T>, StorageError>
    where
        F: FnOnce(u64) -> T,
        T: Readable
            + for<'a> Serialize<
                rkyv::api::high::HighSerializer<
                    rkyv::util::AlignedVec,
                    rkyv::ser::allocator::ArenaHandle<'a>,
                    rkyv::rancor::Error,
                >,
            >,
    {
        let offset = self.root.free_offset;
        let offset_u64 = u64::try_from(offset).assume("free_offset can be converted to u64")?;

        let item = builder(offset_u64);
        let new_offset = self.file.dump(offset, &item)?;

        self.root.free_offset = new_offset;
        self.write_root()?;

        self.readonly().fetch(offset_u64)
    }

    fn commit(&mut self, head: Location) -> Result<(), StorageError> {
        self.root.head = head;
        self.write_root()?;
        Ok(())
    }
}

/// Section of control data for the file
#[derive(Debug, Archive, Serialize, Deserialize)]
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
            head: Location::new(SegmentIndex(u64::MAX), MaxCut(u64::MAX)),
            free_offset: FREE_START,
            checksum: 0,
        }
    }

    fn calc_checksum(&self) -> u64 {
        let mut hasher = aranya_crypto::dangerous::siphasher::sip::SipHasher::new();
        hasher.write_u64(self.generation);
        hasher.write_u64(self.head.segment.0);
        hasher.write_u64(self.head.max_cut.0);
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
    type Handle<T: Readable> = Handle<T>;

    fn fetch<T: Readable>(&self, offset: u64) -> Result<Handle<T>, StorageError> {
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
        libc::fsync(&self.fd)?;
        Ok(())
    }

    fn dump_root(&self, offset: i64, root: &Root) -> Result<(), StorageError> {
        const SIZE: usize = size_of::<ArchivedRoot>();
        let mut buf = [0u8; SIZE];
        let mut writer = rkyv::ser::writer::Buffer::from(buf.as_mut_slice());
        rkyv::api::serialize_using::<_, rkyv::rancor::Failure>(root, &mut writer)
            .assume("can serialize root")?;
        self.write_all(offset, &writer)
    }

    // TODO(jdygert): tests don't cover this.
    fn load_root(&self, offset: i64) -> Result<Root, StorageError> {
        const SIZE: usize = size_of::<ArchivedRoot>();
        let mut bytes = [0u8; SIZE];
        self.read_exact(offset, &mut bytes)?;
        rkyv::api::low::from_bytes(&bytes).map_err(|err: rkyv::rancor::Error| {
            error!(?err, "load_root");
            StorageError::IoError
        })
    }

    fn dump<T>(&self, offset: i64, value: &T) -> Result<i64, StorageError>
    where
        T: for<'a> Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
    {
        let bytes = rkyv::to_bytes(value).map_err(|err| {
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
        let off = offset2
            .checked_add(len.into())
            .assume("offset valid after write")?;
        Ok(off)
    }

    fn load<T: Readable>(&self, offset: i64) -> Result<Handle<T>, StorageError> {
        let mut bytes = [0u8; 4];
        self.read_exact(offset, &mut bytes)?;
        let len = u32::from_be_bytes(bytes);
        let mut bytes = alloc::vec![0u8; len as usize];
        self.read_exact(
            offset.checked_add(4).assume("offset not near u64::MAX")?,
            &mut bytes,
        )?;
        T::yoke(bytes.into_boxed_slice()).map(Handle)
    }
}

/// Handle wrapper around a loaded object.
pub struct Handle<T: Readable>(Yoke<&'static T::Archived, Box<[u8]>>);

impl<T: Readable> Deref for Handle<T> {
    type Target = T::Archived;
    fn deref(&self) -> &Self::Target {
        self.0.get()
    }
}
