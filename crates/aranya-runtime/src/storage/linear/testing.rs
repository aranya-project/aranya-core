use alloc::{sync::Arc, vec::Vec};
use core::{ops::Deref, ptr};

use buggy::BugExt as _;
use rkyv::util::AlignedVec;
use spin::mutex::Mutex;
use stable_deref_trait::StableDeref;
use yoke::Yoke;

use super::{Read, Readable, io};
use crate::{GraphId, Location, MaxCut, SegmentIndex, StorageError};

/// Alias for memory-backed storage provider commonly used in tests.
pub type MemStorageProvider = super::LinearStorageProvider<Manager>;

#[derive(Default)]
pub struct Manager {
    graph_ids: Vec<GraphId>,
}

impl Manager {
    pub fn new() -> Self {
        Self {
            graph_ids: Vec::new(),
        }
    }
}

impl io::IoManager for Manager {
    type Writer = Writer;

    fn create(&mut self, id: GraphId) -> Result<Self::Writer, StorageError> {
        self.graph_ids.push(id);
        Ok(Writer {
            head: Mutex::default(),
            shared: Arc::default(),
        })
    }

    fn open(&mut self, _id: GraphId) -> Result<Option<Self::Writer>, StorageError> {
        Ok(None)
    }

    fn remove(&mut self, _id: GraphId) -> Result<(), StorageError> {
        Ok(())
    }

    fn list(
        &mut self,
    ) -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError> {
        Ok(self.graph_ids.iter().copied().map(Ok))
    }
}

#[derive(Default)]
struct Shared {
    // invariant: push-only
    items: Mutex<Vec<AlignedVec>>,
}

impl Shared {
    fn get(self: &Arc<Self>, idx: usize) -> Option<SharedItem> {
        let item = ptr::from_ref(self.items.lock().get(idx)?.as_slice());
        Some(SharedItem {
            _backing: Arc::clone(self),
            item,
        })
    }
}

struct SharedItem {
    _backing: Arc<Shared>,
    // Points into an `AlignedVec` within `_backing`.
    item: *const [u8],
}

impl Deref for SharedItem {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: `Shared.items` is push-only and `AlignedVec` is stable-deref,
        // so this pointer is valid as long as _backing is held.
        unsafe { &*self.item }
    }
}

// SAFETY: `deref` doesn't rely on location of the shared item.
unsafe impl StableDeref for SharedItem {}

pub struct Writer {
    head: Mutex<Option<Location>>,
    shared: Arc<Shared>,
}

#[derive(Clone)]
pub struct Reader {
    shared: Arc<Shared>,
}

impl io::Write for Writer {
    type ReadOnly = Reader;

    fn readonly(&self) -> Self::ReadOnly {
        Reader {
            shared: Arc::clone(&self.shared),
        }
    }

    fn head(&self) -> Result<Location, StorageError> {
        let head = *self.head.lock();
        Ok(head.assume("head exists")?)
    }

    fn append<F, T>(&mut self, builder: F) -> Result<Handle<T>, StorageError>
    where
        F: FnOnce(u64) -> T,
        T: Readable
            + for<'a> rkyv::Serialize<
                rkyv::api::high::HighSerializer<
                    AlignedVec,
                    rkyv::ser::allocator::ArenaHandle<'a>,
                    rkyv::rancor::Error,
                >,
            >,
    {
        let offset = self.shared.items.lock().len() as u64;
        let item = builder(offset);
        let bytes = rkyv::to_bytes(&item).map_err(|_| StorageError::IoError)?;
        self.shared.items.lock().push(bytes);
        self.readonly().fetch(offset)
    }

    fn commit(&mut self, head: Location) -> Result<(), StorageError> {
        *self.head.lock() = Some(head);
        Ok(())
    }
}

impl Read for Reader {
    type Handle<T: Readable> = Handle<T>;

    fn fetch<T: Readable>(&self, offset: u64) -> Result<Handle<T>, StorageError> {
        let bytes = self
            .shared
            .get(offset as usize)
            .ok_or(StorageError::SegmentOutOfBounds(Location::new(
                SegmentIndex(offset),
                MaxCut(u64::MAX), // Not right but this is just for testing...
            )))?;

        T::yoke(bytes).map(Handle)
    }
}

pub struct Handle<T: Readable>(Yoke<&'static T::Archived, SharedItem>);

impl<T: Readable> Deref for Handle<T> {
    type Target = T::Archived;
    fn deref(&self) -> &Self::Target {
        self.0.get()
    }
}
