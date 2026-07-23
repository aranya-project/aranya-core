use alloc::{boxed::Box, sync::Arc, vec::Vec};

use spin::mutex::Mutex;

use super::io;
use crate::{GraphId, Location, MaxCut, SegmentIndex, StorageError, storage::HeadSet};

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
            committed: Mutex::default(),
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
    items: Mutex<Vec<Box<[u8]>>>,
}

#[derive(Clone)]
struct Committed {
    heads: HeadSet,
    fact_cache: io::FactCacheOffset,
}

pub struct Writer {
    committed: Mutex<Option<Committed>>,
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

    fn heads(&self) -> Result<HeadSet, StorageError> {
        self.committed
            .lock()
            .as_ref()
            .map(|c| c.heads.clone())
            .ok_or(StorageError::NotInitialized)
    }

    fn fact_cache(&self) -> Result<io::FactCacheOffset, StorageError> {
        self.committed
            .lock()
            .as_ref()
            .map(|c| c.fact_cache)
            .ok_or(StorageError::NotInitialized)
    }

    fn append<F, T>(&mut self, builder: F) -> Result<T, StorageError>
    where
        F: FnOnce(u64) -> T,
        T: serde::Serialize,
    {
        let offset = self.shared.items.lock().len() as u64;
        let item = builder(offset);
        let bytes = postcard::to_allocvec(&item)
            .map_err(|_| StorageError::IoError)?
            .into_boxed_slice();
        self.shared.items.lock().push(bytes);
        Ok(item)
    }

    fn commit(
        &mut self,
        heads: &HeadSet,
        fact_cache: io::FactCacheOffset,
    ) -> Result<(), StorageError> {
        *self.committed.lock() = Some(Committed {
            heads: heads.clone(),
            fact_cache,
        });
        Ok(())
    }
}

impl io::Read for Reader {
    fn fetch<T>(&self, offset: u64) -> Result<T, StorageError>
    where
        T: serde::de::DeserializeOwned,
    {
        let items = self.shared.items.lock();
        let bytes = usize::try_from(offset)
            .ok()
            .and_then(|offset| items.get(offset))
            .ok_or(StorageError::SegmentOutOfBounds(Location::new(
                SegmentIndex::new(offset),
                MaxCut::new(u64::MAX), // Not right but this is just for testing...
            )))?;
        postcard::from_bytes(bytes).map_err(|_| StorageError::IoError)
    }
}
