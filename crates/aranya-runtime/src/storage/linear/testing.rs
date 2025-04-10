use alloc::{boxed::Box, sync::Arc, vec::Vec};

use buggy::BugExt;
use spin::mutex::Mutex;

use super::io;
use crate::{GraphId, Location, StorageError};

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

    fn list(&self) -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError> {
        Ok(self.graph_ids.iter().copied().map(Ok))
    }
}

#[derive(Default)]
struct Shared {
    items: Mutex<Vec<Box<[u8]>>>,
}

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
            shared: self.shared.clone(),
        }
    }

    fn head(&self) -> Result<Location, StorageError> {
        let head = *self.head.lock();
        Ok(head.assume("head exists")?)
    }

    fn append<F, T>(&mut self, builder: F) -> Result<T, StorageError>
    where
        F: FnOnce(usize) -> T,
        T: serde::Serialize,
    {
        let offset = self.shared.items.lock().len();
        let item = builder(offset);
        let bytes = postcard::to_allocvec(&item)
            .map_err(|_| StorageError::IoError)?
            .into_boxed_slice();
        self.shared.items.lock().push(bytes);
        Ok(item)
    }

    fn commit(&mut self, head: Location) -> Result<(), StorageError> {
        *self.head.lock() = Some(head);
        Ok(())
    }
}

impl io::Read for Reader {
    fn fetch<T>(&self, offset: usize) -> Result<T, StorageError>
    where
        T: serde::de::DeserializeOwned,
    {
        let items = self.shared.items.lock();
        let bytes = items
            .get(offset)
            .ok_or(StorageError::SegmentOutOfBounds(Location::new(offset, 0)))?;
        postcard::from_bytes(bytes).map_err(|_| StorageError::IoError)
    }
}
