//! IO interfaces for linear storage.
//!
//! It is expected that each "file" is only opened by one storage at a time,
//! especially for write operations. If this is not ensured by the
//! implementation (e.g. `flock(LOCK_EX)`) then the user must ensure this. For
//! example, accidentally running two instances of the program will cause
//! issues.

use serde::{Serialize, de::DeserializeOwned};

use crate::{GraphId, StorageError, storage::HeadSet};

/// IO manager for creating and opening writers for a graph.
pub trait IoManager {
    type Writer: Write;
    /// Create new writer for the graph ID. Should error if already exists.
    fn create(&mut self, id: GraphId) -> Result<Self::Writer, StorageError>;
    /// Open existing writer for the graph ID.
    fn open(&mut self, id: GraphId) -> Result<Option<Self::Writer>, StorageError>;
    /// Remove storage for a graph ID.
    fn remove(&mut self, id: GraphId) -> Result<(), StorageError>;
    /// List all existing graph IDs.
    fn list(&mut self)
    -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError>;
}

/// File offset of the committed fact cache (a merged fact index written via
/// [`Write::append`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FactCacheOffset(u64);

impl FactCacheOffset {
    /// Wraps a raw offset produced by [`Write::append`].
    pub fn new(offset: u64) -> Self {
        Self(offset)
    }

    /// The raw file offset.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Exclusive writer for a linear storage graph.
pub trait Write {
    /// A `Read`er for this writer's shared data.
    type ReadOnly: Read;
    /// Get a [`Read`]er for this writer's shared data.
    fn readonly(&self) -> Self::ReadOnly;

    /// Get the committed head set.
    fn heads(&self) -> Result<HeadSet, StorageError>;

    /// Get the file offset of the cached merged fact index.
    fn fact_cache(&self) -> Result<FactCacheOffset, StorageError>;

    /// Append an item (e.g. segment or fact-index) onto the writer.
    ///
    /// A function is used to allow the item to contain its offset.
    fn append<F, T>(&mut self, builder: F) -> Result<T, StorageError>
    where
        F: FnOnce(u64) -> T,
        T: Serialize;

    /// Commit the head set and fact-cache offset atomically.
    fn commit(&mut self, heads: &HeadSet, fact_cache: FactCacheOffset) -> Result<(), StorageError>;
}

/// A share-able reader for a linear storage graph.
pub trait Read: Clone {
    /// Fetch an item written by `Write::append`.
    fn fetch<T>(&self, offset: u64) -> Result<T, StorageError>
    where
        T: DeserializeOwned;
}
