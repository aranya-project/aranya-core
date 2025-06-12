//! IO interfaces for linear storage.
//!
//! It is expected that each "file" is only opened by one storage at a time,
//! especially for write operations. If this is not ensured by the
//! implementation (e.g. `flock(LOCK_EX)`) then the user must ensure this. For
//! example, accidentally running two instances of the program will cause
//! issues.

use serde::{de::DeserializeOwned, Serialize};

use crate::{GraphId, Location, StorageError};

/// IO manager for creating and opening writers for a graph.
pub trait IoManager {
    type Writer: Write;
    /// Create new writer for the graph ID. Should error if already exists.
    fn create(&mut self, id: GraphId) -> Result<Self::Writer, StorageError>;
    /// Open existing writer for the graph ID.
    fn open(&mut self, id: GraphId) -> Result<Option<Self::Writer>, StorageError>;
    /// Remove storage for a Graph Id.
    fn remove(&mut self, id: GraphId) -> Result<(), StorageError>;
    /// List all existing graph IDs.
    fn list(&mut self)
        -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError>;
}

/// Exclusive writer for a linear storage graph.
pub trait Write {
    /// A `Read`er for this writer's shared data.
    type ReadOnly: Read;
    /// Get a [`Read`]er for this writer's shared data.
    fn readonly(&self) -> Self::ReadOnly;

    /// Get the commit head.
    fn head(&self) -> Result<Location, StorageError>;

    /// Append an item (e.g. segment or fact-index) onto the writer.
    ///
    /// A function is used to allow the item to contain its offset.
    fn append<F, T>(&mut self, builder: F) -> Result<T, StorageError>
    where
        F: FnOnce(usize) -> T,
        T: Serialize;

    /// Set the commit head.
    fn commit(&mut self, head: Location) -> Result<(), StorageError>;
}

/// A share-able reader for a linear storage graph.
pub trait Read: Clone {
    /// Fetch an item written by `Write::append`.
    fn fetch<T>(&self, offset: usize) -> Result<T, StorageError>
    where
        T: DeserializeOwned;
}
