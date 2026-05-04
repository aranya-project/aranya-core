//! IO interfaces for linear storage.
//!
//! It is expected that each "file" is only opened by one storage at a time,
//! especially for write operations. If this is not ensured by the
//! implementation (e.g. `flock(LOCK_EX)`) then the user must ensure this. For
//! example, accidentally running two instances of the program will cause
//! issues.

use core::ops::Deref;

use rkyv::{Archive, Serialize, bytecheck::CheckBytes};
use stable_deref_trait::StableDeref;
use yoke::Yoke;

use crate::{GraphId, Location, StorageError};

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
    fn append<F, T>(
        &mut self,
        builder: F,
    ) -> Result<<Self::ReadOnly as Read>::Handle<T>, StorageError>
    where
        F: FnOnce(u64) -> T,
        T: Readable
            + for<'a> Serialize<
                rkyv::api::high::HighSerializer<
                    rkyv::util::AlignedVec,
                    rkyv::ser::allocator::ArenaHandle<'a>,
                    rkyv::rancor::Error,
                >,
            >;

    /// Set the commit head.
    fn commit(&mut self, head: Location) -> Result<(), StorageError>;
}

/// A share-able reader for a linear storage graph.
pub trait Read: Clone {
    type Handle<T: Readable>: Deref<Target = T::Archived>;

    /// Fetch an item written by `Write::append`.
    fn fetch<T: Readable>(&self, offset: u64) -> Result<Self::Handle<T>, StorageError>;
}

/// A type that can be read from archived bytes.
///
/// This is just a convenience over using
/// `Archive<Archived: for<'a> CheckBytes<HighValidator<'a, Error>>> + 'static`
pub trait Readable: Archive + 'static {
    /// Read the archived type from the bytes of `cart` and attach it.
    ///
    /// The returned [`Yoke`] is static but can accessed `&Self::Archived`.
    fn yoke<C>(cart: C) -> Result<Yoke<&'static Self::Archived, C>, StorageError>
    where
        C: StableDeref<Target = [u8]>;
}

impl<T> Readable for T
where
    T: Archive + 'static,
    T::Archived: for<'a> CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>,
{
    fn yoke<C>(cart: C) -> Result<Yoke<&'static Self::Archived, C>, StorageError>
    where
        C: StableDeref<Target = [u8]>,
    {
        Yoke::try_attach_to_cart(cart, |bytes| {
            rkyv::access::<T::Archived, rkyv::rancor::Error>(bytes).map_err(|err| {
                tracing::error!(?err, "rkyv access");
                StorageError::IoError
            })
        })
    }
}
