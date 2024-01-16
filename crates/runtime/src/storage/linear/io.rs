//! IO interfaces for linear storage.
//!
//! It is expected that each "file" is only opened by one storage at a time,
//! especially for write operations. If this is not ensured by the
//! implementation (e.g. `flock(LOCK_EX)`) then the user must ensure this. For
//! example, accidentally running two instances of the program will cause
//! issues.

use buggy::BugExt;
use serde::{de::DeserializeOwned, Serialize};

use crate::{Id, StorageError};

pub trait FileManager {
    type File: Write;
    /// Create new file for the id. Should error if already exists.
    fn create(&mut self, id: Id) -> Result<Self::File, StorageError>;
    /// Open existing file for the id.
    fn open(&mut self, id: Id) -> Result<Option<Self::File>, StorageError>;
}

pub trait Write {
    type ReadOnly: Read;
    fn readonly(&self) -> Self::ReadOnly;

    fn write_all(&mut self, offset: u64, buf: &[u8]) -> Result<(), StorageError>;
    fn sync(&mut self) -> Result<(), StorageError>;

    fn dump<T: Serialize>(&mut self, offset: u64, value: &T) -> Result<u64, StorageError> {
        let bytes = postcard::to_allocvec(value).map_err(|_| StorageError::IoError)?;
        let len: u32 = bytes
            .len()
            .try_into()
            .assume("serialized objects should fit in u32")?;
        self.write_all(offset, &len.to_be_bytes())?;
        let offset2 = offset.checked_add(4).assume("offset not near u64::MAX")?;
        self.write_all(offset2, &bytes)?;
        Ok(offset2
            .checked_add(u64::from(len))
            .assume("offset valid after write")?)
    }
}

pub trait Read: Clone {
    fn read_exact(&self, offset: u64, buf: &mut [u8]) -> Result<(), StorageError>;

    fn load<T: DeserializeOwned>(&self, offset: u64) -> Result<T, StorageError> {
        let mut bytes = [0u8; 4];
        self.read_exact(offset, &mut bytes)?;
        let len = u32::from_be_bytes(bytes);
        let mut bytes = alloc::vec![0u8; len as usize];
        self.read_exact(
            offset.checked_add(4).assume("offset not near u64::MAX")?,
            &mut bytes,
        )?;
        postcard::from_bytes(&bytes).map_err(|_| StorageError::IoError)
    }
}
