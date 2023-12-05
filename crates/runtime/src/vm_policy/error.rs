use crate::{engine::EngineError, storage::StorageError};

#[allow(dead_code)]
#[derive(Debug)]
/// Errors that can occur because of creation or use of VmPolicy.
pub enum VmPolicyError {
    /// An error happened while deserializing a command struct. Stores an interior
    /// [postcard::Error].
    Deserialization(postcard::Error),
    /// An error happened while executing policy. Stores an interior [EngineError].
    EngineError(EngineError),
    /// An error happened at the storage layer. Stores an interior [StorageError].
    StorageError(StorageError),
    /// Some other happened and we don't know what it is.
    Unknown,
}

impl From<EngineError> for VmPolicyError {
    fn from(value: EngineError) -> Self {
        VmPolicyError::EngineError(value)
    }
}

impl From<StorageError> for VmPolicyError {
    fn from(value: StorageError) -> Self {
        VmPolicyError::StorageError(value)
    }
}
