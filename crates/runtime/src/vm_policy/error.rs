use core::fmt;

use crate::{engine::EngineError, storage::StorageError};

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

impl fmt::Display for VmPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deserialization(e) => write!(f, "deserialize error: {e}"),
            Self::EngineError(e) => write!(f, "engine error: {e}"),
            Self::StorageError(e) => write!(f, "storage error: {e}"),
            Self::Unknown => write!(f, "unknown error"),
        }
    }
}

impl trouble::Error for VmPolicyError {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        match self {
            Self::EngineError(e) => Some(e),
            Self::StorageError(e) => Some(e),
            _ => None,
        }
    }
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
