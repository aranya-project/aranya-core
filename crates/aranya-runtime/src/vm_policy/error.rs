use crate::{engine::EngineError, storage::StorageError};

#[derive(Debug, thiserror::Error)]
/// Errors that can occur because of creation or use of VmPolicy.
pub enum VmPolicyError {
    /// An error happened while deserializing a command struct. Stores an interior
    /// [postcard::Error].
    #[error("deserialize error: {0}")]
    Deserialization(#[from] postcard::Error),
    /// An error happened while executing policy. Stores an interior [EngineError].
    #[error("engine error: {0}")]
    EngineError(#[from] EngineError),
    /// An error happened at the storage layer. Stores an interior [StorageError].
    #[error("storage error: {0}")]
    StorageError(#[from] StorageError),
    /// An error happened when parsing command attributes.
    #[error("invalid atribute: {0}")]
    InvalidAttribute(String),
    /// Some other happened and we don't know what it is.
    #[error("unknown error")]
    Unknown,
}
