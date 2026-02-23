use alloc::{format, string::String};

use crate::{policy::PolicyError, storage::StorageError};

#[derive(Debug, thiserror::Error)]
/// Errors that can occur because of creation or use of VmPolicy.
pub enum VmPolicyError {
    /// An error happened while deserializing a command struct. Stores an interior
    /// [postcard::Error].
    #[error("deserialize error: {0}")]
    Deserialization(#[from] postcard::Error),
    /// An error happened while executing policy. Stores an interior [PolicyError].
    #[error("policy error: {0}")]
    PolicyError(#[from] PolicyError),
    /// An error happened at the storage layer. Stores an interior [StorageError].
    #[error("storage error: {0}")]
    StorageError(#[from] StorageError),
    /// An error happened when parsing command attributes.
    #[error("atribute error: {0}")]
    Attribute(#[from] AttributeError),
    /// Some other happened and we don't know what it is.
    #[error("unknown error")]
    Unknown,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct AttributeError(pub(crate) String);

impl AttributeError {
    pub(crate) fn type_mismatch(cmd: &str, attr: &str, expected: &str, actual: &str) -> Self {
        Self(format!("{cmd}::{attr} should be {expected}, was {actual}"))
    }

    pub(crate) fn exclusive(cmd: &str, attr1: &str, attr2: &str) -> Self {
        Self(format!(
            "{cmd} has both exclusive attributes {attr1} and {attr2}"
        ))
    }

    pub(crate) fn int_range(cmd: &str, attr: &str, min: i64, max: i64) -> Self {
        Self(format!("{cmd}::{attr} must be within [{min}, {max}]"))
    }

    pub(crate) fn missing(cmd: &str, attrs: &str) -> Self {
        Self(format!("{cmd} is missing {attrs}"))
    }
}
