extern crate alloc;

use alloc::string::String;
use core::fmt;

use aranya_crypto::Id;
use aranya_policy_module::{FactKey, FactKeyList, FactValue, FactValueList, KVPair};

use super::Stack;
use crate::{
    error::{MachineError, MachineErrorType},
    CommandContext,
};

/// An I/O error.
#[derive(Debug, Eq, PartialEq)]
pub enum MachineIOError {
    /// Attempted to create a fact that already exists
    FactExists,
    /// Attempt to access a fact that does not exist)
    FactNotFound,
    /// Some internal operation has failed
    Internal,
}

impl fmt::Display for MachineIOError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachineIOError::FactExists => write!(f, "Fact exists"),
            MachineIOError::FactNotFound => write!(f, "Fact not found"),
            MachineIOError::Internal => write!(f, "Internal error"),
        }
    }
}

impl core::error::Error for MachineIOError {}

impl From<MachineIOError> for MachineError {
    fn from(value: MachineIOError) -> Self {
        MachineError::new(MachineErrorType::IO(value))
    }
}

/// The part of a `Machine` that performs I/O.
pub trait MachineIO<S>
where
    S: Stack,
{
    /// Iterates over the results of a fact query.
    type QueryIterator: Iterator<Item = Result<(FactKeyList, FactValueList), MachineIOError>>;

    /// Insert a fact
    fn fact_insert(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
        value: impl IntoIterator<Item = FactValue>,
    ) -> Result<(), MachineIOError>;

    /// Delete a fact
    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError>;

    /// Query a fact
    fn fact_query(
        &self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator, MachineIOError>;

    /// Publish a command
    fn publish(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>);

    /// Create an effect
    fn effect(
        &mut self,
        name: String,
        fields: impl IntoIterator<Item = KVPair>,
        command: Id,
        recalled: bool,
    );

    /// Call external function, e.g., one defined in an `FfiModule`.
    fn call(
        &mut self,
        module: usize,
        procedure: usize,
        stack: &mut S,
        ctx: &CommandContext<'_>,
    ) -> Result<(), MachineError>;
}
