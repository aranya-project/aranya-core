use aranya_crypto::Id;
use aranya_policy_ast::Identifier;
use aranya_policy_module::{FactKey, FactKeyList, FactValue, FactValueList, KVPair};
use buggy::Bug;

use super::Stack;
use crate::{
    error::{MachineError, MachineErrorType},
    CommandContext,
};

/// An I/O error.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum MachineIOError {
    /// Attempted to create a fact that already exists
    #[error("fact exists")]
    FactExists,
    /// Attempt to access a fact that does not exist)
    #[error("fact not found")]
    FactNotFound,
    /// Some internal operation has failed
    #[error("internal error")]
    Internal,
    /// Bug
    #[error("bug: {0}")]
    Bug(Bug),
}

impl From<MachineIOError> for MachineError {
    fn from(value: MachineIOError) -> Self {
        MachineError::new(MachineErrorType::IO(value))
    }
}

impl From<Bug> for MachineIOError {
    fn from(bug: Bug) -> Self {
        Self::Bug(bug)
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
        name: Identifier,
        key: impl IntoIterator<Item = FactKey>,
        value: impl IntoIterator<Item = FactValue>,
    ) -> Result<(), MachineIOError>;

    /// Delete a fact
    fn fact_delete(
        &mut self,
        name: Identifier,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError>;

    /// Query a fact
    fn fact_query(
        &self,
        name: Identifier,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator, MachineIOError>;

    /// Publish a command
    fn publish(&mut self, name: Identifier, fields: impl IntoIterator<Item = KVPair>);

    /// Create an effect
    fn effect(
        &mut self,
        name: Identifier,
        fields: impl IntoIterator<Item = KVPair>,
        command: Id,
        recalled: bool,
    );

    /// Call external function, e.g., one defined in an `FfiModule`.
    fn call(
        &self,
        module: usize,
        procedure: usize,
        stack: &mut S,
        ctx: &CommandContext<'_>,
    ) -> Result<(), MachineError>;
}
