use core::fmt;

use cfg_if::cfg_if;

use super::Stack;
use crate::machine::data::{FactKey, FactKeyList, FactValue, FactValueList, KVPair};
use crate::machine::error::{MachineError, MachineErrorType};

cfg_if! {
    if #[cfg(feature = "std")] {
        use std::error;
    } else if #[cfg(feature = "error_in_core")] {
        use core::error;
    }
}

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

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for MachineIOError {}

impl From<MachineIOError> for MachineError {
    fn from(value: MachineIOError) -> Self {
        MachineError::new(MachineErrorType::IO(value))
    }
}

pub trait MachineIO<S>
where
    S: Stack,
{
    type QueryIterator: Iterator<Item = (FactKeyList, FactValueList)>;

    // Insert a fact
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

    /// Emit a command
    fn emit(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>);

    /// Create an effect
    fn effect(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>);

    /// Call external function, i.e. one defined in a FFIModule
    fn call(&self, module: usize, procedure: usize, stack: &mut S) -> Result<(), MachineError>;
}
