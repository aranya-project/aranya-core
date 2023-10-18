use super::{data::CommandContext, MachineError, Stack};
use crate::lang::ast::FfiFunctionDefinition;

/// Foreign Function Interface to allow the policy VM to call external functions.
pub trait FfiModule<S>
where
    S: Stack,
{
    type Error: Into<MachineError>;

    /// Returns list of function definitions. Used by the compiler to emit the stack instructions needed for a call.
    fn function_table(&self) -> Vec<FfiFunctionDefinition>;

    /// Invokes a function in the module.
    /// `procedure` is the index in [`function_table`][Self::function_table].
    fn call(
        &self,
        procedure: usize,
        stack: &mut S,
        ctx: Option<CommandContext>,
    ) -> Result<(), Self::Error>;
}
