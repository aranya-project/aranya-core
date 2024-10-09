//! The VM's foreign function interface.

use aranya_crypto::Engine;
pub use aranya_policy_module::ffi::*;

#[cfg(feature = "derive")]
pub use crate::derive::*;
use crate::{CommandContext, MachineError, Stack};

/// Foreign Function Interface to allow the policy VM to call external functions.
pub trait FfiModule {
    /// The error result from [`FfiModule::call`].
    type Error: Into<MachineError>;

    /// A list of function definitions. Used by the
    /// compiler to emit the stack instructions needed for
    /// a call.
    const SCHEMA: ModuleSchema<'static>;

    /// Invokes a function in the module.
    /// `procedure` is the index in [`functions`][Self::SCHEMA].
    fn call<E: Engine>(
        &mut self,
        procedure: usize,
        stack: &mut impl Stack,
        ctx: &CommandContext<'_>,
        eng: &mut E,
    ) -> Result<(), Self::Error>;
}
