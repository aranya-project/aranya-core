extern crate alloc;
use alloc::string::String;

use aranya_crypto::policy::CmdId;
use aranya_policy_vm::{CommandContext, MachineError, MachineErrorType, ffi::ffi};

/// Implements 'perspective` FFI module.
///
/// ```text
/// action do_something() {
///   let head_id = perspective::head_id()
/// }```
pub struct FfiPerspective;
#[ffi(module = "perspective")]
impl FfiPerspective {
    /// Returns the ID of the command at the head of the perspective. Only valid for `Action` context.
    #[ffi_export(def = r#"function head_id() id"#)]
    pub(crate) fn head_id<E: aranya_crypto::Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &E,
    ) -> Result<CmdId, MachineError> {
        match ctx {
            CommandContext::Action(actx) => Ok(actx.head_id),
            _ => Err(MachineError::new(MachineErrorType::Unknown(String::from(
                "head_id is only available in Action context",
            )))),
        }
    }
}
