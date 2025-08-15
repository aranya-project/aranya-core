extern crate alloc;
use alloc::string::String;

use aranya_crypto::policy::CmdId;
use aranya_policy_vm::{CommandContext, MachineError, MachineErrorType, ffi::ffi};

/// Implements 'perspective` FFI module.
///
/// ```text
/// command Foo {
///     seal {
///       let head_id = perspective::head_id()
///     }
/// }
///
/// action do_something() {
///   let head_id = perspective::head_id()
/// }```
pub struct FfiPerspective;
#[ffi(module = "perspective")]
impl FfiPerspective {
    /// Returns the ID of the command at the head of the perspective. Only valid for `Seal` and `Action` contexts.
    #[ffi_export(def = r#"function head_id() id"#)]
    pub(crate) fn head_id<E: aranya_crypto::Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &mut E,
    ) -> Result<CmdId, MachineError> {
        match ctx {
            CommandContext::Action(actx) => Ok(actx.head_id),
            CommandContext::Seal(sctx) => Ok(sctx.head_id),
            _ => Err(MachineError::new(MachineErrorType::Unknown(String::from(
                "head_id is only available in Seal and Action contexts",
            )))),
        }
    }
}
