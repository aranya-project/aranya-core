use core::convert::Infallible;

use crypto::Id;
use policy_vm::{ffi::ffi, CommandContext};

/// Implements 'perspective` FFI module
///
/// ```text
/// command Foo {
///   policy {
///     let parent_id = perspective::head_id()
///   }
/// }```
pub struct FfiPerspective;

#[ffi(module = "perspective")]
impl FfiPerspective {
    #[ffi_export(def = r#"function head_id() id"#)]
    pub(crate) fn head_id<E: crypto::Engine + ?Sized>(
        &mut self,
        ctx: &CommandContext<'_>,
        _eng: &mut E,
    ) -> Result<Id, Infallible> {
        match ctx {
            CommandContext::Action(actx) => Ok(actx.head_id),
            CommandContext::Seal(sctx) => Ok(sctx.parent_id),
            CommandContext::Open(octx) => Ok(octx.parent_id),
            CommandContext::Policy(pctx) => Ok(pctx.parent_id),
            CommandContext::Recall(pctx) => Ok(pctx.parent_id),
        }
    }
}
