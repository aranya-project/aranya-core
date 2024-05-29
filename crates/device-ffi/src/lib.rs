//! The `device` FFI module.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

mod tests;

use core::convert::Infallible;

use crypto::UserId;
use policy_vm::{ffi::ffi, CommandContext};

/// Implements the FFI `Device` module
pub struct FfiDevice {
    id: UserId,
}

#[ffi(module = "device")]
impl FfiDevice {
    /// Returns the current user's UserId
    #[ffi_export(def = r#"function current_user_id() id"#)]
    pub(crate) fn current_user_id<E: crypto::Engine>(
        &self,
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
    ) -> Result<UserId, Infallible> {
        Ok(self.id)
    }
}

impl FfiDevice {
    /// Constructor for FfiDevice that initializes it with a UserId
    pub const fn new(id: UserId) -> Self {
        FfiDevice { id }
    }
}
