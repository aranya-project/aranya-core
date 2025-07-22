//! The `device` FFI module.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

mod tests;

use core::convert::Infallible;

use aranya_crypto::DeviceId;
use aranya_policy_vm::{CommandContext, ffi::ffi};

/// Implements the FFI `Device` module
pub struct FfiDevice {
    id: DeviceId,
}

#[ffi(module = "device")]
impl FfiDevice {
    /// Returns the current device's DeviceId
    #[ffi_export(def = r#"function current_device_id() id"#)]
    pub(crate) fn current_device_id<E: aranya_crypto::Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &mut E,
    ) -> Result<DeviceId, Infallible> {
        Ok(self.id)
    }
}

impl FfiDevice {
    /// Constructor for FfiDevice that initializes it with a DeviceId
    pub const fn new(id: DeviceId) -> Self {
        FfiDevice { id }
    }
}
