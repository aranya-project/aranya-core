#![cfg(feature = "testing")]

use alloc::vec::Vec;
use core::convert::Infallible;

use aranya_crypto::{DeviceId, policy::CmdId};
use aranya_policy_vm::{CommandContext, MachineError, ffi::ffi};
use buggy::{BugExt as _, bug};

use crate::testing::hash_for_testing_only;

pub struct TestFfiEnvelope {
    pub device: DeviceId,
}

#[ffi(
    module = "envelope",
    def = r#"
struct Envelope {
    // The parent command ID.
    parent_id id,
    // The author's device ID.
    author_id id,
    // Uniquely identifies the command.
    command_id id,
    // The encoded command.
    payload bytes,
    // The signature over the command and its contextual
    // bindings.
    signature bytes,
}
"#
)]
impl TestFfiEnvelope {
    #[ffi_export(def = "function do_seal(payload bytes) struct Envelope")]
    fn seal<CE>(
        &self,
        ctx: &CommandContext,
        _eng: &CE,
        payload: Vec<u8>,
    ) -> Result<Envelope, MachineError> {
        #[derive(serde::Serialize)]
        struct HashedFields<'a> {
            parent_id: CmdId,
            author_id: DeviceId,
            payload: &'a [u8],
        }

        let CommandContext::Seal(ctx) = ctx else {
            bug!("envelope::do_seal called outside seal context");
        };

        let parent_id = ctx.head_id;
        let author_id = self.device;

        let data = postcard::to_allocvec(&HashedFields {
            parent_id,
            author_id,
            payload: &payload,
        })
        .assume("can serialize `HashedFields`")?;

        let command_id = hash_for_testing_only(&data);

        Ok(Envelope {
            parent_id: parent_id.as_base(),
            author_id: author_id.as_base(),
            command_id: command_id.as_base(),
            payload,
            // TODO(chip): use an actual signature
            signature: b"LOL".to_vec(),
        })
    }

    #[ffi_export(def = "function do_open(envelope_input struct Envelope) bytes")]
    fn open<CE>(
        &self,
        _ctx: &CommandContext,
        _eng: &CE,
        envelope_input: Envelope,
    ) -> Result<Vec<u8>, Infallible> {
        Ok(envelope_input.payload)
    }
}
