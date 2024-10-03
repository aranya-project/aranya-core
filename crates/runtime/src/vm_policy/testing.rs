#![cfg(feature = "testing")]

use alloc::vec::Vec;
use core::convert::Infallible;

use buggy::{bug, BugExt};
use crypto::UserId;
use policy_vm::{ffi::ffi, CommandContext, MachineError};

use crate::CommandId;

pub struct TestFfiEnvelope {
    pub user: UserId,
}

#[ffi(
    module = "envelope",
    def = r#"
struct Envelope {
    // The parent command ID.
    parent_id id,
    // The author's user ID.
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
    #[ffi_export(def = "function seal(payload bytes) struct Envelope")]
    fn seal<E>(
        &self,
        ctx: &CommandContext<'_>,
        _eng: &mut E,
        payload: Vec<u8>,
    ) -> Result<Envelope, MachineError> {
        #[derive(serde::Serialize)]
        struct HashedFields<'a> {
            parent_id: CommandId,
            author_id: UserId,
            payload: &'a [u8],
        }

        let CommandContext::Seal(ctx) = ctx else {
            bug!("envelope::seal called outside seal context");
        };

        let parent_id = ctx.head_id.into();
        let author_id = self.user;

        let data = postcard::to_allocvec(&HashedFields {
            parent_id,
            author_id,
            payload: &payload,
        })
        .assume("can serialize `HashedFields`")?;

        let command_id = CommandId::hash_for_testing_only(&data);

        Ok(Envelope {
            parent_id: parent_id.into(),
            author_id: author_id.into(),
            command_id: command_id.into(),
            payload,
            // TODO(chip): use an actual signature
            signature: b"LOL".to_vec(),
        })
    }

    #[ffi_export(def = "function open(envelope_input struct Envelope) bytes")]
    fn open<E>(
        &self,
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
        envelope_input: Envelope,
    ) -> Result<Vec<u8>, Infallible> {
        Ok(envelope_input.payload)
    }
}
