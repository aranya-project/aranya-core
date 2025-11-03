extern crate alloc;

use alloc::vec::Vec;

use aranya_crypto::{BaseId, DeviceId, engine::Engine, policy::CmdId};
use aranya_policy_vm::{CommandContext, ffi::ffi};

use crate::error::{Error, WrongContext};

/// Implements `envelope-ffi`.
///
/// ```text
/// use crypto
/// use device
/// use envelope
///
/// command Init {
///     seal {
///         let author_id = device::device_id()
///         let author_sign_sk_id = /* TODO */
///         let signed = crypto::sign(
///             author_sign_sk_id,
///             serialize(this),
///         )
///         return envelope::new(
///             author_id,
///             signed.command_id,
///             signed.signature,
///             payload,
///         )
///     }
///
///     open {
///         let author_id = envelope::author_id(envelope)
///         let author_sign_pk = /* TODO */
///         let command = crypto::verify(
///             author_sign_pk,
///             envelope::payload(envelope),
///             envelope::command_id(envelope),
///             envelope::signature(envelope),
///         )
///         return deserialize(command)
///     }
/// }
///
/// command Foo {
///     seal {
///         let author_id = device::device_id()
///         let author_sign_sk_id = unwrap query DeviceSignKey[device_id: author_id]=>{ ... }
///         let signed = crypto::sign(
///             author_sign_sk_id,
///             serialize(this),
///         )
///         return envelope::new(
///             author_id,
///             signed.command_id,
///             signed.signature,
///             payload,
///         )
///     }
///
///     open {
///         let author_id = envelope::author_id(envelope)
///         let author_sign_pk = unwrap query DeviceSignKey[device_id: author_id]=>{ ... }
///         let command = crypto::verify(
///             author_sign_pk,
///             envelope::payload(envelope),
///             envelope::command_id(envelope),
///             envelope::signature(envelope),
///         )
///         return deserialize(command)
///     }
/// }
/// ```
pub struct Ffi;

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
impl Ffi {
    /// Returns the envelope's `parent_id` field.
    #[ffi_export(def = r#"
function parent_id(envelope_input struct Envelope) id
"#)]
    pub(crate) fn parent_id<E: Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &mut E,
        envelope_input: Envelope,
    ) -> Result<BaseId, Error> {
        match ctx {
            CommandContext::Open(_) | CommandContext::Policy(_) | CommandContext::Recall(_) => {
                Ok(envelope_input.parent_id)
            }
            _ => Err(WrongContext(
                "`envelope::parent_id` called outside of an `open`, `policy`, or `recall` block",
            )
            .into()),
        }
    }
    /// Returns the envelope's `author_id` field.
    #[ffi_export(def = r#"
function author_id(envelope_input struct Envelope) id
"#)]
    pub(crate) fn author_id<E: Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &mut E,
        envelope_input: Envelope,
    ) -> Result<BaseId, Error> {
        match ctx {
            CommandContext::Open(_) | CommandContext::Policy(_) | CommandContext::Recall(_) => {
                Ok(envelope_input.author_id)
            }
            _ => Err(WrongContext(
                "`envelope::author_id` called outside of an `open`, `policy`, or `recall` block",
            )
            .into()),
        }
    }

    /// Returns the envelope's `command_id` field.
    #[ffi_export(def = r#"
function command_id(envelope_input struct Envelope) id
"#)]
    pub(crate) fn command_id<E: Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &mut E,
        envelope_input: Envelope,
    ) -> Result<BaseId, Error> {
        match ctx {
            CommandContext::Open(_) | CommandContext::Policy(_) | CommandContext::Recall(_) => {
                Ok(envelope_input.command_id)
            }
            _ => Err(WrongContext(
                "`envelope::command_id` called outside of an `open`, `policy`, or `recall` block",
            )
            .into()),
        }
    }

    /// Returns the envelope's `signature` field.
    #[ffi_export(def = r#"
function signature(envelope_input struct Envelope) bytes
"#)]
    pub(crate) fn signature<E: Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &mut E,
        envelope_input: Envelope,
    ) -> Result<Vec<u8>, Error> {
        match ctx {
            CommandContext::Open(_) | CommandContext::Policy(_) | CommandContext::Recall(_) => {
                Ok(envelope_input.signature)
            }
            _ => Err(WrongContext(
                "`envelope::signature` called outside of an `open`, `policy`, or `recall` block",
            )
            .into()),
        }
    }

    /// Returns the envelope's `payload` field.
    #[ffi_export(def = r#"
function payload(envelope_input struct Envelope) bytes
"#)]
    pub(crate) fn payload<E: Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &mut E,
        envelope_input: Envelope,
    ) -> Result<Vec<u8>, Error> {
        match ctx {
            CommandContext::Open(_) | CommandContext::Policy(_) | CommandContext::Recall(_) => {
                Ok(envelope_input.payload)
            }
            _ => Err(WrongContext(
                "`envelope::payload` called outside of an `open`, `policy`, or `recall` block",
            )
            .into()),
        }
    }

    /// Creates a new envelope.
    #[ffi_export(def = r#"
function new(
    parent_id id,
    author_id id,
    command_id id,
    signature bytes,
    payload bytes,
) struct Envelope
"#)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_envelope<E: Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &mut E,
        parent_id: CmdId,
        author_id: DeviceId,
        command_id: CmdId,
        signature: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<Envelope, Error> {
        if matches!(ctx, CommandContext::Seal(_)) {
            Ok(Envelope {
                parent_id: parent_id.as_base(),
                command_id: command_id.as_base(),
                author_id: author_id.as_base(),
                signature,
                payload,
            })
        } else {
            Err(WrongContext("`envelope::new` called outside of a `seal` block").into())
        }
    }
}
