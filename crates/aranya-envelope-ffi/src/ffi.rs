#![allow(clippy::match_wildcard_for_single_variants)]

extern crate alloc;

use alloc::vec::Vec;

use aranya_crypto::{BaseId, engine::Engine};
use aranya_policy_vm::{CommandContext, ffi::ffi};

use crate::error::{Error, WrongContext};

/// Implements `envelope-ffi`.
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
        _eng: &E,
        envelope_input: Envelope,
    ) -> Result<BaseId, Error> {
        match ctx {
            CommandContext::Policy(_) | CommandContext::Recall { .. } => {
                Ok(envelope_input.parent_id)
            }
            _ => Err(WrongContext(
                "`envelope::parent_id` called outside of a `policy` or `recall` block",
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
        _eng: &E,
        envelope_input: Envelope,
    ) -> Result<BaseId, Error> {
        match ctx {
            CommandContext::Policy(_) | CommandContext::Recall { .. } => {
                Ok(envelope_input.author_id)
            }
            _ => Err(WrongContext(
                "`envelope::author_id` called outside of a `policy` or `recall` block",
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
        _eng: &E,
        envelope_input: Envelope,
    ) -> Result<BaseId, Error> {
        match ctx {
            CommandContext::Policy(_) | CommandContext::Recall { .. } => {
                Ok(envelope_input.command_id)
            }
            _ => Err(WrongContext(
                "`envelope::command_id` called outside of a `policy` or `recall` block",
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
        _eng: &E,
        envelope_input: Envelope,
    ) -> Result<Vec<u8>, Error> {
        match ctx {
            CommandContext::Policy(_) | CommandContext::Recall { .. } => {
                Ok(envelope_input.signature)
            }
            _ => Err(WrongContext(
                "`envelope::signature` called outside of a `policy` or `recall` block",
            )
            .into()),
        }
    }
}
