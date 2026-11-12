use alloc::borrow::Cow;
use core::borrow::Borrow as _;

use aranya_crypto::{
    CipherSuite, DeviceId, Engine, Signature, SigningKey, VerifyingKey,
    policy::{Cmd, unsigned_cmd_id},
};
use aranya_policy_vm::Struct;

use crate::{command::CmdId, vm_policy::protocol::Envelope};

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("signature bytes were malformed")]
    BadSignature(#[source] aranya_crypto::ImportError),
    #[error("command ID did not match")]
    IdMismatch,
    #[error("unsigned command has a signature or author")]
    UnexpectedSignature,
    #[error(transparent)]
    Crypto(#[from] aranya_crypto::Error),
}

pub struct SealCtx<CE: Engine> {
    pub author: DeviceId,
    pub key: SigningKey<CE::CS>,
}

impl<CE: Engine> Clone for SealCtx<CE>
where
    SigningKey<CE::CS>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            author: self.author,
            key: self.key.clone(),
        }
    }
}

pub(super) fn seal_with_key<CS: CipherSuite>(
    key: &SigningKey<CS>,
    command_struct: &Struct,
    payload: &[u8],
    author_id: DeviceId,
    parent_id: CmdId,
) -> Result<Envelope<'static>, aranya_crypto::Error> {
    let (signature, command_id) = key.sign_cmd(Cmd {
        data: payload,
        name: command_struct.name.as_str(),
        parent_id: &parent_id,
    })?;

    Ok(Envelope {
        parent_id,
        author_id,
        command_id,
        signature: Cow::Owned(signature.to_bytes().borrow().to_vec()),
    })
}

pub(super) fn open_with_key<CS: CipherSuite>(
    key: VerifyingKey<CS>,
    command_struct: &Struct,
    payload: &[u8],
    envelope: &Envelope,
) -> Result<(), OpenError> {
    let signature =
        Signature::<CS>::from_bytes(&envelope.signature).map_err(OpenError::BadSignature)?;

    let id = key.verify_cmd(
        Cmd {
            data: payload,
            name: command_struct.name.as_str(),
            parent_id: &envelope.parent_id,
        },
        &signature,
    )?;
    if id != envelope.command_id {
        return Err(OpenError::IdMismatch);
    }

    Ok(())
}

/// Seals a command of the `unsigned` flavor.
///
/// The envelope has an empty signature and a default author, since there is
/// no key to sign with and so no authenticated author.
pub(super) fn seal_unsigned<CS: CipherSuite>(
    command_struct: &Struct,
    payload: &[u8],
    parent_id: CmdId,
) -> Envelope<'static> {
    let command_id = unsigned_cmd_id::<CS>(Cmd {
        data: payload,
        name: command_struct.name.as_str(),
        parent_id: &parent_id,
    });

    Envelope {
        parent_id,
        author_id: DeviceId::default(),
        command_id,
        signature: Cow::Borrowed(&[]),
    }
}

/// Opens a command of the `unsigned` flavor.
///
/// This only checks that the envelope is well-formed and that the command ID
/// matches the contents; it does not authenticate anything.
pub(super) fn open_unsigned<CS: CipherSuite>(
    command_struct: &Struct,
    payload: &[u8],
    envelope: &Envelope,
) -> Result<(), OpenError> {
    // An unsigned command must not claim an author or carry a signature.
    if !envelope.signature.is_empty() || envelope.author_id != DeviceId::default() {
        return Err(OpenError::UnexpectedSignature);
    }

    let id = unsigned_cmd_id::<CS>(Cmd {
        data: payload,
        name: command_struct.name.as_str(),
        parent_id: &envelope.parent_id,
    });
    if id != envelope.command_id {
        return Err(OpenError::IdMismatch);
    }

    Ok(())
}
