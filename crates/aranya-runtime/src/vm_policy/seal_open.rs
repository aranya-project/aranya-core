use alloc::borrow::Cow;
use core::borrow::Borrow as _;

use aranya_crypto::{
    CipherSuite, DeviceId, Engine, Signature, SigningKey, VerifyingKey, policy::Cmd,
};
use aranya_policy_vm::Struct;

use crate::{command::CmdId, vm_policy::Envelope};

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("signature bytes were malformed")]
    BadSignature(#[source] aranya_crypto::ImportError),
    #[error("command ID did not match")]
    IdMismatch,
    #[error(transparent)]
    Crypto(#[from] aranya_crypto::Error),
}

pub struct SealCtx<CE: Engine> {
    pub author: DeviceId,
    pub key: SigningKey<CE::CS>,
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
    envelope: &Envelope<'_>,
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
