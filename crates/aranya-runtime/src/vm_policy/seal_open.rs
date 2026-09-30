use aranya_crypto::{
    CipherSuite, CmdId, DeviceId, Engine, Signature, SigningKey, VerifyingKey, policy::Cmd,
};
use aranya_policy_vm::Struct;

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

pub(super) fn open_with_key<CS: CipherSuite>(
    key: VerifyingKey<CS>,
    command_struct: &Struct,
    payload: &[u8],
    signature: &[u8],
    parent_id: CmdId,
    command_id: CmdId,
) -> Result<(), OpenError> {
    let signature = Signature::<CS>::from_bytes(signature).map_err(OpenError::BadSignature)?;

    let id = key.verify_cmd(
        Cmd {
            data: payload,
            name: command_struct.name.as_str(),
            parent_id: &parent_id,
        },
        &signature,
    )?;
    if id != command_id {
        return Err(OpenError::IdMismatch);
    }

    Ok(())
}
