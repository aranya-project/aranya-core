use alloc::borrow::Cow;
use core::borrow::Borrow as _;

use aranya_crypto::{
    CipherSuite, DeviceId, Engine, KeyStore, Signature, SigningKey, SigningKeyId, VerifyingKey,
    policy::Cmd,
};
use aranya_policy_vm::{FactKey, HashableValue, Struct, Value, ident};

use crate::{
    command::CmdId,
    vm_policy::{Envelope, QueryValue, QueryValueError},
};

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error(transparent)]
    Crypto(#[from] aranya_crypto::Error),
    #[error("keystore error")]
    KeyStore,
    #[error("not supported")]
    NotSupported,
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("command struct was malformed")]
    BadStruct,
    #[error("key bytes were malformed")]
    BadKey(#[source] postcard::Error),
    #[error("signature bytes were malformed")]
    BadSignature(#[source] aranya_crypto::ImportError),
    #[error("fact did not have expected value")]
    BadFact,
    #[error("required fact was missing")]
    MissingFact,
    #[error("command ID did not match")]
    IdMismatch,
    #[error(transparent)]
    Query(#[from] QueryValueError),
    #[error(transparent)]
    Crypto(#[from] aranya_crypto::Error),
}

pub trait Seal<CE> {
    fn seal_command(
        &self,
        engine: &CE,
        command_struct: &Struct,
        payload: &[u8],
        parent_id: CmdId,
    ) -> Result<Envelope<'_>, SealError>;
}

pub trait Open<CS> {
    fn open_command(
        &self,
        command_struct: &Struct,
        payload: &[u8],
        envelope: &Envelope<'_>,
        facts: &dyn QueryValue,
    ) -> Result<(), OpenError>;
}

/// A seal instance which is not able to seal any commands.
///
/// Could be useful for clients which just exist for syncing.
pub struct NoSeal;

impl<CE> Seal<CE> for NoSeal {
    fn seal_command(
        &self,
        _engine: &CE,
        _command_struct: &Struct,
        _payload: &[u8],
        _parent_id: CmdId,
    ) -> Result<Envelope<'_>, SealError> {
        Err(SealError::NotSupported)
    }
}

/// Implements the standard command seal, using the provided key.
pub struct StandardSeal<KS> {
    device_id: DeviceId,
    sign_key_id: SigningKeyId,
    keystore: KS,
}

impl<KS> StandardSeal<KS> {
    pub fn new(device_id: DeviceId, sign_key_id: SigningKeyId, keystore: KS) -> Self {
        Self {
            device_id,
            sign_key_id,
            keystore,
        }
    }
}

impl<CE, KS> Seal<CE> for StandardSeal<KS>
where
    CE: Engine,
    KS: KeyStore,
{
    fn seal_command(
        &self,
        engine: &CE,
        command_struct: &Struct,
        payload: &[u8],
        parent_id: CmdId,
    ) -> Result<Envelope<'_>, SealError> {
        use aranya_crypto::KeyStoreExt as _;

        let author_id = self.device_id;

        let key: SigningKey<CE::CS> = self
            .keystore
            .get_key(&engine, self.sign_key_id)
            .map_err(|error| {
                tracing::error!(%error, "keystore error");
                SealError::KeyStore
            })?
            .ok_or_else(|| {
                tracing::warn!("key not found");
                SealError::KeyStore
            })?;

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
}

/// Implements the standard command open.
///
/// The init command will be opened using the key bytes at `this.sign_pk`.
///
/// Other commands will be opened with the key stored at
/// `fact DeviceSignPubKey[device_id id]=>{key bytes, ...}`.
pub struct StandardOpen;

impl<CE: Engine> Open<CE> for StandardOpen {
    fn open_command(
        &self,
        command_struct: &Struct,
        payload: &[u8],
        envelope: &Envelope<'_>,
        facts: &dyn QueryValue,
    ) -> Result<(), OpenError> {
        let key = get_verifying_key::<CE::CS>(command_struct, envelope, facts)?;
        open_with_key(command_struct, payload, envelope, key)
    }
}

pub fn open_with_key<CS: CipherSuite>(
    command_struct: &Struct,
    payload: &[u8],
    envelope: &Envelope<'_>,
    key: VerifyingKey<CS>,
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

fn get_verifying_key<CS: CipherSuite>(
    command_struct: &Struct,
    envelope: &Envelope<'_>,
    facts: &dyn QueryValue,
) -> Result<VerifyingKey<CS>, OpenError> {
    let key = if envelope.parent_id == CmdId::default() {
        let key = command_struct
            .fields
            .iter()
            .find(|(name, _)| name.as_str() == "sign_pk")
            .ok_or(OpenError::BadStruct)?
            .1;
        let Value::Bytes(key) = key else {
            return Err(OpenError::BadStruct);
        };
        Cow::Borrowed(key)
    } else {
        let values = facts
            .query_value(
                "DeviceSignPubKey",
                &[FactKey {
                    identifier: ident!("device_id"),
                    value: HashableValue::Id(envelope.author_id.as_base()),
                }],
            )?
            .ok_or(OpenError::MissingFact)?;
        let key = values
            .into_iter()
            .find(|v| v.identifier == "key")
            .ok_or(OpenError::BadFact)?
            .value;
        let Value::Bytes(key) = key else {
            return Err(OpenError::BadFact);
        };
        Cow::Owned(key)
    };

    postcard::from_bytes(&key).map_err(OpenError::BadKey)
}
