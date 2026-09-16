use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow as _;

use aranya_crypto::{
    CipherSuite, DeviceId, Engine, Signature, SigningKey, VerifyingKey, policy::Cmd,
};
use aranya_policy_vm::{FactKey, HashableValue, Identifier, Struct, Value, ident};

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

pub(super) fn find_key<CS: CipherSuite>(
    command_struct: &Struct,
    envelope: &Envelope<'_>,
    facts: &impl crate::storage::Query,
) -> Option<VerifyingKey<CS>> {
    let key = if envelope.parent_id == CmdId::default() {
        from_struct(command_struct, &[], "sign_pk")
            .or_else(|| from_struct(command_struct, &[], "owner_key"))
            .or_else(|| from_struct(command_struct, &["owner_keys"], "sign_key"))?
    } else {
        let author_id = envelope.author_id;
        from_fact(
            facts,
            author_id,
            "DeviceSignPubKey",
            ident!("device_id"),
            "key",
        )
        .or_else(|| from_fact(facts, author_id, "Device", ident!("dev"), "key"))
        .or_else(|| {
            from_fact(
                facts,
                author_id,
                "DeviceSignKey",
                ident!("device_id"),
                "key",
            )
        })?
    };

    postcard::from_bytes(&key).ok()
}

fn get_struct_field<'st>(strukt: &'st Struct, field: &str) -> Option<&'st Value> {
    strukt
        .fields
        .iter()
        .find(|(name, _)| name.as_str() == field)
        .map(|(_, val)| val)
}

fn from_struct(mut strukt: &Struct, path: &[&str], last: &str) -> Option<Vec<u8>> {
    for &p in path {
        match get_struct_field(strukt, p)? {
            Value::Struct(s) => {
                strukt = s;
            }
            _ => return None,
        }
    }
    match get_struct_field(strukt, last)? {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    }
}

fn from_fact(
    facts: &impl crate::storage::Query,
    author_id: DeviceId,
    fact_name: &str,
    fact_key: Identifier,
    fact_value: &str,
) -> Option<Vec<u8>> {
    let fact = facts
        .query(
            fact_name,
            &super::ser_keys(core::iter::once(FactKey {
                identifier: fact_key,
                value: HashableValue::Id(author_id.as_base()),
            })),
        )
        .ok()??;
    let values = super::deser_values(fact).ok()?;
    match values
        .into_iter()
        .find(|v| v.identifier == fact_value)?
        .value
    {
        Value::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}
