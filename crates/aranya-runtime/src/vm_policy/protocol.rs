extern crate alloc;

use alloc::{borrow::Cow, collections::BTreeMap};

use aranya_crypto::DeviceId;
use aranya_policy_vm::{
    Struct, Value,
    ast::{Identifier, ident},
};
use serde::{Deserialize, Serialize};

use crate::{
    Address, Prior,
    command::{CmdId, Command, Priority},
};

/// The data inside a [`VmProtocol`]. It gets serialized and deserialized over the wire.
#[derive(Debug, Serialize, Deserialize)]
pub struct VmProtocolData<'a> {
    pub author_id: DeviceId,
    pub kind: Identifier,
    #[serde(borrow)]
    pub serialized_fields: &'a [u8],
    #[serde(borrow)]
    pub signature: &'a [u8],
}

/// The Command implementation as used by the VM. It deserializes the interior data into a
/// [VmProtocolData] struct, and it keeps the original serialized copy around for quick
/// access to that.
#[derive(Debug)]
pub struct VmProtocol<'a> {
    pub id: CmdId,
    pub priority: Priority,
    pub parent: Prior<Address>,
    pub policy: Option<[u8; 8]>,
    /// Serialized [`VmProtocolData`].
    pub data: &'a [u8],
}

impl Command for VmProtocol<'_> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> CmdId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        self.parent
    }

    fn policy(&self) -> Option<&[u8]> {
        self.policy.as_ref().map(|p| &p[..])
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }
}

#[derive(Clone, Debug)]
pub struct Envelope<'a> {
    pub parent_id: CmdId,
    pub author_id: DeviceId,
    pub command_id: CmdId,
    pub payload: Cow<'a, [u8]>,
    pub signature: Cow<'a, [u8]>,
}

impl From<Envelope<'_>> for Struct {
    fn from(e: Envelope<'_>) -> Self {
        Self::new(
            ident!("Envelope"),
            [
                (ident!("parent_id"), e.parent_id.into()),
                (ident!("author_id"), e.author_id.into()),
                (ident!("command_id"), e.command_id.into()),
                (ident!("payload"), e.payload.into_owned().into()),
                (ident!("signature"), e.signature.into_owned().into()),
            ],
        )
    }
}

impl TryFrom<Struct> for Envelope<'_> {
    type Error = EnvelopeError;

    fn try_from(
        Struct {
            name,
            ref mut fields,
        }: Struct,
    ) -> Result<Self, Self::Error> {
        if name != "Envelope" {
            return Err(EnvelopeError::InvalidName(name));
        }

        Ok(Self {
            parent_id: get::<aranya_crypto::BaseId>(fields, "parent_id")?.into(),
            author_id: get::<aranya_crypto::BaseId>(fields, "author_id")?.into(),
            command_id: get::<aranya_crypto::BaseId>(fields, "command_id")?.into(),
            payload: Cow::Owned(get(fields, "payload")?),
            signature: Cow::Owned(get(fields, "signature")?),
        })
    }
}

fn get<T: TryFrom<Value>>(
    fields: &mut BTreeMap<Identifier, Value>,
    key: &'static str,
) -> Result<T, EnvelopeError> {
    fields
        .remove(key)
        .ok_or(EnvelopeError::MissingField(key))?
        .try_into()
        .map_err(|_| EnvelopeError::InvalidType(key))
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("invalid struct name {0:?}")]
    InvalidName(Identifier),
    #[error("missing field {0:?}")]
    MissingField(&'static str),
    #[error("invalid type for field {0:?}")]
    InvalidType(&'static str),
}
