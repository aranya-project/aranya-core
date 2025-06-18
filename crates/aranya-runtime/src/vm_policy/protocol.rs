extern crate alloc;

use alloc::{borrow::Cow, collections::BTreeMap};

use aranya_crypto::DeviceId;
use aranya_policy_vm::{
    ast::{ident, Identifier},
    Struct, Value,
};
use serde::{Deserialize, Serialize};

use crate::{
    command::{Command, CommandId, Priority},
    Address, Prior,
};

/// The data inside a [VmProtocol]. It gets serialized and deserialized over the wire.
#[derive(Debug, Serialize, Deserialize)]
pub enum VmProtocolData<'a> {
    Init {
        policy: [u8; 8],
        author_id: DeviceId,
        kind: Identifier,
        #[serde(borrow)]
        serialized_fields: &'a [u8],
        #[serde(borrow)]
        signature: &'a [u8],
    },
    Merge {
        left: Address,
        right: Address,
    },
    Basic {
        parent: Address,
        author_id: DeviceId,
        kind: Identifier,
        #[serde(borrow)]
        serialized_fields: &'a [u8],
        #[serde(borrow)]
        signature: &'a [u8],
    },
}

/// The Command implementation as used by the VM. It deserializes the interior data into a
/// [VmProtocolData] struct, and it keeps the original serialized copy around for quick
/// access to that.
#[derive(Debug)]
pub struct VmProtocol<'a> {
    /// Reference to the serialized data underlying the command
    data: &'a [u8],
    /// The ID of the command
    id: CommandId,
    /// The deserialized data
    unpacked: VmProtocolData<'a>,
    /// The command's priority.
    priority: Priority,
}

impl<'a> VmProtocol<'a> {
    pub fn new(
        data: &'a [u8],
        id: CommandId,
        unpacked: VmProtocolData<'a>,
        priority: Priority,
    ) -> VmProtocol<'a> {
        VmProtocol {
            data,
            id,
            unpacked,
            priority,
        }
    }
}

impl Command for VmProtocol<'_> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> CommandId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        match self.unpacked {
            VmProtocolData::Init { .. } => Prior::None,
            VmProtocolData::Merge { left, right, .. } => Prior::Merge(left, right),
            VmProtocolData::Basic { parent, .. } => Prior::Single(parent),
        }
    }

    fn policy(&self) -> Option<&[u8]> {
        match self.unpacked {
            VmProtocolData::Init { ref policy, .. } => Some(policy),
            _ => None,
        }
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }
}

#[derive(Clone, Debug)]
pub struct Envelope<'a> {
    pub parent_id: CommandId,
    pub author_id: DeviceId,
    pub command_id: CommandId,
    pub payload: Cow<'a, [u8]>,
    pub signature: Cow<'a, [u8]>,
}

impl From<Envelope<'_>> for Struct {
    fn from(e: Envelope<'_>) -> Self {
        Self::new(
            ident!("Envelope"),
            [
                (ident!("parent_id"), Value::Id(e.parent_id.into_id())),
                (ident!("author_id"), Value::Id(e.author_id.into_id())),
                (ident!("command_id"), Value::Id(e.command_id.into_id())),
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
            parent_id: get::<aranya_crypto::Id>(fields, "parent_id")?.into_id(),
            author_id: get::<aranya_crypto::Id>(fields, "author_id")?.into_id(),
            command_id: get::<aranya_crypto::Id>(fields, "command_id")?.into_id(),
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
