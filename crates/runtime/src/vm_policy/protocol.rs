extern crate alloc;

use alloc::{borrow::Cow, collections::BTreeMap, string::String, sync::Arc};
use core::fmt;

use crypto::UserId;
use policy_vm::{Struct, Value};
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
        author_id: UserId,
        #[serde(borrow)]
        kind: &'a str,
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
        author_id: UserId,
        #[serde(borrow)]
        kind: &'a str,
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
    /// A mapping between command names and priorities, shared with the underlying
    /// [`super::VmPolicy`] and other [`VmProtocol`] instances.
    priority_map: Arc<BTreeMap<String, u32>>,
}

impl<'a> VmProtocol<'a> {
    pub fn new(
        data: &'a [u8],
        id: CommandId,
        unpacked: VmProtocolData<'a>,
        priority_map: Arc<BTreeMap<String, u32>>,
    ) -> VmProtocol<'a> {
        VmProtocol {
            data,
            id,
            unpacked,
            priority_map,
        }
    }
}

impl<'a> Command for VmProtocol<'a> {
    fn priority(&self) -> Priority {
        match self.unpacked {
            VmProtocolData::Init { .. } => Priority::Init,
            VmProtocolData::Merge { .. } => Priority::Merge,
            VmProtocolData::Basic { kind, .. } => {
                Priority::Basic(self.priority_map.get(kind).copied().unwrap_or_default())
            }
        }
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
    pub author_id: UserId,
    pub command_id: CommandId,
    pub payload: Cow<'a, [u8]>,
    pub signature: Cow<'a, [u8]>,
}

impl From<Envelope<'_>> for Struct {
    fn from(e: Envelope<'_>) -> Self {
        Self::new(
            "Envelope",
            [
                ("parent_id".into(), e.parent_id.into_id().into()),
                ("author_id".into(), e.author_id.into_id().into()),
                ("command_id".into(), e.command_id.into_id().into()),
                ("payload".into(), e.payload.into_owned().into()),
                ("signature".into(), e.signature.into_owned().into()),
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
            parent_id: get::<crypto::Id>(fields, "parent_id")?.into(),
            author_id: get::<crypto::Id>(fields, "author_id")?.into(),
            command_id: get::<crypto::Id>(fields, "command_id")?.into(),
            payload: Cow::Owned(get(fields, "payload")?),
            signature: Cow::Owned(get(fields, "signature")?),
        })
    }
}

fn get<T: TryFrom<Value>>(
    fields: &mut BTreeMap<String, Value>,
    key: &'static str,
) -> Result<T, EnvelopeError> {
    fields
        .remove(key)
        .ok_or(EnvelopeError::MissingField(key))?
        .try_into()
        .map_err(|_| EnvelopeError::InvalidType(key))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidName(String),
    MissingField(&'static str),
    InvalidType(&'static str),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => write!(f, "invalid struct name {name:?}"),
            Self::MissingField(field) => write!(f, "missing field {field:?}"),
            Self::InvalidType(field) => write!(f, "invalid type for field {field:?}"),
        }
    }
}

impl core::error::Error for EnvelopeError {}
