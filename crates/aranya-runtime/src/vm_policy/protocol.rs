use aranya_crypto::DeviceId;
use aranya_policy_vm::{
    Struct,
    ast::{Identifier, ident},
};
use serde::{Deserialize, Serialize};

use crate::{
    Address, Prior,
    command::{CmdId, Command},
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
    pub parent: Prior<Address>,
    pub policy: Option<[u8; 8]>,
    /// Serialized [`VmProtocolData`].
    pub data: &'a [u8],
}

impl Command for VmProtocol<'_> {
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

pub enum Envelope {
    Init(InitEnvelope),
    Basic(BasicEnvelope),
    Ephemeral(EphemeralEnvelope),
}

// temporary helper methods
impl Envelope {
    pub(super) fn command_id(&self) -> CmdId {
        match self {
            Self::Init(e) => e.command_id,
            Self::Basic(e) => e.command_id,
            Self::Ephemeral(e) => e.command_id,
        }
    }

    pub(super) fn parent_id(&self) -> CmdId {
        match self {
            Self::Init(_) => CmdId::default(),
            Self::Basic(e) => e.parent_id,
            Self::Ephemeral(e) => e.graph_id,
        }
    }

    pub(super) fn author_id(&self) -> DeviceId {
        match self {
            Self::Init(e) => e.author_id,
            Self::Basic(e) => e.author_id,
            Self::Ephemeral(e) => e.author_id,
        }
    }
}

#[derive(Clone, Debug)]
pub struct InitEnvelope {
    pub command_id: CmdId,
    pub author_id: DeviceId,
}

#[derive(Clone, Debug)]
pub struct BasicEnvelope {
    pub command_id: CmdId,
    pub parent_id: CmdId,
    pub author_id: DeviceId,
}

#[derive(Clone, Debug)]
pub struct EphemeralEnvelope {
    pub command_id: CmdId,
    pub graph_id: CmdId,
    pub author_id: DeviceId,
}

impl From<Envelope> for Struct {
    fn from(e: Envelope) -> Self {
        match e {
            Envelope::Init(e) => e.into(),
            Envelope::Basic(e) => e.into(),
            Envelope::Ephemeral(e) => e.into(),
        }
    }
}

impl From<InitEnvelope> for Struct {
    fn from(
        InitEnvelope {
            command_id,
            author_id,
        }: InitEnvelope,
    ) -> Self {
        Self::new(
            ident!("InitEnvelope"),
            [
                (ident!("command_id"), command_id.into()),
                (ident!("author_id"), author_id.into()),
            ],
        )
    }
}

impl From<BasicEnvelope> for Struct {
    fn from(
        BasicEnvelope {
            command_id,
            parent_id,
            author_id,
        }: BasicEnvelope,
    ) -> Self {
        Self::new(
            ident!("BasicEnvelope"),
            [
                (ident!("command_id"), command_id.into()),
                (ident!("parent_id"), parent_id.into()),
                (ident!("author_id"), author_id.into()),
            ],
        )
    }
}

impl From<EphemeralEnvelope> for Struct {
    fn from(
        EphemeralEnvelope {
            command_id,
            graph_id,
            author_id,
        }: EphemeralEnvelope,
    ) -> Self {
        Self::new(
            ident!("EphemeralEnvelope"),
            [
                (ident!("command_id"), command_id.into()),
                (ident!("graph_id"), graph_id.into()),
                (ident!("author_id"), author_id.into()),
            ],
        )
    }
}
