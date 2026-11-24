use aranya_crypto::DeviceId;
use aranya_policy_vm::ast::Identifier;
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
    pub policy: Option<&'a [u8]>,
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
