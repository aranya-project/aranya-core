extern crate alloc;

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

use crate::{
    command::{Command, Id, Priority},
    Prior,
};

/// The data inside a [VmProtocol]. It gets serialized and deserialized over the wire.
#[derive(Debug, Serialize, Deserialize)]
pub enum VmProtocolData {
    Init {
        policy: [u8; 8],
    },
    Merge {
        left: Id,
        right: Id,
    },
    Basic {
        parent: Id,
        author_id: Id,
        kind: String,
        serialized_fields: Vec<u8>,
    },
}

/// The Command implementation as used by the VM. It deserializes the interior data into a
/// [VmProtocolData] struct, and it keeps the original serialized copy around for quick
/// access to that.
#[derive(Debug)]
pub struct VmProtocol<'a> {
    data: &'a [u8],
    id: Id,
    unpacked: VmProtocolData,
}

impl<'a> VmProtocol<'a> {
    pub fn new(data: &'a [u8], id: Id, unpacked: VmProtocolData) -> VmProtocol<'_> {
        VmProtocol { data, id, unpacked }
    }
}

impl<'a> Command<'a> for VmProtocol<'a> {
    fn priority(&self) -> Priority {
        match &self.unpacked {
            VmProtocolData::Init { .. } => Priority::Init,
            VmProtocolData::Merge { .. } => Priority::Merge,
            // TODO(chip): implement actual message priorities
            VmProtocolData::Basic { .. } => Priority::Basic(0),
        }
    }

    fn id(&self) -> Id {
        self.id
    }

    fn parent(&self) -> Prior<Id> {
        match self.unpacked {
            VmProtocolData::Init { .. } => Prior::None,
            VmProtocolData::Merge { left, right } => Prior::Merge(left, right),
            VmProtocolData::Basic { parent, .. } => Prior::Single(parent),
        }
    }

    fn policy(&self) -> Option<&[u8]> {
        match self.unpacked {
            VmProtocolData::Init { ref policy } => Some(policy),
            _ => None,
        }
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }
}
